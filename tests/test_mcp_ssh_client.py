from __future__ import annotations

import asyncio
import errno
import json
import os
import shlex
import sys
from contextlib import AsyncExitStack
from dataclasses import replace
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client

from cross_assistant_memory import mcp_ssh_client as ssh
from cross_assistant_memory.mcp_ssh_client import (
    _connection_slot,  # pyright: ignore[reportPrivateUsage]
    _ssh_connection,  # pyright: ignore[reportPrivateUsage]
)

HELPER = Path(__file__).parent / "fixtures" / "ssh_mcp_process.py"
CONNECTION = ssh.SSHConnection(
    host="user@mini",
    remote_python="/private runtime/venv/bin/python",
    remote_runtime="/private runtime/code",
    remote_credential_file="/remote only/token",
    endpoint="http://127.0.0.1:28765/mcp",
)
SECRET = "SYNTHETIC-REMOTE-SECRET-NOT-FOR-LOGS"


def test_ssh_arguments_enforce_no_persistence_and_quote_remote_paths() -> None:
    params = replace(CONNECTION, identity_file=Path("/keys/private key")).parameters()
    assert params.command == "/usr/bin/ssh"
    for option in (
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "ConnectTimeout=10",
        "ConnectionAttempts=1",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "ControlMaster=no",
        "ControlPath=none",
        "ControlPersist=no",
    ):
        index = params.args.index(option)
        assert params.args[index - 1] == "-o"
    assert params.args[-3:-1] == ["--", "user@mini"]
    remote = shlex.split(params.args[-1])
    assert remote[:4] == ["exec", "/usr/bin/env", "-u", "CAM_EVIDENCE_CONFIG"]
    assert "PYTHONPATH=/private runtime/code/src" in remote
    assert CONNECTION.remote_python in remote
    assert remote[-2:] == ["--credential-file", CONNECTION.remote_credential_file]
    assert params.args[params.args.index("-i") + 1] == "/keys/private key"


@pytest.mark.parametrize(
    "host", ["-oProxyCommand=bad", "mini;whoami", "user@", "mini\n", "a b", "a@b@c"]
)
def test_bad_host_refused(host: str) -> None:
    with pytest.raises(ValueError):
        replace(CONNECTION, host=host).parameters()


@pytest.mark.parametrize("path", ["relative", "/a\n", "/a\x00"])
def test_bad_remote_path_refused(path: str) -> None:
    with pytest.raises(ValueError):
        replace(CONNECTION, remote_runtime=path).parameters()


def test_shell_metacharacters_in_remote_paths_remain_literal() -> None:
    path = "/somewhere/$(touch SHOULD_NOT_EXIST);'"
    command = replace(CONNECTION, remote_runtime=path).parameters().args[-1]
    assert f"PYTHONPATH={path}/src" in shlex.split(command)


def _parameters(root: Path, timeout: float = 45) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(HELPER), "relay", str(root), str(timeout)],
        env={
            "CAM_HOME": str(root / "must-not-create-ledger"),
            "CAM_EVIDENCE_CONFIG": "/absent/not-read",
            "PYTHONPATH": str(HELPER.resolve().parents[2] / "src"),
        },
    )


def _events(root: Path) -> list[dict[str, Any]]:
    path = root / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _assert_idle(root: Path) -> None:
    events = _events(root)
    starts = {event["pid"] for event in events if event["event"] == "start"}
    stops = {event["pid"] for event in events if event["event"] == "stop"}
    assert starts == stops
    for pid in starts:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        raise AssertionError(f"synthetic child {pid} has not exited yet")


def test_forty_open_clients_have_no_idle_children_and_share_four_slots(tmp_path: Path) -> None:
    (tmp_path / "mode").write_text("slow")

    async def exercise() -> None:
        ready = [asyncio.Event() for _ in range(40)]
        called = [asyncio.Event() for _ in range(40)]
        call_gate, close_gate = asyncio.Event(), asyncio.Event()
        starting = asyncio.Semaphore(4)

        async def client_task(index: int) -> None:
            async with AsyncExitStack() as lifetime:
                # Discovery has its own 20s deadline: open in waves, then burst all 40 calls.
                async with starting:
                    client = await lifetime.enter_async_context(
                        Client(_parameters(tmp_path), read_timeout_seconds=60, cache=None)
                    )
                    assert len((await client.list_tools()).tools) == 3
                ready[index].set()
                await call_gate.wait()
                result = await client.call_tool("memory_search", {"query": "synthetic"})
                assert not result.is_error
                assert result.structured_content == {
                    "tool": "memory_search",
                    "text": "synthetic evidence",
                    "arguments": {"query": "synthetic"},
                }
                called[index].set()
                await close_gate.wait()

        async with asyncio.TaskGroup() as tasks:
            for index in range(40):
                tasks.create_task(client_task(index))
            await asyncio.gather(*(event.wait() for event in ready))
            _assert_idle(tmp_path)
            call_gate.set()
            await asyncio.gather(*(event.wait() for event in called))
            _assert_idle(tmp_path)
            close_gate.set()

    asyncio.run(asyncio.wait_for(exercise(), 100))
    active, peak, starts = 0, 0, 0
    for event in _events(tmp_path):
        if event["event"] == "start":
            active += 1
            starts += 1
            peak = max(peak, active)
        elif event["event"] == "stop":
            active -= 1
        assert 0 <= active <= 4
    assert active == 0 and peak == 4 and starts == 80
    assert not (tmp_path / "must-not-create-ledger").exists()


def test_outage_drift_errors_and_malformed_frames_preserve_local_client(tmp_path: Path) -> None:
    (tmp_path / "mode").write_text("ok")
    error_path = tmp_path / "stderr"

    async def exercise() -> None:
        with error_path.open("w") as errors:
            async with Client(
                stdio_client(_parameters(tmp_path, 3), errlog=errors), cache=None
            ) as client:
                before = len(_events(tmp_path))
                assert (await client.call_tool("memory_propose", {})).is_error
                assert len(_events(tmp_path)) == before
                for mode in ("unavailable", "drift", "error", "malformed", "hang"):
                    (tmp_path / "mode").write_text(mode)
                    assert (await client.call_tool("memory_status", {})).is_error
                    assert len((await client.list_tools()).tools) == 3
                    _assert_idle(tmp_path)
                    (tmp_path / "mode").write_text("ok")
                    assert not (await client.call_tool("memory_get_evidence", {})).is_error
                    _assert_idle(tmp_path)

    asyncio.run(asyncio.wait_for(exercise(), 45))
    assert SECRET not in error_path.read_text()


@pytest.mark.parametrize(
    "unsafe", ["public-dir", "symlink-dir", "public-file", "symlink-file", "hardlink-file"]
)
def test_unsafe_slot_state_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    root = tmp_path / "slots"
    root.mkdir(mode=0o700)
    if unsafe == "public-dir":
        root.chmod(0o755)
    elif unsafe == "symlink-dir":
        root.rmdir()
        root.symlink_to(tmp_path, target_is_directory=True)
    else:
        file = root / "slot-0"
        if unsafe == "symlink-file":
            file.symlink_to(tmp_path / "absent")
        else:
            file.touch(mode=0o600)
            if unsafe == "public-file":
                file.chmod(0o644)
            else:
                os.link(file, root / "second")
    monkeypatch.setattr(ssh, "_slot_directory", lambda: root)

    async def exercise() -> None:
        with pytest.raises((ValueError, OSError)):
            async with _connection_slot():
                pytest.fail("unsafe slot accepted")

    asyncio.run(exercise())


def test_queue_timeout_spawns_nothing_and_releases_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "_slot_directory", lambda: tmp_path / "slots")

    async def exercise() -> None:
        async with AsyncExitStack() as held:
            for _ in range(4):
                await held.enter_async_context(_connection_slot())
            with pytest.raises(TimeoutError):
                async with _ssh_connection(StdioServerParameters(command="/must/not/spawn"), 0.1):
                    pytest.fail("queue admitted a fifth connection")
        async with _connection_slot():
            pass

    asyncio.run(exercise())


@pytest.mark.parametrize("disappeared", [False, True])
def test_slot_creation_race_opens_existing_file_without_recreating_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disappeared: bool
) -> None:
    monkeypatch.setattr(ssh, "_slot_directory", lambda: tmp_path / "slots")
    original_open = os.open
    slot_flags: list[int] = []
    raced = False

    def racing_open(
        path: str | Path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        nonlocal raced
        if path == "slot-0":
            slot_flags.append(flags)
            if not raced and flags & os.O_CREAT:
                raced = True
                descriptor = original_open(path, flags | os.O_EXCL, mode, dir_fd=dir_fd)
                os.close(descriptor)
                if disappeared:
                    os.unlink(path, dir_fd=dir_fd)
                if flags & os.O_EXCL:
                    raise FileExistsError(errno.EEXIST, "concurrent creator", path)
                raise FileNotFoundError(errno.ENOENT, "nonexclusive creation race", path)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(ssh.os, "open", racing_open)

    async def exercise() -> None:
        if disappeared:
            with pytest.raises(FileNotFoundError):
                async with _connection_slot():
                    pytest.fail("removed slot was recreated")
            assert not (tmp_path / "slots" / "slot-0").exists()
        else:
            async with _connection_slot():
                pass
            async with _connection_slot():
                pass

    asyncio.run(exercise())
    assert slot_flags[0] & os.O_EXCL
    assert not slot_flags[1] & (os.O_CREAT | os.O_EXCL)
    for flags in slot_flags:
        assert flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC and flags & os.O_NONBLOCK


@pytest.mark.parametrize("disconnect", ["eof", "kill", "cancel"])
def test_inflight_disconnect_reaps_remote_and_frees_slots(tmp_path: Path, disconnect: str) -> None:
    (tmp_path / "mode").write_text("ok")
    meta = {
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "synthetic-test", "version": "1"},
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    }

    async def exercise() -> None:
        params = _parameters(tmp_path)
        process = await asyncio.create_subprocess_exec(
            params.command,
            *params.args,
            env={**os.environ, **(params.env or {})},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert process.stdin and process.stdout and process.stderr

        async def send(value: dict[str, Any]) -> None:
            assert process.stdin is not None
            process.stdin.write((json.dumps({"jsonrpc": "2.0", **value}) + "\n").encode())
            await process.stdin.drain()

        try:
            await send({"id": 1, "method": "tools/list", "params": {"_meta": meta}})
            assert "result" in json.loads(await asyncio.wait_for(process.stdout.readline(), 10))
            (tmp_path / "mode").write_text("hang")
            await send(
                {
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "_meta": meta,
                        "name": "memory_status",
                        "arguments": {},
                    },
                }
            )
            with anyio.fail_after(10):
                while not any(event["event"] == "waiting" for event in _events(tmp_path)):
                    await asyncio.sleep(0.02)
            if disconnect == "kill":
                process.kill()
            elif disconnect == "eof":
                process.stdin.close()
            else:
                await send({"method": "notifications/cancelled", "params": {"requestId": 2}})
            with anyio.fail_after(8):
                while True:
                    try:
                        _assert_idle(tmp_path)
                        break
                    except AssertionError:
                        await asyncio.sleep(0.02)
            if disconnect == "cancel":
                (tmp_path / "mode").write_text("ok")
                await send(
                    {
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "_meta": meta,
                            "name": "memory_status",
                            "arguments": {},
                        },
                    }
                )
                with anyio.fail_after(8):
                    while True:
                        response = json.loads(await process.stdout.readline())
                        if response.get("id") == 3:
                            assert not response["result"].get("isError", False)
                            break
                process.stdin.close()
            await asyncio.wait_for(process.wait(), 8)
            assert process.returncode == (-9 if disconnect == "kill" else 0)
            assert SECRET.encode() not in await process.stderr.read()
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    asyncio.run(asyncio.wait_for(exercise(), 35))


def test_discovery_timeout_cleans_up_without_secret_output(tmp_path: Path) -> None:
    (tmp_path / "mode").write_text("discovery-hang")

    async def exercise() -> None:
        params = _parameters(tmp_path, 1)
        process = await asyncio.create_subprocess_exec(
            params.command,
            *params.args,
            env={**os.environ, **(params.env or {})},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode != 0
        assert SECRET.encode() not in stdout + stderr
        _assert_idle(tmp_path)

    asyncio.run(exercise())
