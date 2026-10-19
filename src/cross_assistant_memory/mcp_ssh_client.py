from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import pwd
import re
import shlex
import stat
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import anyio
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server

from cross_assistant_memory.mcp_client import create_readonly_relay, validate_loopback_endpoint

SSH_SLOTS = 4
DISCOVERY_TIMEOUT = 20.0
REQUEST_TIMEOUT = 45.0


@dataclass(frozen=True)
class SSHConnection:
    host: str
    remote_python: str
    remote_runtime: str
    remote_credential_file: str
    endpoint: str
    identity_file: Path | None = None

    def parameters(self) -> StdioServerParameters:
        if not re.fullmatch(
            r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9_.-]*", self.host
        ):
            raise ValueError("SSH host must be a hostname or user@hostname")
        validate_loopback_endpoint(self.endpoint)
        for path in (self.remote_python, self.remote_runtime, self.remote_credential_file):
            if not path.startswith("/") or any(ord(char) < 32 for char in path):
                raise ValueError("remote paths must be absolute and contain no control characters")
        args = ["-T"]
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
            args.extend(("-o", option))
        if self.identity_file is not None:
            args.extend(("-o", "IdentitiesOnly=yes"))
            args.extend(("-i", str(self.identity_file.expanduser())))
        remote = shlex.join(
            [
                "/usr/bin/env",
                "-u",
                "CAM_EVIDENCE_CONFIG",
                "PYTHONDONTWRITEBYTECODE=1",
                f"PYTHONPATH={self.remote_runtime}/src",
                self.remote_python,
                "-m",
                "cross_assistant_memory",
                "connect",
                "--url",
                self.endpoint,
                "--credential-file",
                self.remote_credential_file,
            ]
        )
        args.extend(("--", self.host, f"exec {remote}"))
        return StdioServerParameters(command="/usr/bin/ssh", args=args)


def _slot_directory() -> Path:
    # OS account identity, not CAM_HOME, cwd, or per-task HOME overrides, owns the budget.
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".cross-agent-memory-ssh"


@asynccontextmanager
async def _connection_slot() -> AsyncGenerator[None]:
    directory = _slot_directory()
    directory.mkdir(mode=0o700, exist_ok=True)
    with_directory = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor: int | None = None
    try:
        info = os.fstat(with_directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("SSH slot directory must be private and owned by this user")
        while descriptor is None:
            for index in range(SSH_SLOTS):
                name = f"slot-{index}"
                flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                # Concurrent nonexclusive O_CREAT can fail with ENOENT on macOS.
                try:
                    candidate = os.open(
                        name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=with_directory
                    )
                except FileExistsError:
                    candidate = os.open(name, flags, dir_fd=with_directory)
                try:
                    info = os.fstat(candidate)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.getuid()
                        or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600
                    ):
                        raise ValueError("SSH slot file must be private, regular, and owned")
                    fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    os.close(candidate)
                except BaseException:
                    os.close(candidate)
                    raise
                else:
                    descriptor = candidate
                    break
            if descriptor is None:
                await anyio.sleep(0.05)
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(with_directory)


@asynccontextmanager
async def _ssh_connection(
    parameters: StdioServerParameters,
    timeout: float,
) -> AsyncGenerator[Client]:
    # The SDK shields bounded child cleanup; retain the slot until that cleanup finishes.
    with anyio.fail_after(timeout):
        async with _connection_slot():
            with open(os.devnull, "w") as errors:
                async with Client(
                    stdio_client(parameters, errlog=errors),
                    read_timeout_seconds=REQUEST_TIMEOUT,
                    cache=None,
                ) as upstream:
                    yield upstream


def _redact_transport_log(record: logging.LogRecord) -> bool:
    record.msg = "Memory transport diagnostic suppressed."
    record.args = ()
    record.exc_info = None
    record.exc_text = None
    record.stack_info = None
    return True


async def _connect_ssh(
    parameters: StdioServerParameters,
    evidence_text_max_bytes: int | None,
) -> None:
    discovering = True
    relay = await create_readonly_relay(
        lambda: _ssh_connection(
            parameters,
            DISCOVERY_TIMEOUT if discovering else REQUEST_TIMEOUT,
        ),
        evidence_text_max_bytes=evidence_text_max_bytes,
    )
    discovering = False
    async with stdio_server() as (reader, writer):
        await relay.run(reader, writer, relay.create_initialization_options())


def run_ssh_client(
    connection: SSHConnection, *, evidence_text_max_bytes: int | None = None
) -> None:
    # SDK validation exceptions can otherwise echo malformed remote frames into stderr.
    for name in ("mcp.client.stdio", "mcp.client.session"):
        logging.getLogger(name).addFilter(_redact_transport_log)
    try:
        parameters = connection.parameters()
        asyncio.run(_connect_ssh(parameters, evidence_text_max_bytes))
    except Exception:
        raise RuntimeError("Memory SSH connection refused or unavailable.") from None
