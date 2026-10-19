from __future__ import annotations

import errno
import fcntl
import os
import select
import sqlite3
import subprocess
import sys
import time
from collections.abc import Generator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory, gettempdir
from typing import Literal, cast

import pytest

import cross_assistant_memory.storage as storage
from cross_assistant_memory.config import Settings

_ROOT = Path(__file__).resolve().parents[1]
_CODE_PARENT = Path(storage.__file__).resolve().parents[1]
_PROMPT_DEADLINE = 1.0
_Action = Literal[
    "exclusive",
    "exclusive_default",
    "exclusive_wait",
    "initialize",
    "connect",
    "connect_default",
    "publication",
    "publication_default",
    "readonly",
    "live_readonly",
    "owned",
]


@pytest.fixture
def settings() -> Generator[Settings]:
    assert _CODE_PARENT == _ROOT / "src" or _CODE_PARENT.is_relative_to(_ROOT / ".venv")
    temporary_parent = Path(gettempdir()).resolve()
    assert not temporary_parent.is_relative_to(Path.home().resolve())
    with TemporaryDirectory(
        prefix="cam-maintenance-lock-tests-", dir=temporary_parent
    ) as directory:
        root = Path(directory)
        configured = Settings(root / "ledger")
        storage.Ledger(configured)
        try:
            yield configured
        finally:
            assert sum(path.stat().st_size for path in root.rglob("*") if path.is_file()) < 8 << 20


@dataclass
class _Worker:
    process: subprocess.Popen[bytes]
    pending: bytearray = field(default_factory=bytearray)

    def receive(self, timeout: float = _PROMPT_DEADLINE) -> str:
        output = self.process.stdout
        assert output is not None
        deadline = time.monotonic() + timeout
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([output], [], [], remaining)[0]:
                raise TimeoutError("lock worker exceeded its response deadline")
            chunk = os.read(output.fileno(), 4096)
            assert chunk, f"lock worker exited without a response: {bytes(self.pending[:512])!r}"
            self.pending.extend(chunk)
            assert len(self.pending) < 8192, "unexpectedly large lock worker output"
        line, _, remainder = self.pending.partition(b"\n")
        self.pending = bytearray(remainder)
        return line.decode("utf-8")

    def send(self, signal: bytes = b"go\n") -> None:
        stream = self.process.stdin
        assert stream is not None
        stream.write(signal)
        stream.flush()

    def start(self) -> None:
        self.send()
        assert self.receive() == "attempting"

    def finish(self, expected: str) -> None:
        assert self.receive() == expected
        assert self.process.wait(timeout=3) == 0


@contextmanager
def _worker_process(settings: Settings, action: _Action) -> Generator[_Worker]:
    # Fresh exec avoids inherited lock descriptors and the shared editable source tree.
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from tests.test_ledger_maintenance_locks import _run_worker; _run_worker()",
            action,
            str(settings.data_root),
        ],
        cwd=_ROOT,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(settings.data_root.parent),
            "TMPDIR": str(settings.data_root.parent),
            "PYTHONPATH": f"{_CODE_PARENT}:{_ROOT}:{Path(pytest.__file__).resolve().parents[1]}",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )
    worker = _Worker(process)
    try:
        assert worker.receive(timeout=10) == "ready"
        yield worker
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()
        assert process.poll() is not None


@contextmanager
def _os_lock(settings: Settings, mode: int) -> Generator[None]:
    descriptor = os.open(settings.run_root / "ledger-writer.lock", os.O_RDWR)
    try:
        fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def _assert_os_busy(settings: Settings, mode: int) -> None:
    descriptor = os.open(settings.run_root / "ledger-writer.lock", os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def _assert_closed(descriptors: list[int]) -> None:
    assert descriptors, "the operation never opened a writer-lock descriptor"
    for descriptor in descriptors:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


def _query(ledger: storage.Ledger) -> None:
    with closing(ledger._connect()) as connection:  # pyright: ignore[reportPrivateUsage]
        row = connection.execute("SELECT COUNT(*) FROM events").fetchone()
        assert row is not None and row[0] == 0
        if ledger.read_only:
            assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                connection.execute("DELETE FROM events")


def _exercise(action: _Action, settings: Settings, ledger: storage.Ledger | None) -> None:
    if action in {"exclusive", "exclusive_default", "exclusive_wait"}:
        if action == "exclusive_default":
            manager = storage.exclusive_ledger_writer(settings)
        else:
            manager = storage.exclusive_ledger_writer(settings, wait=action == "exclusive_wait")
        with manager as token:
            assert token.active
            os.fstat(token.descriptor)
    elif action == "initialize":
        _query(storage.Ledger(settings, fail_fast_on_maintenance=True))
    elif action in {"readonly", "live_readonly"}:
        _query(
            storage.Ledger(
                settings,
                read_only=True,
                require_checkpointed=action == "readonly",
                fail_fast_on_maintenance=True,
            )
        )
    else:
        assert ledger is not None
        if action in {"publication", "publication_default"}:
            with ledger._publication_writer(  # pyright: ignore[reportPrivateUsage]
                force_exclusive=True
            ) as writer:
                token = writer._exclusive_writer_token  # pyright: ignore[reportPrivateUsage]
                assert token is not None and token.active
                _query(writer)
        else:
            _query(ledger)


def _exercise_owned(settings: Settings, descriptors: list[int]) -> None:
    with storage.exclusive_ledger_writer(settings, wait=False) as token:
        ledger = storage.Ledger(
            settings,
            exclusive_writer_token=token,
            fail_fast_on_maintenance=True,
        )
        _query(ledger)
        with ledger._publication_writer(  # pyright: ignore[reportPrivateUsage]
            force_exclusive=True
        ) as writer:
            assert writer is ledger
            _query(writer)
        assert descriptors == [token.descriptor], "owned token reacquired a file lock"
        assert token.active
        os.fstat(token.descriptor)
        print("owned", flush=True)
        assert sys.stdin.readline() == "release\n"
    assert not token.active


def _run_worker() -> None:
    assert _CODE_PARENT == _ROOT / "src" or _CODE_PARENT.is_relative_to(_ROOT / ".venv")
    action = cast(_Action, sys.argv[1])
    settings = Settings(Path(sys.argv[2]))
    ledger = None
    if action in {"connect", "connect_default", "publication", "publication_default"}:
        ledger = (
            storage.Ledger(settings, fail_fast_on_maintenance=True)
            if action in {"connect", "publication"}
            else storage.Ledger(settings)
        )
    descriptors: list[int] = []
    original_open = storage._open_writer_lock  # pyright: ignore[reportPrivateUsage]

    def record_open(configured: Settings) -> int:
        descriptor = original_open(configured)
        descriptors.append(descriptor)
        return descriptor

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(storage, "_open_writer_lock", record_open)
        print("ready", flush=True)
        assert sys.stdin.readline() == "go\n"
        print("attempting", flush=True)
        if action == "owned":
            _exercise_owned(settings, descriptors)
            _assert_closed(descriptors)
            print("ok;closed", flush=True)
            return
        results: list[str] = []
        for _ in range(3):
            try:
                _exercise(action, settings, ledger)
            except storage.LedgerWriterBusy:
                results.append("busy")
            else:
                results.append("ok")
            if action not in {"readonly", "live_readonly"}:
                _assert_closed(descriptors)
        if action in {"readonly", "live_readonly"}:
            assert not descriptors, "read-only queries acquired writer locks"
            suffix = "no-lock"
        else:
            suffix = "closed"
        print(f"{','.join(results)};{suffix}", flush=True)


def _assert_reusable(settings: Settings) -> None:
    with storage.exclusive_ledger_writer(settings, wait=False) as token:
        ledger = storage.Ledger(settings, exclusive_writer_token=token)
        _query(ledger)
        descriptor = token.descriptor
    assert not token.active
    _assert_closed([descriptor])


def test_writer_busy_is_a_runtime_error() -> None:
    assert issubclass(storage.LedgerWriterBusy, RuntimeError)


@pytest.mark.parametrize("held_mode", [fcntl.LOCK_SH, fcntl.LOCK_EX], ids=["shared", "exclusive"])
def test_nonblocking_exclusive_writer_refuses_and_closes_descriptors(
    settings: Settings, held_mode: int
) -> None:
    with _worker_process(settings, "exclusive") as worker, _os_lock(settings, held_mode):
        worker.start()
        worker.finish("busy,busy,busy;closed")
        _assert_os_busy(settings, fcntl.LOCK_EX)
        if held_mode == fcntl.LOCK_EX:
            _assert_os_busy(settings, fcntl.LOCK_SH)
    _assert_reusable(settings)


@pytest.mark.parametrize("action", ["initialize", "connect", "publication"])
def test_flagged_writable_paths_refuse_exclusive_maintenance_promptly(
    settings: Settings, action: _Action
) -> None:
    with _worker_process(settings, action) as worker, _os_lock(settings, fcntl.LOCK_EX):
        worker.start()
        worker.finish("busy,busy,busy;closed")
        _assert_os_busy(settings, fcntl.LOCK_SH)
        _assert_os_busy(settings, fcntl.LOCK_EX)
    _assert_reusable(settings)


def test_flagged_connection_uses_shared_not_exclusive_lock(settings: Settings) -> None:
    with _worker_process(settings, "connect") as worker, _os_lock(settings, fcntl.LOCK_SH):
        worker.start()
        worker.finish("ok,ok,ok;closed")
        _assert_os_busy(settings, fcntl.LOCK_EX)
    _assert_reusable(settings)


def test_flagged_publication_requires_exclusive_lock(settings: Settings) -> None:
    with _worker_process(settings, "publication") as worker, _os_lock(settings, fcntl.LOCK_SH):
        worker.start()
        worker.finish("busy,busy,busy;closed")
        _assert_os_busy(settings, fcntl.LOCK_EX)
    _assert_reusable(settings)


@pytest.mark.parametrize(
    "action", ["exclusive_default", "exclusive_wait", "connect_default", "publication_default"]
)
def test_ordinary_writers_wait_then_resume(settings: Settings, action: _Action) -> None:
    with _worker_process(settings, action) as worker:
        with _os_lock(settings, fcntl.LOCK_EX):
            worker.start()
            with pytest.raises(TimeoutError):
                worker.receive(timeout=0.2)
            _assert_os_busy(settings, fcntl.LOCK_EX)
        worker.finish("ok,ok,ok;closed")
    _assert_reusable(settings)


def test_deadline_failure_reaps_blocked_worker_without_releasing_owner(settings: Settings) -> None:
    with _os_lock(settings, fcntl.LOCK_EX):
        with pytest.raises(TimeoutError), _worker_process(settings, "exclusive_default") as worker:
            worker.start()
            worker.receive(timeout=0.2)
        assert worker.process.poll() is not None
        _assert_os_busy(settings, fcntl.LOCK_SH)
        _assert_os_busy(settings, fcntl.LOCK_EX)
    _assert_reusable(settings)


@pytest.mark.parametrize("action", ["readonly", "live_readonly"])
def test_readonly_queries_remain_available_during_maintenance(
    settings: Settings, action: _Action
) -> None:
    with _worker_process(settings, action) as worker, _os_lock(settings, fcntl.LOCK_EX):
        worker.start()
        worker.finish("ok,ok,ok;no-lock")
        _assert_os_busy(settings, fcntl.LOCK_SH)
    _assert_reusable(settings)


def test_owned_token_bypasses_reacquisition_and_survives_connection_close(
    settings: Settings,
) -> None:
    with _worker_process(settings, "owned") as worker:
        worker.start()
        assert worker.receive() == "owned"
        _assert_os_busy(settings, fcntl.LOCK_SH)
        _assert_os_busy(settings, fcntl.LOCK_EX)
        worker.send(b"release\n")
        worker.finish("ok;closed")
    _assert_reusable(settings)
