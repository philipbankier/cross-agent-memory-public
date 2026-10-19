from __future__ import annotations

import fcntl
import os
import signal
import threading
import time
from collections.abc import Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

import cross_assistant_memory.recovery as recovery
from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import (
    EncryptedObjectManifest,
    EncryptedObjectStore,
    FilesystemObjectBackend,
    RootKey,
)
from cross_assistant_memory.recovery import (
    _run_b2_object_io,  # pyright: ignore[reportPrivateUsage]
)
from cross_assistant_memory.storage import exclusive_ledger_writer


@pytest.fixture
def manifest(tmp_path: Path) -> EncryptedObjectManifest:
    source = tmp_path / "synthetic.txt"
    source.write_bytes(b"synthetic concurrency fixture")
    store = EncryptedObjectStore(
        tmp_path / "metadata", FilesystemObjectBackend(tmp_path / "objects"), RootKey.generate()
    )
    return store.put_file(source, media_type="text/plain")


def _items(manifest: EncryptedObjectManifest, sizes: list[int]) -> list[EncryptedObjectManifest]:
    return [
        replace(
            manifest,
            source_object_id=f"source_{index:032x}",
            storage_object_id=f"storage_{index:032x}",
            ciphertext_byte_length=size,
        )
        for index, size in enumerate(sizes)
    ]


def test_b2_io_bounds_submissions_and_keeps_guards_on_caller(
    manifest: EncryptedObjectManifest, monkeypatch: pytest.MonkeyPatch
) -> None:
    items = _items(manifest, [1] * 12)
    release = threading.Event()
    started = threading.Event()
    entered_wait = threading.Event()
    lock = threading.Lock()
    active = 0
    peak = 0
    caller: list[int] = []
    guard_threads: list[int] = []
    before_ids: list[str] = []
    after_ids: list[str] = []
    worker_threads: set[int] = set()
    original_wait = recovery.wait

    def observed_wait(
        futures: Iterable[Future[None]], *, return_when: str = FIRST_COMPLETED
    ) -> tuple[set[Future[None]], set[Future[None]]]:
        entered_wait.set()
        return original_wait(futures, return_when=return_when)

    monkeypatch.setattr(recovery, "wait", observed_wait)

    def before(item: EncryptedObjectManifest) -> None:
        guard_threads.append(threading.get_ident())
        before_ids.append(item.source_object_id)

    def after(item: EncryptedObjectManifest) -> None:
        guard_threads.append(threading.get_ident())
        after_ids.append(item.source_object_id)

    def operation(_item: EncryptedObjectManifest) -> None:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            worker_threads.add(threading.get_ident())
            if active == 4:
                started.set()
        try:
            assert release.wait(5)
        finally:
            with lock:
                active -= 1

    def run() -> None:
        caller.append(threading.get_ident())
        _run_b2_object_io(items, operation, before=before, after=after)

    with ThreadPoolExecutor(max_workers=1) as controller:
        result = controller.submit(run)
        try:
            assert started.wait(5)
            assert entered_wait.wait(5)
            assert len(before_ids) == 4
        finally:
            release.set()
        result.result(timeout=5)
    assert peak == 4
    assert active == 0
    assert before_ids == [item.source_object_id for item in items]
    assert set(after_ids) == set(before_ids)
    assert set(guard_threads) == set(caller)
    assert not worker_threads.intersection(caller)
    assert not any(thread.name.startswith("cam-b2-io") for thread in threading.enumerate())


def test_b2_io_byte_budget_runs_oversized_objects_alone(
    manifest: EncryptedObjectManifest, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(recovery, "_B2_IO_BYTES", 100)
    items = _items(manifest, [60, 60, 150, 25, 25, 25, 25, 25])
    lock = threading.Lock()
    active: dict[str, int] = {}
    observations: list[tuple[int, int]] = []

    def operation(item: EncryptedObjectManifest) -> None:
        with lock:
            active[item.source_object_id] = item.ciphertext_byte_length
            observations.append((len(active), sum(active.values())))
        try:
            time.sleep(0.02)
        finally:
            with lock:
                del active[item.source_object_id]

    _run_b2_object_io(items, operation)
    assert len(observations) == len(items)
    assert all(count <= 4 and (size <= 100 or count == 1) for count, size in observations)
    assert (1, 150) in observations
    assert not active


@pytest.mark.parametrize("failure", ["before", "operation", "after", "interrupt"])
def test_b2_io_failure_settles_started_work_before_return(
    manifest: EncryptedObjectManifest, failure: str
) -> None:
    items = _items(manifest, [1] * 12)
    release = threading.Event()
    all_started = threading.Event()
    failed = threading.Event()
    lock = threading.Lock()
    executed: list[str] = []
    finished: list[str] = []
    expected_started = 2 if failure == "before" else 4

    def fail() -> None:
        failed.set()
        if failure == "interrupt":
            raise KeyboardInterrupt
        raise RuntimeError("synthetic bounded I/O failure")

    def before(item: EncryptedObjectManifest) -> None:
        if failure == "before" and item == items[2]:
            assert all_started.wait(5)
            fail()

    def after(item: EncryptedObjectManifest) -> None:
        if failure == "after" and item == items[0]:
            fail()

    def operation(item: EncryptedObjectManifest) -> None:
        with lock:
            executed.append(item.source_object_id)
            if len(executed) == expected_started:
                all_started.set()
        try:
            if item == items[0] and failure != "before":
                assert all_started.wait(5)
                if failure != "after":
                    fail()
            else:
                assert release.wait(5)
        finally:
            with lock:
                finished.append(item.source_object_id)

    with ThreadPoolExecutor(max_workers=1) as controller:
        result = controller.submit(_run_b2_object_io, items, operation, before=before, after=after)
        try:
            assert failed.wait(5)
            assert not result.done()
        finally:
            release.set()
        expected_error = KeyboardInterrupt if failure == "interrupt" else RuntimeError
        with pytest.raises(expected_error):
            result.result(timeout=5)
    assert len(executed) == expected_started
    assert set(finished) == set(executed)
    assert not any(thread.name.startswith("cam-b2-io") for thread in threading.enumerate())


def test_b2_io_empty_inventory_performs_no_operation() -> None:
    def unexpected(_item: EncryptedObjectManifest) -> None:
        pytest.fail("empty inventory must not execute provider operations or guards")

    _run_b2_object_io([], unexpected, before=unexpected, after=unexpected)


@pytest.mark.parametrize("provider_failure", [False, True])
def test_b2_io_repeated_sigint_keeps_writer_until_started_operations_settle(
    manifest: EncryptedObjectManifest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_failure: bool,
) -> None:
    items = _items(manifest, [1] * 12)
    settings = Settings(tmp_path / "signal-node")
    started = threading.Event()
    first_complete = threading.Event()
    release = threading.Event()
    draining = threading.Event()
    returned = threading.Event()
    lock = threading.Lock()
    executed: list[str] = []
    settled: list[str] = []
    original_handler = signal.getsignal(signal.SIGINT)
    assert original_handler == signal.default_int_handler
    original_shutdown = ThreadPoolExecutor.shutdown

    def observed_shutdown(
        self: ThreadPoolExecutor, wait: bool = True, *, cancel_futures: bool = False
    ) -> None:
        draining.set()
        original_shutdown(self, wait, cancel_futures=cancel_futures)

    monkeypatch.setattr(ThreadPoolExecutor, "shutdown", observed_shutdown)

    def operation(item: EncryptedObjectManifest) -> None:
        with lock:
            executed.append(item.source_object_id)
            if len(executed) == 4:
                started.set()
        try:
            if item == items[0]:
                assert first_complete.wait(5)
                if provider_failure:
                    raise RuntimeError("synthetic provider failure before repeated interrupt")
            else:
                assert release.wait(5)
        finally:
            with lock:
                settled.append(item.source_object_id)

    def interrupt() -> None:
        try:
            assert started.wait(5)
            if not provider_failure:
                os.kill(os.getpid(), signal.SIGINT)
            first_complete.set()
            assert draining.wait(5)
            for _ in range(3):
                os.kill(os.getpid(), signal.SIGINT)
                time.sleep(0.02)
                assert not returned.is_set()
                with (
                    (settings.run_root / "ledger-writer.lock").open("rb") as lease,
                    pytest.raises(BlockingIOError),
                ):
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            first_complete.set()
            release.set()

    with ThreadPoolExecutor(max_workers=1) as controller, exclusive_ledger_writer(settings):
        signals = controller.submit(interrupt)
        try:
            with pytest.raises(KeyboardInterrupt):
                _run_b2_object_io(items, operation)
        finally:
            returned.set()
        signals.result(timeout=5)
    assert len(executed) == 4
    assert set(settled) == set(executed)
    assert signal.getsignal(signal.SIGINT) == original_handler
    assert not any(thread.name.startswith("cam-b2-io") for thread in threading.enumerate())
    with (settings.run_root / "ledger-writer.lock").open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lease, fcntl.LOCK_UN)


def test_b2_io_preserves_embedding_signal_policy(manifest: EncryptedObjectManifest) -> None:
    items = _items(manifest, [1] * 5)
    callers: list[int] = []
    original = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        _run_b2_object_io(items, lambda _item: callers.append(threading.get_ident()))
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGINT, original)
    assert len(callers) == len(items)
    assert threading.get_ident() not in callers


def test_b2_io_custom_signal_handler_stays_on_caller(manifest: EncryptedObjectManifest) -> None:
    items = _items(manifest, [1] * 5)
    callers: list[int] = []

    def handler(_signum: int, _frame: object) -> None:
        pytest.fail("custom signal handler must not be called")

    original = signal.signal(signal.SIGINT, handler)
    try:
        _run_b2_object_io(items, lambda _item: callers.append(threading.get_ident()))
        assert signal.getsignal(signal.SIGINT) is handler
    finally:
        signal.signal(signal.SIGINT, original)
    assert callers == [threading.get_ident()] * len(items)
