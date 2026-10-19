from __future__ import annotations

import io
import os
import signal
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import cross_assistant_memory.recovery as recovery
from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import EncryptedObjectManifest, EncryptedObjectStore
from cross_assistant_memory.recovery_status import (
    BACKUP_RECEIPT_ROOT,
    RESTORE_RECEIPT_ROOT,
    inspect_recovery_status,
)
from tests.test_b2_capture_resume import (
    FakeProviderError,
    RecoveryCase,
    _cli_error,  # pyright: ignore[reportPrivateUsage]
    _cli_interrupted,  # pyright: ignore[reportPrivateUsage]
    _run_cli,  # pyright: ignore[reportPrivateUsage]
)
from tests.test_b2_capture_resume import recovery_case as recovery_case


@pytest.mark.parametrize("failure", ["corruption", "provider", "sigint"])
def test_b2_restore_failure_drains_decryptions_before_workspace_cleanup(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    case = recovery_case
    _run_cli(capsys, case.arguments("backup", "--b2"))
    original_restore = EncryptedObjectStore.restore_file
    original_get = case.client.get_object
    original_shutdown = ThreadPoolExecutor.shutdown
    original_cleanup = tempfile.TemporaryDirectory[str].cleanup
    original_handler = signal.getsignal(signal.SIGINT)
    assert original_handler == signal.default_int_handler
    caller = threading.get_ident()
    lock = threading.Lock()
    fault_ready = threading.Event()
    peers_ready = threading.Event()
    fault_release = threading.Event()
    peer_release = threading.Event()
    draining = threading.Event()
    outputs: dict[str, Path] = {}
    worker_sources: dict[int, str] = {}
    reads: dict[str, int] = {}
    active: set[str] = set()
    peers: set[str] = set()
    settled: set[str] = set()
    succeeded: set[str] = set()
    errors: dict[str, BaseException] = {}
    parents_at_settlement: list[bool] = []
    cleanup_states: list[tuple[int, int, bool]] = []
    fault_source: str | None = None

    def observed_restore(
        self: EncryptedObjectStore, source_object_id: str, output: Path
    ) -> EncryptedObjectManifest:
        nonlocal fault_source
        if "restored-snapshot" not in output.parts:
            return original_restore(self, source_object_id, output)
        with lock:
            if fault_source is None:
                fault_source = source_object_id
            outputs[source_object_id] = output
            worker_sources[threading.get_ident()] = source_object_id
            active.add(source_object_id)
        try:
            manifest = original_restore(self, source_object_id, output)
            with lock:
                succeeded.add(source_object_id)
            return manifest
        except BaseException as error:
            with lock:
                errors[source_object_id] = error
            raise
        finally:
            with lock:
                parents_at_settlement.append(output.parent.is_dir())
                active.remove(source_object_id)
                settled.add(source_object_id)

    def get_object(**kwargs: object) -> dict[str, object]:
        with lock:
            source = worker_sources.get(threading.get_ident())
            if source is not None:
                reads[source] = reads.get(source, 0) + 1
                read_number = reads[source]
            else:
                read_number = 0
        if source is not None and source == fault_source and read_number == 1:
            fault_ready.set()
            assert fault_release.wait(10)
            if failure == "provider":
                raise FakeProviderError("AccessDenied")
            if failure == "corruption":
                response = original_get(**kwargs)
                body = cast(io.BytesIO, response["Body"])
                payload = body.getvalue()
                body.close()
                response["Body"] = io.BytesIO(bytes([payload[0] ^ 1]) + payload[1:])
                return response
        elif source is not None and source != fault_source and read_number == 2:
            # The second open happens after ciphertext verification and partial-file creation.
            with lock:
                peers.add(source)
                if len(peers) == 3:
                    peers_ready.set()
            assert peer_release.wait(10)
        return original_get(**kwargs)

    def observed_shutdown(
        self: ThreadPoolExecutor, wait: bool = True, *, cancel_futures: bool = False
    ) -> None:
        if threading.get_ident() == caller:
            draining.set()
        original_shutdown(self, wait, cancel_futures=cancel_futures)

    def observed_cleanup(self: tempfile.TemporaryDirectory[str]) -> None:
        if Path(self.name).name.startswith(f".{case.output.name}.restore-"):
            with lock:
                cleanup_states.append(
                    (
                        len(active),
                        len(settled),
                        any(t.name.startswith("cam-b2-io") for t in threading.enumerate()),
                    )
                )
        original_cleanup(self)

    def release_after_shutdown_starts() -> None:
        try:
            assert fault_ready.wait(10)
            assert peers_ready.wait(10)
            if failure == "sigint":
                os.kill(os.getpid(), signal.SIGINT)
            fault_release.set()
            assert draining.wait(10)
            with lock:
                assert len(active) == 3
                assert len(settled) == 1
                assert not cleanup_states
                assert all(outputs[source].parent.is_dir() for source in active)
                assert all(
                    list(outputs[source].parent.glob(f".{outputs[source].name}.*.partial"))
                    for source in active
                )
            assert not case.output.exists()
        finally:
            fault_release.set()
            peer_release.set()

    monkeypatch.setattr(EncryptedObjectStore, "restore_file", observed_restore)
    monkeypatch.setattr(case.client, "get_object", get_object)
    monkeypatch.setattr(ThreadPoolExecutor, "shutdown", observed_shutdown)
    monkeypatch.setattr(tempfile.TemporaryDirectory, "cleanup", observed_cleanup)
    with ThreadPoolExecutor(max_workers=1) as controller:
        observer = controller.submit(release_after_shutdown_starts)
        try:
            if failure == "sigint":
                _cli_interrupted(capsys, case.arguments("restore", "--b2"))
            else:
                error_name = "FakeProviderError" if failure == "provider" else "RuntimeError"
                assert f"B2 restore failed ({error_name})" in _cli_error(
                    capsys, case.arguments("restore", "--b2")
                )
        finally:
            fault_release.set()
            peer_release.set()
            observer.result(timeout=10)

    assert len(outputs) == len(settled) == 4
    assert not active
    assert all(parents_at_settlement)
    assert cleanup_states == [(0, 4, False)]
    assert caller not in worker_sources
    if failure == "sigint":
        assert not errors
        assert succeeded == settled
    else:
        assert set(errors) == {fault_source}
        assert len(succeeded) == 3
        if failure == "corruption":
            assert (
                str(next(iter(errors.values()))) == "encrypted backend object failed verification"
            )
        else:
            assert isinstance(next(iter(errors.values())), FakeProviderError)
    assert not case.output.exists()
    assert not list(case.output.parent.glob(f".{case.output.name}.restore-*"))
    assert not list(case.output.parent.glob(f".{case.output.name}.candidate-*"))
    assert signal.getsignal(signal.SIGINT) == original_handler
    assert not any(t.name.startswith("cam-b2-io") for t in threading.enumerate())


def test_b2_restore_preserves_encrypted_private_receipts_readonly_on_caller(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = recovery_case
    _run_cli(capsys, case.arguments("backup", "--b2"))
    _run_cli(capsys, case.arguments("restore", "--b2"))
    second = replace(
        case,
        settings=Settings(case.output),
        package_kit=case.package_kit.with_name("second-package-kit.json"),
        output=case.output.with_name("second-node"),
    )
    retained = {
        path.relative_to(case.output): path.read_bytes()
        for root in (BACKUP_RECEIPT_ROOT, RESTORE_RECEIPT_ROOT)
        for path in (case.output / root).glob("*.json")
    }
    assert retained
    _run_cli(capsys, second.arguments("backup", "--b2"))
    caller = threading.get_ident()
    original_chmod = Path.chmod
    original_verify = recovery.verify_snapshot
    chmod_threads: dict[Path, int] = {}
    checked: set[Path] = set()

    def observed_chmod(self: Path, mode: int, *, follow_symlinks: bool = True) -> None:
        if "restored-snapshot" in self.parts and mode == 0o400:
            chmod_threads[self] = threading.get_ident()
        original_chmod(self, mode, follow_symlinks=follow_symlinks)

    def verify_snapshot(snapshot: Path) -> dict[str, Any]:
        if snapshot.name == "restored-snapshot":
            for relative, payload in retained.items():
                path = snapshot / relative
                assert path.read_bytes() == payload
                assert path.stat().st_mode & 0o777 == 0o400
                assert chmod_threads[path] == caller
                checked.add(relative)
        return original_verify(snapshot)

    monkeypatch.setattr(Path, "chmod", observed_chmod)
    monkeypatch.setattr(recovery, "verify_snapshot", verify_snapshot)
    result = _run_cli(capsys, second.arguments("restore", "--b2"))
    assert result["status"] == "verified"
    assert checked == set(retained)
    for relative, payload in retained.items():
        assert (second.output / relative).read_bytes() == payload
    receipts = [
        path
        for root in (BACKUP_RECEIPT_ROOT, RESTORE_RECEIPT_ROOT)
        for path in (second.output / root).glob("*.json")
    ]
    assert len(receipts) == 4
    assert all(path.stat().st_mode & 0o777 == 0o400 for path in receipts)
    status = inspect_recovery_status(Settings(second.output))
    assert status["status"] == "backup_and_restore_verified"
    assert status["invalid_receipt_count"] == 0
    assert not any(t.name.startswith("cam-b2-io") for t in threading.enumerate())


@pytest.mark.parametrize("ignore_sigint", [False, True])
def test_b2_restore_overlaps_four_independent_files(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    ignore_sigint: bool,
) -> None:
    case = recovery_case
    _run_cli(capsys, case.arguments("backup", "--b2"))
    original = EncryptedObjectStore.restore_file
    lock = threading.Lock()
    release = threading.Event()
    active = peak = 0
    caller = threading.get_ident()
    threads: set[int] = set()

    def observed(
        self: EncryptedObjectStore, source_object_id: str, output: Path
    ) -> recovery.EncryptedObjectManifest:
        nonlocal active, peak
        if "restored-snapshot" not in output.parts:
            return original(self, source_object_id, output)
        with lock:
            active += 1
            peak = max(peak, active)
            threads.add(threading.get_ident())
            if active == 4:
                release.set()
        try:
            assert release.wait(5)
            return original(self, source_object_id, output)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(EncryptedObjectStore, "restore_file", observed)
    timer = threading.Timer(1, release.set)
    original_handler = signal.getsignal(signal.SIGINT)
    if ignore_sigint:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    timer.start()
    try:
        result = _run_cli(capsys, case.arguments("restore", "--b2"))
        assert signal.getsignal(signal.SIGINT) == (
            signal.SIG_IGN if ignore_sigint else original_handler
        )
    finally:
        signal.signal(signal.SIGINT, original_handler)
        release.set()
        timer.cancel()
        timer.join()
    assert result["status"] == "verified"
    assert peak == 4
    assert active == 0 and caller not in threads
    assert not any(t.name.startswith("cam-b2-io") for t in threading.enumerate())
