from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest

from cross_assistant_memory import setup_workflow as setup_workflow_module
from cross_assistant_memory.config import Settings
from cross_assistant_memory.human_gates import HumanGateKind
from cross_assistant_memory.setup_workflow import (
    SetupAction,
    SetupState,
    apply_setup_plan,
    build_setup_plan,
    inspect_setup,
    load_setup_plan,
    verify_setup,
    write_setup_plan,
)
from cross_assistant_memory.storage import SCHEMA_VERSION, Ledger


def test_absent_setup_inspection_and_plan_do_not_mutate_the_target(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")

    inspection = inspect_setup(settings)
    first = build_setup_plan(settings)
    second = build_setup_plan(settings)

    assert inspection.state is SetupState.ABSENT
    assert first.action is SetupAction.INITIALIZE
    assert first.plan_sha256 == second.plan_sha256
    assert not settings.data_root.exists()

    plan_path = tmp_path / "setup-plan.json"
    result = write_setup_plan(first, plan_path)

    assert result["plan_sha256"] == first.plan_sha256
    assert stat.S_IMODE(plan_path.stat().st_mode) == 0o400
    assert load_setup_plan(plan_path) == first
    assert not settings.data_root.exists()


def test_fresh_setup_applies_atomically_and_reruns_as_a_noop(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)

    preview = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=False,
    )
    assert preview["status"] == "awaiting_execute"
    assert not settings.data_root.exists()

    applied = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )
    assert applied["status"] == "initialized"
    assert applied["mutated"] is True
    assert inspect_setup(settings).state is SetupState.READY
    assert verify_setup(settings)["integrity_check"] == "ok"

    same_plan_rerun = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )
    assert same_plan_rerun["status"] == "already_configured"
    assert same_plan_rerun["mutated"] is False

    rerun_plan = build_setup_plan(settings)
    rerun_path = tmp_path / "rerun-plan.json"
    write_setup_plan(rerun_plan, rerun_path)
    rerun = apply_setup_plan(
        settings,
        rerun_path,
        expected_plan_sha256=rerun_plan.plan_sha256,
        execute=False,
    )
    assert rerun_plan.action is SetupAction.VERIFY
    assert rerun["status"] == "already_configured"
    assert rerun["mutated"] is False


def _prepare_retained_wal(settings: Settings, *, pending_write: bool = False) -> None:
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sqlite3
import sys
from pathlib import Path

from cross_assistant_memory.config import Settings
from cross_assistant_memory.storage import Ledger

settings = Settings(Path(sys.argv[1]))
Ledger(settings)
connection = sqlite3.connect(settings.database_path)
assert connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
if sys.argv[2] == "pending":
    connection.execute(
        "INSERT INTO installations VALUES (?, ?, ?)",
        ("installation:extra", "owner:extra", "2026-10-06T00:00:00+00:00"),
    )
    connection.commit()
os._exit(0)
""",
            str(settings.data_root),
            "pending" if pending_write else "checkpointed",
        ],
        check=True,
        timeout=30,
    )
    wal = Path(f"{settings.database_path}-wal")
    shm = Path(f"{settings.database_path}-shm")
    assert wal.stat().st_size > 0 if pending_write else wal.stat().st_size == 0
    assert shm.stat().st_size > 0


def test_setup_verifies_idle_checkpointed_wal_without_mutation(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    _prepare_retained_wal(settings)
    before = {
        path.relative_to(settings.data_root): path.read_bytes()
        for path in settings.data_root.rglob("*")
        if path.is_file()
    }

    inspection = inspect_setup(settings)
    plan = build_setup_plan(settings)
    verified = verify_setup(settings)

    assert inspection.state is SetupState.READY
    assert inspection.reasons == ()
    assert plan.action is SetupAction.VERIFY
    assert verified["mutated"] is False
    assert verified["state_sha256"] == inspection.state_sha256
    assert verified["installation_count"] == 1
    assert before == {
        path.relative_to(settings.data_root): path.read_bytes()
        for path in settings.data_root.rglob("*")
        if path.is_file()
    }


def test_setup_refuses_checkpointed_wal_with_a_managed_writer(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    _prepare_retained_wal(settings)
    descriptor = os.open(settings.run_root / "ledger-writer.lock", os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        assert inspect_setup(settings).state is SetupState.ACTIVE
        with pytest.raises(RuntimeError, match="found active"):
            verify_setup(settings)
    finally:
        os.close(descriptor)
    assert verify_setup(settings)["status"] == "verified"


def test_setup_refuses_uncheckpointed_wal_rows(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    _prepare_retained_wal(settings, pending_write=True)

    assert inspect_setup(settings).state is SetupState.ACTIVE
    assert build_setup_plan(settings).action is SetupAction.PAUSE
    with pytest.raises(RuntimeError, match="found active"):
        verify_setup(settings)


@pytest.mark.parametrize("poison", ["missing_shm", "symlink", "hardlink", "permissions"])
def test_setup_refuses_incomplete_or_unsafe_checkpointed_wal(tmp_path: Path, poison: str) -> None:
    settings = Settings(tmp_path / "memory")
    _prepare_retained_wal(settings)
    wal = Path(f"{settings.database_path}-wal")
    if poison == "missing_shm":
        Path(f"{settings.database_path}-shm").unlink()
    elif poison == "symlink":
        wal.unlink()
        wal.symlink_to(tmp_path / "unrelated")
    elif poison == "hardlink":
        os.link(wal, tmp_path / "second-wal-link")
    else:
        wal.chmod(0o644)

    expected = SetupState.ACTIVE if poison == "missing_shm" else SetupState.UNSAFE
    assert inspect_setup(settings).state is expected
    with pytest.raises(RuntimeError, match=f"found {expected.value}"):
        verify_setup(settings)


def test_frozen_ledger_still_refuses_idle_checkpointed_wal(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    _prepare_retained_wal(settings)

    with pytest.raises(RuntimeError, match="no SQLite sidecars"):
        Ledger(settings, read_only=True)


def test_setup_holds_writer_lease_through_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(tmp_path / "memory")
    _prepare_retained_wal(settings)
    original_connect = setup_workflow_module._connect_sqlite_descriptor  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def require_exclusive_lease(descriptor: int) -> sqlite3.Connection:
        nonlocal calls
        probe = os.open(settings.run_root / "ledger-writer.lock", os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
        finally:
            os.close(probe)
        calls += 1
        return original_connect(descriptor)

    monkeypatch.setattr(
        setup_workflow_module, "_connect_sqlite_descriptor", require_exclusive_lease
    )
    assert verify_setup(settings)["status"] == "verified"
    assert calls == 3
    probe = os.open(settings.run_root / "ledger-writer.lock", os.O_RDONLY)
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(probe)


@pytest.mark.parametrize("during", ["inspection", "verification"])
def test_setup_refuses_a_wal_change_during_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    during: str,
) -> None:
    settings = Settings(tmp_path / "memory")
    _prepare_retained_wal(settings)
    original_connect = setup_workflow_module._connect_sqlite_descriptor  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def mutate_wal(descriptor: int) -> sqlite3.Connection:
        nonlocal calls
        calls += 1
        if calls == (1 if during == "inspection" else 2):
            with Path(f"{settings.database_path}-wal").open("ab") as wal:
                wal.write(b"changed during inspection")
        return original_connect(descriptor)

    monkeypatch.setattr(setup_workflow_module, "_connect_sqlite_descriptor", mutate_wal)
    if during == "inspection":
        assert inspect_setup(settings).state is SetupState.ACTIVE
    else:
        with pytest.raises(RuntimeError, match="changed during verification"):
            verify_setup(settings)
    probe = os.open(settings.run_root / "ledger-writer.lock", os.O_RDONLY)
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(probe)


def test_same_plan_recovers_after_publication_before_the_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    original_verify = setup_workflow_module.verify_setup
    failed_once = False

    def fail_after_publication(candidate: Settings) -> dict[str, object]:
        nonlocal failed_once
        if candidate.data_root == settings.data_root and not failed_once:
            failed_once = True
            raise RuntimeError("injected receipt interruption")
        return original_verify(candidate)

    monkeypatch.setattr(setup_workflow_module, "verify_setup", fail_after_publication)
    with pytest.raises(RuntimeError, match="receipt interruption"):
        apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256=plan.plan_sha256,
            execute=True,
        )

    resumed = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )

    assert resumed["status"] == "already_configured"
    assert resumed["mutated"] is False
    assert verify_setup(settings)["integrity_check"] == "ok"


def test_same_plan_resumes_a_complete_plan_owned_staging_root(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    staging = setup_workflow_module._setup_staging_path(  # pyright: ignore[reportPrivateUsage]
        plan
    )
    Ledger(Settings(staging))
    setup_workflow_module._write_setup_publication_marker(  # pyright: ignore[reportPrivateUsage]
        staging,
        plan,
    )

    resumed = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )

    assert resumed["status"] == "initialized"
    assert resumed["mutated"] is True
    assert settings.data_root.exists()
    assert not staging.exists()
    assert verify_setup(settings)["integrity_check"] == "ok"


def test_same_plan_recovers_an_empty_interrupted_staging_root(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    staging = setup_workflow_module._setup_staging_path(  # pyright: ignore[reportPrivateUsage]
        plan
    )
    staging.mkdir(mode=0o700)

    result = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )

    assert result["status"] == "initialized"
    assert settings.data_root.exists()
    assert not staging.exists()
    assert verify_setup(settings)["integrity_check"] == "ok"


def test_same_plan_recovers_a_marked_staging_root_after_hard_exit(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    staging = setup_workflow_module._setup_staging_path(  # pyright: ignore[reportPrivateUsage]
        plan
    )
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sys
from pathlib import Path

import cross_assistant_memory.setup_workflow as setup
from cross_assistant_memory.config import Settings

def die_during_initialization(settings):
    partial = settings.data_root / "ledger.sqlite3"
    partial.write_bytes(b"partial")
    partial.chmod(0o600)
    os._exit(71)

setup.Ledger = die_during_initialization
setup.apply_setup_plan(
    Settings(Path(sys.argv[1])),
    Path(sys.argv[2]),
    expected_plan_sha256=sys.argv[3],
    execute=True,
)
""",
            str(settings.data_root),
            str(plan_path),
            plan.plan_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert child.returncode == 71
    assert staging.exists()
    assert (staging / "ledger.sqlite3").read_bytes() == b"partial"

    result = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )

    assert result["status"] == "initialized"
    assert not staging.exists()
    assert verify_setup(settings)["integrity_check"] == "ok"


def test_same_plan_recovers_when_killed_during_staging_marker_write(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    staging = setup_workflow_module._setup_staging_path(  # pyright: ignore[reportPrivateUsage]
        plan
    )
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sys
from pathlib import Path

import cross_assistant_memory.setup_workflow as setup
from cross_assistant_memory.config import Settings

def die_during_marker_write(descriptor, payload):
    os.write(descriptor, payload[:8])
    os.fsync(descriptor)
    os._exit(74)

setup._write_all = die_during_marker_write
setup.apply_setup_plan(
    Settings(Path(sys.argv[1])),
    Path(sys.argv[2]),
    expected_plan_sha256=sys.argv[3],
    execute=True,
)
""",
            str(settings.data_root),
            str(plan_path),
            plan.plan_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert child.returncode == 74
    entries = tuple(staging.iterdir())
    assert len(entries) == 1
    assert entries[0].name.startswith(
        setup_workflow_module._setup_marker_temp_prefix(  # pyright: ignore[reportPrivateUsage]
            setup_workflow_module.SETUP_STAGING_MARKER,
            plan,
        )
    )

    result = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )

    assert result["status"] == "initialized"
    assert not staging.exists()
    assert not (settings.data_root / setup_workflow_module.SETUP_STAGING_MARKER).exists()
    assert verify_setup(settings)["integrity_check"] == "ok"


def test_same_plan_recovers_when_ready_staging_dies_before_publication_marker(
    tmp_path: Path,
) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    staging = setup_workflow_module._setup_staging_path(  # pyright: ignore[reportPrivateUsage]
        plan
    )
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sys
from pathlib import Path

import cross_assistant_memory.setup_workflow as setup
from cross_assistant_memory.config import Settings

def die_before_publication_marker(_staging, _plan):
    os._exit(72)

setup._write_setup_publication_marker = die_before_publication_marker
setup.apply_setup_plan(
    Settings(Path(sys.argv[1])),
    Path(sys.argv[2]),
    expected_plan_sha256=sys.argv[3],
    execute=True,
)
""",
            str(settings.data_root),
            str(plan_path),
            plan.plan_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert child.returncode == 72
    assert inspect_setup(Settings(staging)).state is SetupState.READY
    assert (staging / setup_workflow_module.SETUP_STAGING_MARKER).is_file()
    assert not (staging / setup_workflow_module.SETUP_PUBLICATION_MARKER).exists()

    result = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )

    assert result["status"] == "initialized"
    assert not staging.exists()
    assert not (settings.data_root / setup_workflow_module.SETUP_STAGING_MARKER).exists()
    assert verify_setup(settings)["integrity_check"] == "ok"


def test_same_plan_recovers_when_ready_staging_dies_before_marker_cleanup(
    tmp_path: Path,
) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    staging = setup_workflow_module._setup_staging_path(  # pyright: ignore[reportPrivateUsage]
        plan
    )
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sys
from pathlib import Path

import cross_assistant_memory.setup_workflow as setup
from cross_assistant_memory.config import Settings

def die_before_staging_marker_cleanup(_staging):
    os._exit(73)

setup._fsync_setup_tree = die_before_staging_marker_cleanup
setup.apply_setup_plan(
    Settings(Path(sys.argv[1])),
    Path(sys.argv[2]),
    expected_plan_sha256=sys.argv[3],
    execute=True,
)
""",
            str(settings.data_root),
            str(plan_path),
            plan.plan_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert child.returncode == 73
    assert inspect_setup(Settings(staging)).state is SetupState.READY
    assert (staging / setup_workflow_module.SETUP_STAGING_MARKER).is_file()
    assert (staging / setup_workflow_module.SETUP_PUBLICATION_MARKER).is_file()

    result = apply_setup_plan(
        settings,
        plan_path,
        expected_plan_sha256=plan.plan_sha256,
        execute=True,
    )

    assert result["status"] == "initialized"
    assert not staging.exists()
    assert not (settings.data_root / setup_workflow_module.SETUP_STAGING_MARKER).exists()
    assert verify_setup(settings)["integrity_check"] == "ok"


def test_same_plan_rejects_unmarked_nonempty_staging_root(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    staging = setup_workflow_module._setup_staging_path(  # pyright: ignore[reportPrivateUsage]
        plan
    )
    staging.mkdir(mode=0o700)
    unrelated = staging / "unrelated.txt"
    unrelated.write_text("preserve me\n")
    unrelated.chmod(0o600)

    with pytest.raises(RuntimeError, match="staging state is incomplete or unsafe"):
        apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256=plan.plan_sha256,
            execute=True,
        )

    assert not settings.data_root.exists()
    assert unrelated.read_text() == "preserve me\n"


def test_same_plan_serializes_concurrent_setup_application(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)

    def apply(_index: int) -> dict[str, object]:
        return apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256=plan.plan_sha256,
            execute=True,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(apply, range(2)))

    assert sorted(str(result["status"]) for result in results) == [
        "already_configured",
        "initialized",
    ]
    assert inspect_setup(settings).state is SetupState.READY
    assert not list(tmp_path.glob(".memory.setup-*"))


def test_same_plan_serializes_setup_application_across_processes(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    lock_path = tmp_path / ".memory.setup.lock"
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    child: subprocess.Popen[str] | None = None
    try:
        os.fchmod(lock_descriptor, 0o600)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        command = [
            sys.executable,
            "-c",
            "from cross_assistant_memory.cli import main; main()",
            "--home",
            str(settings.data_root),
            "setup-apply",
            "--plan",
            str(plan_path),
            "--expected-plan-sha256",
            plan.plan_sha256,
            "--execute",
        ]
        child = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.2)
        assert child.poll() is None
        assert not settings.data_root.exists()
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        stdout, stderr = child.communicate(timeout=15)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()

    assert child is not None
    assert child.returncode == 0, stderr
    assert json.loads(stdout)["status"] == "initialized"

    replay = subprocess.run(command, check=True, capture_output=True, text=True)
    assert json.loads(replay.stdout)["status"] == "already_configured"
    assert inspect_setup(settings).state is SetupState.READY


def test_setup_apply_rejects_an_unsafe_target_lock(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    lock = tmp_path / ".memory.setup.lock"
    lock.write_text("unsafe\n", encoding="utf-8")
    lock.chmod(0o644)

    with pytest.raises(RuntimeError, match="setup target lock is unsafe"):
        apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256=plan.plan_sha256,
            execute=True,
        )

    assert not settings.data_root.exists()


def test_absent_plan_rejects_an_independently_created_ready_ledger(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "fresh-plan.json"
    write_setup_plan(plan, plan_path)
    Ledger(settings)

    with pytest.raises(RuntimeError, match="not published by this plan"):
        apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256=plan.plan_sha256,
            execute=True,
        )


def test_setup_rejects_a_stale_plan_without_initializing(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "stale-plan.json"
    write_setup_plan(plan, plan_path)
    settings.data_root.mkdir(mode=0o700)

    with pytest.raises(RuntimeError, match="changed after"):
        apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256=plan.plan_sha256,
            execute=True,
        )

    assert list(settings.data_root.iterdir()) == []


def test_legacy_setup_pauses_without_migrating(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    Ledger(settings)
    with closing(sqlite3.connect(settings.database_path)) as connection:
        connection.execute("DELETE FROM schema_migrations")
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (11, ?)",
            ("2026-09-03T00:00:00+00:00",),
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    before = settings.database_path.read_bytes()

    inspection = inspect_setup(settings)
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "legacy-plan.json"
    write_setup_plan(plan, plan_path)

    assert inspection.state is SetupState.LEGACY
    assert inspection.schema_version == 11
    assert plan.action is SetupAction.PAUSE
    assert [gate.kind for gate in plan.required_human_gates] == [HumanGateKind.OPERATOR_REVIEW]
    assert len(plan.required_human_gates[0].gate_sha256) == 64
    with pytest.raises(RuntimeError, match="operator review"):
        apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256=plan.plan_sha256,
            execute=True,
        )
    assert settings.database_path.read_bytes() == before
    with closing(sqlite3.connect(settings.database_path)) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 11


def test_setup_inspection_rejects_symlinks_and_broad_permissions(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(external, target_is_directory=True)

    symlinked = inspect_setup(Settings(linked))
    assert symlinked.state is SetupState.UNSAFE
    assert any("symlink" in reason for reason in symlinked.reasons)

    settings = Settings(tmp_path / "memory")
    Ledger(settings)
    settings.data_root.chmod(0o755)
    try:
        broad = inspect_setup(settings)
        assert broad.state is SetupState.UNSAFE
        assert broad.reasons == ("directory_permissions_invalid:.",)
    finally:
        settings.data_root.chmod(0o700)


def test_setup_inspection_rejects_a_dangling_symlink_ancestor(tmp_path: Path) -> None:
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "missing", target_is_directory=True)

    inspection = inspect_setup(Settings(dangling / "memory"))

    assert inspection.state is SetupState.UNSAFE
    assert inspection.reasons == ("data_root_ancestor_is_symlink",)


def test_setup_rejects_a_real_hot_rollback_journal(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    Ledger(settings)
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA journal_mode = DELETE")
connection.execute("PRAGMA synchronous = FULL")
connection.execute("PRAGMA cache_size = 1")
connection.execute("BEGIN IMMEDIATE")
connection.execute("CREATE TABLE hot_journal_probe(payload BLOB)")
for _ in range(256):
    connection.execute("INSERT INTO hot_journal_probe VALUES (randomblob(4096))")
os._exit(0)
""",
            str(settings.database_path),
        ],
        check=True,
    )
    journal = Path(f"{settings.database_path}-journal")
    assert journal.stat().st_size > 512
    journal.chmod(0o600)

    inspection = inspect_setup(settings)

    assert inspection.state is SetupState.ACTIVE
    present = ",".join(
        "ledger.sqlite3" + suffix
        for suffix in ("-wal", "-shm", "-journal")
        if Path(f"{settings.database_path}{suffix}").exists()
    )
    assert inspection.reasons == ("sqlite_sidecars_present:" + present,)
    with pytest.raises(RuntimeError, match="found active"):
        verify_setup(settings)


@pytest.mark.parametrize("poison", ["missing", "symlink", "hardlink", "permissions"])
def test_setup_rejects_an_unusable_writer_lock(tmp_path: Path, poison: str) -> None:
    settings = Settings(tmp_path / "memory")
    Ledger(settings)
    lock = settings.run_root / "ledger-writer.lock"
    if poison == "missing":
        lock.unlink()
    elif poison == "symlink":
        lock.unlink()
        lock.symlink_to(tmp_path / "missing-lock")
    elif poison == "hardlink":
        os.link(lock, tmp_path / "second-lock-link")
    else:
        lock.chmod(0o644)

    inspection = inspect_setup(settings)

    expected = SetupState.UNSAFE
    if poison == "missing":
        expected = (
            SetupState.ACTIVE
            if Path(f"{settings.database_path}-wal").exists()
            else SetupState.PARTIAL
        )
    assert inspection.state is expected
    with pytest.raises(RuntimeError, match="setup verification requires ready state"):
        verify_setup(settings)


@pytest.mark.parametrize("violation", ["installation", "foreign_key"])
def test_setup_rejects_application_invariant_violations(
    tmp_path: Path,
    violation: str,
) -> None:
    settings = Settings(tmp_path / "memory")
    Ledger(settings)
    with closing(sqlite3.connect(settings.database_path)) as connection:
        if violation == "installation":
            connection.execute(
                "INSERT INTO installations VALUES (?, ?, ?)",
                ("installation:extra", "owner:extra", "2026-09-03T00:00:00+00:00"),
            )
        else:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                "INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "device:orphan",
                    "installation:missing",
                    "orphan",
                    "test",
                    "active",
                    "2026-09-03T00:00:00+00:00",
                    "2026-09-03T00:00:00+00:00",
                ),
            )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()

    inspection = inspect_setup(settings)

    assert inspection.state is SetupState.INVALID
    assert inspection.reasons == (
        "installation_count_invalid" if violation == "installation" else "foreign_key_violation",
    )
    with pytest.raises(RuntimeError, match="found invalid"):
        verify_setup(settings)


@pytest.mark.parametrize(
    ("state", "prepare"),
    [
        (SetupState.PARTIAL, "partial"),
        (SetupState.ACTIVE, "active"),
        (SetupState.NEWER, "newer"),
        (SetupState.INVALID, "invalid"),
    ],
)
def test_nonconvergent_setup_states_pause_without_mutation(
    tmp_path: Path,
    state: SetupState,
    prepare: str,
) -> None:
    settings = Settings(tmp_path / "memory")
    if prepare == "partial":
        settings.data_root.mkdir(mode=0o700)
    elif prepare == "invalid":
        settings.ensure_directories()
        settings.database_path.write_bytes(b"not sqlite")
        settings.database_path.chmod(0o600)
    else:
        Ledger(settings)
        if prepare == "active":
            _prepare_retained_wal(settings, pending_write=True)
        else:
            with closing(sqlite3.connect(settings.database_path)) as connection:
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION + 1, "2026-09-03T00:00:00+00:00"),
                )
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    before = {
        path.relative_to(settings.data_root): path.read_bytes()
        for path in settings.data_root.rglob("*")
        if path.is_file()
    }

    inspection = inspect_setup(settings)
    plan = build_setup_plan(settings)

    assert inspection.state is state
    assert plan.action is SetupAction.PAUSE
    assert [gate.kind for gate in plan.required_human_gates] == [HumanGateKind.OPERATOR_REVIEW]
    after = {
        path.relative_to(settings.data_root): path.read_bytes()
        for path in settings.data_root.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_setup_plan_rejects_tampering_and_wrong_permissions(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "setup-plan.json"
    write_setup_plan(plan, plan_path)

    plan_path.chmod(0o600)
    with pytest.raises(ValueError, match="mode 0400"):
        load_setup_plan(plan_path)

    raw = json.loads(plan_path.read_text(encoding="utf-8"))
    raw["action"] = SetupAction.VERIFY.value
    plan_path.write_text(json.dumps(raw), encoding="utf-8")
    plan_path.chmod(0o400)
    with pytest.raises(ValueError, match="does not match"):
        load_setup_plan(plan_path)


def test_setup_publication_collision_preserves_the_competing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "setup-plan.json"
    write_setup_plan(plan, plan_path)
    original_publish = setup_workflow_module.publish_directory_no_replace

    def race(source: Path, target: Path, **kwargs: object) -> None:
        target.mkdir(mode=0o700)
        (target / "keep.txt").write_text("keep", encoding="utf-8")
        original_publish(source, target, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(setup_workflow_module, "publish_directory_no_replace", race)

    with pytest.raises(FileExistsError, match="already exists"):
        apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256=plan.plan_sha256,
            execute=True,
        )

    assert (settings.data_root / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert not list(tmp_path.glob(".memory.setup-*"))


def test_setup_plan_output_must_be_outside_the_target(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)

    with pytest.raises(ValueError, match="outside"):
        write_setup_plan(plan, settings.data_root / "plan.json")


def test_setup_plan_digest_must_match_at_apply_time(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "memory")
    plan = build_setup_plan(settings)
    plan_path = tmp_path / "setup-plan.json"
    write_setup_plan(plan, plan_path)

    with pytest.raises(ValueError, match="SHA-256"):
        apply_setup_plan(
            settings,
            plan_path,
            expected_plan_sha256="0" * 64,
            execute=True,
        )

    assert not settings.data_root.exists()
