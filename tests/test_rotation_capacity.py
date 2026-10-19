from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest

import cross_assistant_memory.evidence_rotation as rotation
from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import (
    FilesystemObjectBackend,
    OperationalKey,
    RecoverySecret,
    RootKey,
    build_recovery_kit,
)
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import Scope, SourceSystem
from cross_assistant_memory.private_json import write_owner_only_json
from cross_assistant_memory.storage import Ledger, exclusive_ledger_writer
from tests.test_b2_capture_resume import write_jsonl

MIB = 1024 * 1024
RETAINED_LIMITS = [(50_000, 64), (50_000, 80), (64_000, 100)]


@dataclass(frozen=True)
class RotationCase:
    settings: Settings
    config: Path
    new_key: Path
    backend_root: Path


@pytest.fixture
def case(tmp_path: Path) -> RotationCase:
    root = tmp_path.resolve()
    settings = Settings(root / "data")
    ledger = Ledger(settings)
    source = write_jsonl(
        root / "synthetic.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "rotation-capacity", "source": "vscode"}},
            *[
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": f"Synthetic rotation capacity record {i}.",
                            }
                        ],
                    },
                }
                for i in range(2)
            ],
        ],
    )
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )
    material = root / "material"
    material.mkdir(mode=0o700)
    for name in ("old", "new"):
        secret = RecoverySecret.generate()
        kit = build_recovery_kit(RootKey.generate(), secret)
        OperationalKey.from_recovery_kit(kit, secret).write(material / f"{name}.json")
    backend_root = root / "backend"
    backend = FilesystemObjectBackend(backend_root)
    reader = EncryptedEvidenceReader(
        backend, OperationalKey.load(material / "old.json").root_key, MIB, 2 * MIB
    )
    with exclusive_ledger_writer(settings) as token:
        ledger = Ledger(settings, exclusive_writer_token=token, encrypted_evidence_reader=reader)
        events = ledger.search("Synthetic rotation capacity", scopes=[Scope.USER_GLOBAL])
        assert len(events) == 2
        for event in events:
            ledger.publish_encrypted_evidence(
                event.event_id,
                expected_generation_digest=ledger.generation_digest(),
                authorized_by="local:synthetic-test",
                authorization_scope="memory:maintain",
                reason="synthetic rotation capacity fixture",
            )
    config = material / "evidence.json"
    write_owner_only_json(
        config,
        {
            "format_version": 1,
            "data_root": str(settings.data_root),
            "operational_key": str(material / "old.json"),
            "backend": {"profile": "filesystem-v1", "root": str(backend_root)},
            "max_plaintext_bytes": MIB,
            "max_ciphertext_bytes": 2 * MIB,
            "max_snapshot_bytes": 4 * MIB,
        },
        label="synthetic evidence configuration",
        max_bytes=16 * 1024,
    )
    result = RotationCase(settings, config, material / "new.json", backend_root)
    assert len(_mappings(result)) == 2
    return result


def _tree(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


def _mappings(case: RotationCase) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(case.settings.database_path)) as connection:
        return connection.execute(
            "SELECT * FROM encrypted_object_locations ORDER BY object_id"
        ).fetchall()


def _journal(case: RotationCase) -> dict[str, Any]:
    with closing(sqlite3.connect(case.settings.database_path)) as connection:
        row = connection.execute("SELECT journal_json FROM evidence_rotation").fetchone()
    assert row is not None
    return cast(dict[str, Any], json.loads(row[0]))


def _extended_plan(objects: int, inventory_mib: int, journal_mib: int = 192) -> dict[str, Any]:
    return {
        "format_version": 2,
        "capacity": "extended",
        "capacity_limits": {
            "objects": objects,
            "inventory_bytes": inventory_mib * MIB,
            "journal_bytes": journal_mib * MIB,
        },
    }


def _process(case: RotationCase, command: str, operation: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "cross_assistant_memory",
            "--home",
            str(case.settings.data_root),
            command,
            "--operation-id",
            operation,
            "--execute",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return cast(dict[str, Any], json.loads(result.stdout))


def test_capacity_limits_are_explicit_and_bound_to_the_plan(case: RotationCase) -> None:
    standard = rotation.plan_rotation(case.settings, case.config, case.new_key)
    explicit = rotation.plan_rotation(case.settings, case.config, case.new_key, capacity="standard")
    extended = rotation.plan_rotation(case.settings, case.config, case.new_key, capacity="extended")
    assert standard == explicit
    assert standard["capacity"] == "standard"
    assert standard["capacity_limits"] == {
        "objects": 10_000,
        "inventory_bytes": 32 * MIB // 3,
        "journal_bytes": 32 * MIB,
    }
    assert extended["capacity"] == "extended"
    assert extended["capacity_limits"] == _extended_plan(100_000, 112)["capacity_limits"]
    assert standard["plan_sha256"] != extended["plan_sha256"]
    before = _tree(case.settings.data_root)
    with pytest.raises(RuntimeError, match="plan changed"):
        rotation.apply_rotation(
            case.settings,
            case.config,
            case.new_key,
            expected_plan_sha256=extended["plan_sha256"],
            execute=True,
        )
    assert _tree(case.settings.data_root) == before
    assert rotation.rotation_status(case.settings)["status"] == "not_started"


def test_standard_overflow_does_not_automatically_select_extended(
    case: RotationCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rotation, "MAX_ROTATION_OBJECTS", 1)
    before = _tree(case.settings.data_root)
    with pytest.raises(ValueError, match="object limit"):
        rotation.plan_rotation(case.settings, case.config, case.new_key)
    assert _tree(case.settings.data_root) == before
    extended = rotation.plan_rotation(case.settings, case.config, case.new_key, capacity="extended")
    assert extended["object_count"] == 2
    assert extended["capacity_limits"] == _extended_plan(100_000, 112)["capacity_limits"]
    assert rotation.rotation_status(case.settings)["status"] == "not_started"


@pytest.mark.parametrize(("objects", "inventory_mib"), RETAINED_LIMITS)
def test_previous_extended_plan_requires_regeneration(
    case: RotationCase, monkeypatch: pytest.MonkeyPatch, objects: int, inventory_mib: int
) -> None:
    with monkeypatch.context() as old_runtime:
        old_runtime.setattr(rotation, "MAX_EXTENDED_ROTATION_OBJECTS", objects)
        old_runtime.setattr(rotation, "MAX_EXTENDED_ROTATION_INVENTORY_BYTES", inventory_mib * MIB)
        plan = rotation.plan_rotation(case.settings, case.config, case.new_key, capacity="extended")
    before = _tree(case.settings.data_root)
    with pytest.raises(RuntimeError, match="plan changed"):
        rotation.apply_rotation(
            case.settings,
            case.config,
            case.new_key,
            capacity="extended",
            expected_plan_sha256=plan["plan_sha256"],
            execute=True,
        )
    assert _tree(case.settings.data_root) == before
    assert rotation.rotation_status(case.settings)["status"] == "not_started"


@pytest.mark.parametrize(("objects", "inventory_mib"), RETAINED_LIMITS)
def test_retained_journal_resumes_and_rolls_back_in_fresh_processes(
    case: RotationCase, monkeypatch: pytest.MonkeyPatch, objects: int, inventory_mib: int
) -> None:
    generation = Ledger(case.settings, read_only=True).generation_digest()
    mappings = _mappings(case)
    config = case.config.read_bytes()
    ciphertext = _tree(case.backend_root)
    assert len(ciphertext) == 2
    with monkeypatch.context() as old_runtime:
        old_runtime.setattr(rotation, "MAX_EXTENDED_ROTATION_OBJECTS", objects)
        old_runtime.setattr(rotation, "MAX_EXTENDED_ROTATION_INVENTORY_BYTES", inventory_mib * MIB)
        plan = rotation.plan_rotation(case.settings, case.config, case.new_key, capacity="extended")
        applied = rotation.apply_rotation(
            case.settings,
            case.config,
            case.new_key,
            capacity="extended",
            expected_plan_sha256=plan["plan_sha256"],
            execute=True,
        )
    assert applied["status"] == "restart_required"
    assert _tree(case.backend_root) == ciphertext
    assert _mappings(case) != mappings
    operation = applied["operation_id"]
    original_limits = _extended_plan(objects, inventory_mib)["capacity_limits"]
    journal = _journal(case)
    assert journal["plan"]["capacity_limits"] == original_limits
    limits = rotation._plan_limits(journal["plan"])  # pyright: ignore[reportPrivateUsage]
    assert asdict(limits) == original_limits
    assert journal["plan"]["before_generation"] == generation
    assert _process(case, "evidence-rotation-resume", operation)["status"] == "active"
    rotated_generation = Ledger(case.settings, read_only=True).generation_digest()
    assert rotated_generation == _journal(case)["after_generation"]
    assert rotated_generation != generation
    assert _tree(case.backend_root) == ciphertext
    assert _journal(case)["plan"]["capacity_limits"] == original_limits
    assert _process(case, "evidence-rotation-rollback", operation)["status"] == "restart_required"
    assert _tree(case.backend_root) == ciphertext
    assert _journal(case)["plan"]["capacity_limits"] == original_limits
    assert _process(case, "evidence-rotation-resume", operation)["status"] == "rolled_back"
    assert _mappings(case) == mappings
    assert case.config.read_bytes() == config
    assert _tree(case.backend_root) == ciphertext
    assert Ledger(case.settings, read_only=True).generation_digest() == generation
    assert _journal(case)["plan"]["capacity_limits"] == original_limits


@pytest.mark.parametrize(("objects", "inventory_mib"), [*RETAINED_LIMITS, (100_000, 112)])
def test_issued_inventory_enforces_its_original_object_limit_without_a_large_corpus(
    objects: int, inventory_mib: int
) -> None:
    limits = rotation._plan_limits(  # pyright: ignore[reportPrivateUsage]
        _extended_plan(objects, inventory_mib)
    )
    assert asdict(limits) == _extended_plan(objects, inventory_mib)["capacity_limits"]
    connection = Mock(spec=sqlite3.Connection)
    connection.execute.return_value.fetchone.return_value = (objects + 1,)
    with pytest.raises(ValueError, match="object limit"):
        rotation._inventory(  # pyright: ignore[reportPrivateUsage]
            cast(sqlite3.Connection, connection), limits
        )
    connection.execute.assert_called_once_with("SELECT count(*) FROM encrypted_object_locations")


@pytest.mark.parametrize(
    ("objects", "inventory_mib", "journal_mib"),
    [
        (50_000, 70, 192),
        (64_000, 80, 192),
        (64_000, 100, 193),
        (100_000, 113, 192),
        (100_001, 112, 192),
        (100_000, 112, 193),
    ],
)
def test_unissued_extended_limits_refuse(
    objects: int, inventory_mib: int, journal_mib: int
) -> None:
    with pytest.raises(ValueError, match="capacity limits changed"):
        rotation._plan_limits(  # pyright: ignore[reportPrivateUsage]
            _extended_plan(objects, inventory_mib, journal_mib)
        )


@pytest.mark.parametrize("bound", ["OBJECTS", "INVENTORY_BYTES", "JOURNAL_BYTES"])
def test_extended_bounds_refuse_before_preparation(
    case: RotationCase, monkeypatch: pytest.MonkeyPatch, bound: str
) -> None:
    monkeypatch.setattr(rotation, f"MAX_EXTENDED_ROTATION_{bound}", 1)
    before = _tree(case.settings.data_root)
    config = case.config.read_bytes()
    ciphertext = _tree(case.backend_root)
    with pytest.raises(ValueError, match=r"limit|budget"):
        plan = rotation.plan_rotation(case.settings, case.config, case.new_key, capacity="extended")
        rotation.apply_rotation(
            case.settings,
            case.config,
            case.new_key,
            capacity="extended",
            expected_plan_sha256=plan["plan_sha256"],
            execute=True,
        )
    assert _tree(case.settings.data_root) == before
    assert case.config.read_bytes() == config
    assert _tree(case.backend_root) == ciphertext
    assert rotation.rotation_status(case.settings)["status"] == "not_started"
