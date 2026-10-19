from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock

import pytest

import cross_assistant_memory.backup as backup_module
from cross_assistant_memory.backup import create_snapshot, verify_snapshot
from cross_assistant_memory.config import Settings
from cross_assistant_memory.storage import Ledger


@pytest.mark.parametrize("active_source", [False, True])
def test_snapshot_copy_is_self_contained_without_wal(tmp_path: Path, active_source: bool) -> None:
    settings = Settings(tmp_path / "data")
    Ledger(settings)
    source_digest = hashlib.sha256(settings.database_path.read_bytes()).hexdigest()
    writer = sqlite3.connect(settings.database_path) if active_source else None
    snapshot = tmp_path / "snapshot"
    try:
        if writer is not None:
            writer.execute("BEGIN IMMEDIATE")
        create_snapshot(settings, snapshot)
        database = snapshot / "ledger.sqlite3"
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as reader:
            assert reader.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert not Path(f"{database}-wal").exists()
        assert not Path(f"{database}-shm").exists()
        assert hashlib.sha256(settings.database_path.read_bytes()).hexdigest() == source_digest
        assert verify_snapshot(snapshot)["status"] == "verified"
    finally:
        if writer is not None:
            writer.rollback()
            writer.close()


@pytest.mark.parametrize("active_wal", [False, True])
def test_snapshot_generation_uses_one_validated_read_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, active_wal: bool
) -> None:
    settings = Settings(tmp_path / "data")
    expected = Ledger(settings).generation_digest()
    writer = sqlite3.connect(settings.database_path)
    try:
        if active_wal:
            writer.execute("BEGIN IMMEDIATE")
        before = hashlib.sha256(settings.database_path.read_bytes()).hexdigest()
        reopened = Mock(side_effect=AssertionError("generation reopened the live ledger"))
        monkeypatch.setattr(backup_module, "Ledger", reopened)
        validate = Mock(wraps=backup_module.validate_current_schema_objects)
        rotation = Mock(wraps=backup_module.require_rotation_access)
        monkeypatch.setattr(backup_module, "validate_current_schema_objects", validate)
        monkeypatch.setattr(backup_module, "require_rotation_access", rotation)

        assert backup_module.snapshot_source_generation(settings) == expected

        reopened.assert_not_called()
        assert validate.call_count == rotation.call_count == 1
        assert hashlib.sha256(settings.database_path.read_bytes()).hexdigest() == before
    finally:
        writer.rollback()
        writer.close()
