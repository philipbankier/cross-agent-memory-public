from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory import portable as portable_module
from cross_assistant_memory.backup import (
    create_offline_clone,
    create_snapshot,
    load_snapshot_manifest,
    verify_snapshot,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import Capability, ClientKind, Scope, SourceSystem
from cross_assistant_memory.storage import Ledger


def test_legacy_wal_snapshot_clone_preserves_the_artifact(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "data")
    Ledger(settings)
    snapshot = tmp_path / "snapshot"
    create_snapshot(settings, snapshot)
    database = snapshot / "ledger.sqlite3"
    legacy = tmp_path / "legacy.sqlite3"
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("VACUUM INTO ?", (str(legacy),)).fetchall()
    legacy.chmod(0o600)
    with closing(sqlite3.connect(legacy)) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    assert legacy.read_bytes()[18:20] == b"\x02\x02"
    assert not any(Path(f"{legacy}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal"))
    legacy.replace(database)
    manifest = load_snapshot_manifest(snapshot)
    database_bytes = database.read_bytes()
    entries = [entry for entry in manifest["files"] if entry["path"] == "ledger.sqlite3"]
    assert len(entries) == 1
    entries[0]["size"] = len(database_bytes)
    entries[0]["sha256"] = hashlib.sha256(database_bytes).hexdigest()
    manifest_path = snapshot / "snapshot-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    verified = verify_snapshot(snapshot)
    before = {
        path.relative_to(snapshot): path.read_bytes()
        for path in snapshot.rglob("*")
        if path.is_file()
    }
    clone_root = tmp_path / "clone"
    create_offline_clone(snapshot, clone_root)
    assert (
        Ledger(Settings(clone_root), read_only=True, require_checkpointed=False).status()["events"]
        == 0
    )
    assert (
        verify_snapshot(snapshot)["snapshot_manifest_sha256"]
        == verified["snapshot_manifest_sha256"]
    )
    assert {
        path.relative_to(snapshot): path.read_bytes()
        for path in snapshot.rglob("*")
        if path.is_file()
    } == before


@pytest.mark.parametrize("change", ["index", "credential"])
def test_portable_verifier_reads_committed_wal(tmp_path: Path, change: str) -> None:
    settings = Settings(tmp_path / "data")
    ledger = Ledger(settings)
    source = tmp_path / "synthetic.jsonl"
    source.write_text(
        json.dumps({"type": "session_meta", "payload": {"id": "synthetic-wal", "source": "vscode"}})
        + "\n"
        + json.dumps(
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Synthetic WAL decision."}],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )
    with closing(sqlite3.connect(settings.database_path)) as keeper:
        keeper.execute("PRAGMA journal_mode=WAL").fetchall()
        assert keeper.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
        if change == "index":
            keeper.execute("DELETE FROM events_fts")
            keeper.commit()
            error = "search index is incomplete"
            query = "SELECT COUNT(*) FROM events_fts"
            frozen_count = 1
        else:
            client = ledger.register_client(
                label="synthetic WAL client",
                kind=ClientKind.ASSISTANT,
                capabilities=[Capability.MEMORY_SEARCH],
            )
            ledger.issue_client_credential(
                cast(str, client["client_id"]),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
            error = "credential-bearing rows"
            query = "SELECT COUNT(*) FROM client_credentials"
            frozen_count = 0
        assert Path(f"{settings.database_path}-wal").stat().st_size > 0
        with closing(
            sqlite3.connect(settings.database_path.as_uri() + "?mode=ro&immutable=1", uri=True)
        ) as frozen:
            assert frozen.execute(query).fetchone()[0] == frozen_count
        generation = Ledger(
            settings, read_only=True, require_checkpointed=False
        ).generation_digest()
        with pytest.raises(RuntimeError, match=error):
            portable_module._verify_imported_node(  # pyright: ignore[reportPrivateUsage]
                settings, expected_generation=generation
            )
