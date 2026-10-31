from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal

import pytest

from cross_assistant_memory.collector import CollectorQueueConfig
from cross_assistant_memory.collector_queue import (
    CURSOR_CHECKPOINT_PAYLOAD,
    EMPTY_SHA256,
    QUEUE_DATABASE_FILENAME,
    QUEUE_PAYLOAD_FORMAT_VERSION,
    QUEUE_SCHEMA_V3,
    QUEUE_SCHEMA_V4,
    QUEUE_SCHEMA_V5,
    QUEUE_SCHEMA_VERSION,
    QUEUE_SELECTION_SCHEMA,
    CollectorQueue,
    QueueItemKind,
    QueueItemState,
    _associated_data,  # pyright: ignore[reportPrivateUsage]
    _QueueMetadata,  # pyright: ignore[reportPrivateUsage]
    source_key_for,
)
from cross_assistant_memory.models import ParseResult, SourceKind, SourceSystem
from cross_assistant_memory.tink_crypto import AeadPrimitive, Keyset

QUEUE_SCHEMA_V6 = QUEUE_SCHEMA_V5 + QUEUE_SELECTION_SCHEMA
NOW = 1_700_000_000
ACCOUNT = "source-account"


def test_payload_format_stays_at_version_3() -> None:
    assert QUEUE_PAYLOAD_FORMAT_VERSION == 3
    assert QUEUE_SCHEMA_VERSION == 7


def test_source_key_for_accepts_grok_bot_and_rejects_web_sources() -> None:
    path_hash = _digest("grok-bot-path")
    source_key = source_key_for(SourceSystem.GROK_BOT, ACCOUNT, path_hash)
    assert (
        source_key
        == hashlib.sha256(
            json.dumps(
                [SourceSystem.GROK_BOT.value, ACCOUNT, path_hash],
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode()
        ).hexdigest()
    )
    assert source_key_for(SourceSystem.CODEX, ACCOUNT, path_hash) != source_key
    with pytest.raises(ValueError, match="native sources"):
        source_key_for(SourceSystem.CHATGPT_WEB, ACCOUNT, path_hash)


def test_new_queue_starts_at_schema_7(tmp_path: Path) -> None:
    config = _config(tmp_path)
    queue = CollectorQueue.initialize(config)
    assert queue.status(now_epoch=NOW).schema_version == 7
    with _connect(config) as connection:
        _assert_current_source_check(connection)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_schema6_migration_preserves_ciphertext_cursors_and_foreign_keys(tmp_path: Path) -> None:
    config, primitive = _materialize(tmp_path, QUEUE_SCHEMA_V6, 6)
    codex_key, hold_key, build_key, checkpoint, hold_ciphertext = _populate_schema6(
        config, primitive
    )
    before = _snapshot(config)
    opened = CollectorQueue.open(config)
    assert opened.status(now_epoch=NOW).schema_version == 6
    assert _user_version(config) == 6
    assert _snapshot(config) == before

    queue = CollectorQueue.initialize(config)
    assert queue.status(now_epoch=NOW).schema_version == 7
    after = _snapshot(config)
    assert after["queue_items"] == before["queue_items"]
    assert after["source_state"] == before["source_state"]
    assert after["replay_boundaries"] == before["replay_boundaries"]
    assert after["file_observations"] == before["file_observations"]
    assert after["initial_selections"] == before["initial_selections"]
    assert after["scan_rotation"] == before["scan_rotation"]
    assert _user_version(config) == 7

    with _connect(config) as connection:
        _assert_current_source_check(connection)
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        connection.execute("BEGIN")
        connection.execute("DELETE FROM source_state WHERE source_key = ?", (codex_key,))
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM file_observations WHERE source_key = ?",
                (codex_key,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM replay_boundaries WHERE source_key = ?",
                (codex_key,),
            ).fetchone()[0]
            == 0
        )
        connection.rollback()

    retained = queue.cursor_checkpoint(codex_key)
    assert retained is not None
    assert retained.end_record_ordinal == checkpoint.end_record_ordinal
    assert retained.end_byte_offset == checkpoint.end_byte_offset
    assert retained.end_prefix_sha256 == checkpoint.end_prefix_sha256
    cursor = queue.cursor(codex_key)
    assert cursor is not None
    assert (cursor.next_record_ordinal, cursor.next_byte_offset, cursor.prefix_digest) == (
        checkpoint.start_record_ordinal,
        checkpoint.start_byte_offset,
        checkpoint.start_prefix_sha256,
    )
    held = queue.schema_hold(hold_key)
    assert held is not None
    assert held.end_byte_offset == 8
    with _connect(config) as connection:
        stored = connection.execute(
            "SELECT ciphertext FROM queue_items WHERE item_id = ?",
            ("queue:schema-hold",),
        ).fetchone()
        assert stored is not None
        assert stored[0] == hold_ciphertext
        build = connection.execute(
            "SELECT next_record_ordinal, next_byte_offset, prefix_sha256, last_success_at_epoch "
            "FROM source_state WHERE source_key = ?",
            (build_key,),
        ).fetchone()
        assert tuple(build) == (9, 400, _digest("build-prefix"), NOW + 50)

    repeated = _snapshot(config)
    again = CollectorQueue.initialize(config)
    assert again.status(now_epoch=NOW).schema_version == 7
    assert _snapshot(config) == repeated

    codex_path = tmp_path / "codex-session.jsonl"
    codex_parsed = _parse_result(SourceSystem.CODEX, codex_path)
    codex_item = queue.enqueue_cursor_checkpoint(
        codex_parsed, source_account_id="codex-continued", now_epoch=NOW + 10
    )
    codex_source = source_key_for(
        SourceSystem.CODEX,
        "codex-continued",
        hashlib.sha256(str(codex_path).encode()).hexdigest(),
    )
    continued = queue.cursor(codex_source)
    assert continued is not None
    assert continued.conversation_id == codex_parsed.conversation_id
    assert continued.next_byte_offset == 0
    assert queue.cursor_checkpoint(codex_source) is not None
    assert codex_item.startswith("queue:")

    grok_path = tmp_path / "grok-bot-session.jsonl"
    grok_parsed = _parse_result(SourceSystem.GROK_BOT, grok_path)
    grok_account = "grok-bot-account"
    grok_key = source_key_for(
        SourceSystem.GROK_BOT,
        grok_account,
        hashlib.sha256(str(grok_path).encode()).hexdigest(),
    )
    queue.enqueue_cursor_checkpoint(grok_parsed, source_account_id=grok_account, now_epoch=NOW + 20)
    accepted = queue.cursor(grok_key)
    assert accepted is not None
    assert (accepted.next_record_ordinal, accepted.next_byte_offset, accepted.prefix_digest) == (
        0,
        0,
        EMPTY_SHA256,
    )
    assert any(
        source.source_system is SourceSystem.GROK_BOT and source.source_key == grok_key
        for source in queue.status(now_epoch=NOW + 20).sources
    )


def test_altered_or_unknown_schema_is_rejected_before_mutation(tmp_path: Path) -> None:
    config, _primitive = _materialize(tmp_path, QUEUE_SCHEMA_V6, 6)
    with _connect(config) as connection:
        connection.execute("ALTER TABLE queue_items ADD COLUMN tamper TEXT")
        connection.execute(
            "UPDATE queue_items SET tamper = 'sentinel' WHERE item_id = 'queue:codex-checkpoint'"
        )
    before = _snapshot(config)
    with pytest.raises(RuntimeError, match="unknown legacy schema"):
        CollectorQueue.initialize(config)
    assert _snapshot(config) == before
    assert _user_version(config) == 6

    with _connect(config) as connection:
        connection.execute("PRAGMA user_version = 8")
    stamped = _snapshot(config)
    with pytest.raises(RuntimeError, match="unsupported"):
        CollectorQueue.initialize(config)
    assert _snapshot(config) == stamped
    assert _user_version(config) == 8


def test_interrupted_schema6_migration_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, primitive = _materialize(tmp_path, QUEUE_SCHEMA_V6, 6)
    _populate_schema6(config, primitive)
    before = _snapshot(config)
    real_connect = sqlite3.connect
    drop_table = getattr(sqlite3, "SQLITE_DROP_TABLE", 32)
    deny = getattr(sqlite3, "SQLITE_DENY", 1)
    allow = getattr(sqlite3, "SQLITE_OK", 0)

    def connect(
        database: str | bytes | os.PathLike[str],
        timeout: float = 5.0,
        detect_types: int = 0,
        isolation_level: Literal["DEFERRED", "EXCLUSIVE", "IMMEDIATE"] | None = "DEFERRED",
        check_same_thread: bool = True,
        cached_statements: int = 128,
        uri: bool = False,
    ) -> sqlite3.Connection:
        connection = real_connect(
            database,
            timeout=timeout,
            detect_types=detect_types,
            isolation_level=isolation_level,
            check_same_thread=check_same_thread,
            cached_statements=cached_statements,
            uri=uri,
        )

        def authorizer(
            action: int,
            arg1: str | None,
            _arg2: str | None,
            _database: str | None,
            _source: str | None,
        ) -> int:
            if action == drop_table and arg1 == "queue_items":
                return deny
            return allow

        connection.set_authorizer(authorizer)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        CollectorQueue.initialize(config)
    monkeypatch.undo()
    assert _user_version(config) == 6
    assert _snapshot(config) == before
    assert CollectorQueue.initialize(config).status(now_epoch=NOW).schema_version == 7


def test_user_version_changed_after_preflight_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, primitive = _materialize(tmp_path, QUEUE_SCHEMA_V6, 6)
    _populate_schema6(config, primitive)
    before = _snapshot(config)
    schema_before = _schema_objects(config)
    real_connect = sqlite3.connect
    raced = False

    class VersionRaceConnection(sqlite3.Connection):
        def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
            nonlocal raced
            if not raced and " ".join(sql.split()).upper() == "BEGIN IMMEDIATE":
                raced = True
                listed = super().execute("PRAGMA database_list").fetchone()
                file_name = None if listed is None else listed[2]
                if isinstance(file_name, str) and file_name not in {"", ":memory:"}:
                    other = real_connect(file_name, isolation_level=None)
                    try:
                        other.execute("PRAGMA user_version = 99")
                    finally:
                        other.close()
            return super().execute(sql, parameters)

    def connect(
        database: str | bytes | os.PathLike[str],
        timeout: float = 5.0,
        detect_types: int = 0,
        isolation_level: Literal["DEFERRED", "EXCLUSIVE", "IMMEDIATE"] | None = "DEFERRED",
        check_same_thread: bool = True,
        cached_statements: int = 128,
        uri: bool = False,
    ) -> sqlite3.Connection:
        return real_connect(
            database,
            timeout=timeout,
            detect_types=detect_types,
            isolation_level=isolation_level,
            check_same_thread=check_same_thread,
            factory=VersionRaceConnection,
            cached_statements=cached_statements,
            uri=uri,
        )

    monkeypatch.setattr(sqlite3, "connect", connect)
    with pytest.raises(RuntimeError, match="changed before migration"):
        CollectorQueue.initialize(config)
    monkeypatch.undo()
    assert _user_version(config) == 99
    assert _snapshot(config) == before
    assert _schema_objects(config) == schema_before


@pytest.mark.parametrize(
    ("version", "schema_sql"),
    [
        pytest.param(3, QUEUE_SCHEMA_V3, id="v3"),
        pytest.param(4, QUEUE_SCHEMA_V4, id="v4"),
        pytest.param(5, QUEUE_SCHEMA_V5, id="v5"),
    ],
)
def test_legacy_queue_upgrades_through_schema_6(
    tmp_path: Path, version: int, schema_sql: str
) -> None:
    config, _primitive = _materialize(tmp_path, schema_sql, version)
    source_key = _digest(f"legacy-{version}")
    path_hash = _digest(f"legacy-path-{version}")
    prefix = _digest(f"legacy-prefix-{version}")
    ciphertext = f"legacy-ciphertext-{version}".encode()
    with _connect(config) as connection:
        _insert_source_state(connection, source_key, path_hash, prefix, last_success=None)
        _insert_queue_item(
            connection,
            item_id=f"queue:legacy-{version}",
            kind=QueueItemKind.CURSOR_CHECKPOINT,
            state=QueueItemState.RETRY_WAIT,
            source_key=source_key,
            source_system=SourceSystem.CODEX.value,
            path_hash=path_hash,
            conversation_id=f"legacy-{version}",
            source_kind=SourceKind.INTERACTIVE.value,
            provenance=_digest(f"legacy-provenance-{version}"),
            payload_sha=_digest(f"legacy-payload-{version}"),
            bounds=(1, 16, 2, 32),
            prefixes=(prefix, _digest(f"legacy-end-{version}")),
            attempts=1,
            next_attempt_at=NOW + 5,
            last_error_code="timeout",
            ciphertext=ciphertext,
        )
        connection.execute(
            """
            INSERT INTO replay_boundaries(
              source_key, expected_batch_id, end_record_ordinal, end_byte_offset,
              end_prefix_sha256, observed_file_size, file_mtime_ns, expired_at_epoch
            ) VALUES (?, ?, 2, 32, ?, 32, 7, ?)
            """,
            (source_key, "batch:" + _digest("legacy-batch"), _digest(f"legacy-end-{version}"), NOW),
        )
    before = _snapshot(config)
    opened = CollectorQueue.open(config)
    assert opened.status(now_epoch=NOW).schema_version == version
    assert _snapshot(config) == before

    queue = CollectorQueue.initialize(config)
    assert queue.status(now_epoch=NOW).schema_version == 7
    after = _snapshot(config)
    assert after["queue_items"] == before["queue_items"]
    assert after["source_state"] == before["source_state"]
    assert after["replay_boundaries"] == before["replay_boundaries"]
    with _connect(config) as connection:
        _assert_current_source_check(connection)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    assert {"scan_rotation", "file_observations", "initial_selections"} <= tables
    grok_path = tmp_path / f"grok-bot-{version}.jsonl"
    grok_parsed = _parse_result(SourceSystem.GROK_BOT, grok_path)
    queue.enqueue_cursor_checkpoint(
        grok_parsed, source_account_id=f"grok-bot-{version}", now_epoch=NOW + version
    )


def _config(tmp_path: Path) -> CollectorQueueConfig:
    root = (tmp_path / "queue").resolve()
    secrets = (tmp_path / "secrets").resolve()
    root.mkdir(mode=0o700)
    secrets.mkdir(mode=0o700)
    root.chmod(0o700)
    secrets.chmod(0o700)
    return CollectorQueueConfig(
        root=root,
        key_file=secrets / "queue-key.tink",
        max_bytes=1024 * 1024,
        max_age_seconds=86_400,
    )


def _materialize(
    tmp_path: Path, schema_sql: str, version: int
) -> tuple[CollectorQueueConfig, AeadPrimitive]:
    config = _config(tmp_path)
    keyset = Keyset.generate_aead()
    _write_private(config.key_file, keyset.serialize_cleartext())
    database = config.root / QUEUE_DATABASE_FILENAME
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.executescript(schema_sql)
        connection.execute(f"PRAGMA user_version = {version}")
    finally:
        connection.close()
    database.chmod(0o600)
    return config, keyset.aead()


def _populate_schema6(
    config: CollectorQueueConfig, primitive: AeadPrimitive
) -> tuple[str, str, str, _QueueMetadata, bytes]:
    codex_path_hash = _digest("codex-path")
    codex_key = source_key_for(SourceSystem.CODEX, ACCOUNT, codex_path_hash)
    start_prefix = _digest("codex-start")
    end_prefix = _digest("codex-end")
    provenance = _digest("codex-provenance")
    checkpoint = _QueueMetadata(
        item_id="queue:codex-checkpoint",
        kind=QueueItemKind.CURSOR_CHECKPOINT,
        source_key=codex_key,
        source_system=SourceSystem.CODEX,
        source_path_hash=codex_path_hash,
        conversation_id="conv-codex",
        source_kind=SourceKind.INTERACTIVE,
        provenance_sha256=provenance,
        payload_sha256=hashlib.sha256(CURSOR_CHECKPOINT_PAYLOAD).hexdigest(),
        start_record_ordinal=3,
        start_byte_offset=90,
        end_record_ordinal=5,
        end_byte_offset=140,
        start_prefix_sha256=start_prefix,
        end_prefix_sha256=end_prefix,
        created_at_epoch=NOW,
        expires_at_epoch=NOW + 3600,
    )
    ciphertext = primitive.encrypt(CURSOR_CHECKPOINT_PAYLOAD, _associated_data(checkpoint))
    hold_path_hash = _digest("hold-path")
    hold_key = source_key_for(SourceSystem.CLAUDE_CODE, ACCOUNT, hold_path_hash)
    hold_ciphertext = bytes(range(32)) + b"schema-hold-ciphertext"
    build_path_hash = _digest("build-path")
    build_key = source_key_for(SourceSystem.GROK_BUILD, ACCOUNT, build_path_hash)
    with _connect(config) as connection:
        _insert_source_state(
            connection,
            codex_key,
            codex_path_hash,
            start_prefix,
            last_success=None,
            provenance=provenance,
        )
        _insert_source_state(
            connection,
            build_key,
            build_path_hash,
            _digest("build-prefix"),
            last_success=NOW + 50,
            ordinal=9,
            offset=400,
            system=SourceSystem.GROK_BUILD.value,
            conversation_id="conv-build",
        )
        _insert_queue_item(
            connection,
            item_id=checkpoint.item_id,
            kind=checkpoint.kind,
            state=QueueItemState.RETRY_WAIT,
            source_key=codex_key,
            source_system=SourceSystem.CODEX.value,
            path_hash=codex_path_hash,
            conversation_id=checkpoint.conversation_id,
            source_kind=SourceKind.INTERACTIVE.value,
            provenance=provenance,
            payload_sha=checkpoint.payload_sha256,
            bounds=(3, 90, 5, 140),
            prefixes=(start_prefix, end_prefix),
            attempts=2,
            next_attempt_at=NOW + 30,
            last_error_code="network_unreachable",
            ciphertext=ciphertext,
        )
        _insert_queue_item(
            connection,
            item_id="queue:schema-hold",
            kind=QueueItemKind.SCHEMA_HOLD,
            state=QueueItemState.BLOCKED,
            source_key=hold_key,
            source_system=SourceSystem.CLAUDE_CODE.value,
            path_hash=hold_path_hash,
            conversation_id=None,
            source_kind=None,
            provenance=None,
            payload_sha=hashlib.sha256(hold_ciphertext).hexdigest(),
            bounds=(0, 0, 1, 8),
            prefixes=(EMPTY_SHA256, _digest("hold-end")),
            attempts=0,
            next_attempt_at=NOW,
            last_error_code=None,
            ciphertext=hold_ciphertext,
        )
        connection.execute(
            """
            INSERT INTO replay_boundaries(
              source_key, expected_batch_id, end_record_ordinal, end_byte_offset,
              end_prefix_sha256, observed_file_size, file_mtime_ns, expired_at_epoch
            ) VALUES (?, ?, 5, 140, ?, 180, 99, ?)
            """,
            (codex_key, "batch:" + _digest("replay-batch"), end_prefix, NOW),
        )
        connection.execute(
            """
            INSERT INTO file_observations(
              source_key, file_device, file_inode, file_size, file_mtime_ns, file_ctime_ns,
              end_record_ordinal, end_byte_offset, end_prefix_sha256, complete, observed_at_epoch
            ) VALUES (?, 11, 22, 180, 33, 44, 5, 140, ?, 0, ?)
            """,
            (codex_key, end_prefix, NOW),
        )
        connection.execute(
            """
            INSERT INTO initial_selections(
              source_key, start_record_ordinal, start_byte_offset, start_prefix_sha256
            ) VALUES (?, 3, 90, ?)
            """,
            (codex_key, start_prefix),
        )
        connection.execute(
            """
            INSERT INTO scan_rotation(
              singleton, after_source_key, priority_after_source_key, next_priority
            ) VALUES (1, ?, NULL, 0)
            """,
            (codex_key,),
        )
    return codex_key, hold_key, build_key, checkpoint, hold_ciphertext


def _insert_source_state(
    connection: sqlite3.Connection,
    source_key: str,
    path_hash: str,
    prefix: str,
    *,
    last_success: int | None,
    ordinal: int = 3,
    offset: int = 90,
    system: str = SourceSystem.CODEX.value,
    conversation_id: str = "conv-codex",
    provenance: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO source_state(
          source_key, source_system, source_path_hash, conversation_id, source_kind,
          provenance_sha256, next_record_ordinal, next_byte_offset, prefix_sha256,
          initialized_at_epoch, last_success_at_epoch
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_key,
            system,
            path_hash,
            conversation_id,
            SourceKind.INTERACTIVE.value,
            provenance if provenance is not None else _digest(f"provenance-{source_key}"),
            ordinal,
            offset,
            prefix,
            NOW,
            last_success,
        ),
    )


def _insert_queue_item(
    connection: sqlite3.Connection,
    *,
    item_id: str,
    kind: QueueItemKind,
    state: QueueItemState,
    source_key: str,
    source_system: str,
    path_hash: str,
    conversation_id: str | None,
    source_kind: str | None,
    provenance: str | None,
    payload_sha: str,
    bounds: tuple[int, int, int, int],
    prefixes: tuple[str, str],
    attempts: int,
    next_attempt_at: int,
    last_error_code: str | None,
    ciphertext: bytes,
) -> None:
    connection.execute(
        """
        INSERT INTO queue_items(
          item_id, kind, state, source_key, source_system, source_path_hash,
          conversation_id, source_kind, provenance_sha256, payload_sha256,
          start_record_ordinal, start_byte_offset, end_record_ordinal, end_byte_offset,
          start_prefix_sha256, end_prefix_sha256, created_at_epoch, expires_at_epoch,
          attempts, next_attempt_at_epoch, last_error_code, ciphertext, ciphertext_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item_id,
            kind.value,
            state.value,
            source_key,
            source_system,
            path_hash,
            conversation_id,
            source_kind,
            provenance,
            payload_sha,
            *bounds,
            *prefixes,
            NOW,
            NOW + 3600,
            attempts,
            next_attempt_at,
            last_error_code,
            ciphertext,
            len(ciphertext),
        ),
    )


def _parse_result(
    system: SourceSystem,
    path: Path,
    *,
    start: tuple[int, int, str] = (0, 0, EMPTY_SHA256),
    end: tuple[int, int, str] | None = None,
) -> ParseResult:
    resolved = path.resolve()
    end_bounds = (1, 12, _digest(f"end-{system.value}")) if end is None else end
    return ParseResult(
        source_system=system,
        parser_name="queue-migration-test",
        parser_version="0",
        path=resolved,
        file_digest=_digest("file"),
        file_size=end_bounds[1],
        file_mtime_ns=1,
        conversation_id=f"conversation-{system.value}",
        branch_id=None,
        captured_at=None,
        history_base=None,
        records=(),
        unknown_record_types=(),
        malformed_records=0,
        source_kind=SourceKind.INTERACTIVE,
        segment_start_ordinal=start[0],
        segment_start_byte=start[1],
        segment_end_ordinal_exclusive=end_bounds[0],
        segment_end_byte=end_bounds[1],
        start_prefix_digest=start[2],
        end_prefix_digest=end_bounds[2],
        observed_file_size=end_bounds[1],
    )


def _snapshot(config: CollectorQueueConfig) -> dict[str, list[tuple[object, ...]]]:
    with _connect(config) as connection:
        tables = [
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        ]
        return {
            table: [
                tuple(row)
                for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            ]
            for table in tables
        }


def _schema_objects(config: CollectorQueueConfig) -> list[tuple[object, ...]]:
    with _connect(config) as connection:
        return [
            tuple(row)
            for row in connection.execute(
                """
                SELECT type, name, sql FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            )
        ]


def _user_version(config: CollectorQueueConfig) -> int:
    with _connect(config) as connection:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])


def _assert_current_source_check(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT name, sql FROM sqlite_master
        WHERE name IN ('queue_items', 'source_state')
        ORDER BY name
        """
    ).fetchall()
    assert [row[0] for row in rows] == ["queue_items", "source_state"]
    for _name, sql in rows:
        assert "'grok_bot'" in sql
        assert "'chatgpt_web'" not in sql
        assert "codex" in sql and "claude_code" in sql and "grok_build" in sql


@contextmanager
def _connect(config: CollectorQueueConfig) -> Generator[sqlite3.Connection, None, None]:
    connection = sqlite3.connect(config.root / QUEUE_DATABASE_FILENAME, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
    finally:
        connection.close()


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()
