from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import cast

from cross_assistant_memory.collector import CollectorQueueConfig, InitialSourceCursor
from cross_assistant_memory.models import ParseResult, SourceCursor, SourceKind, SourceSystem
from cross_assistant_memory.tink_crypto import AeadPrimitive, Keyset
from cross_assistant_memory.uploads import UploadBatch, parse_upload_batch, reclassify_upload_batch

QUEUE_SCHEMA_VERSION = 6
QUEUE_PAYLOAD_FORMAT_VERSION = 3
QUEUE_DATABASE_FILENAME = "queue.sqlite3"
QUEUE_SYNC_LOCK_FILENAME = ".sync.lock"
MAX_QUEUE_KEY_BYTES = 4096
MAX_DUE_UPLOADS = 64
MAX_FILE_OBSERVATIONS = 4096
BACKOFF_BASE_SECONDS = 5
BACKOFF_MAX_SECONDS = 15 * 60
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
CURSOR_CHECKPOINT_PAYLOAD = b"cross-agent-memory:cursor-checkpoint:v1"


class QueueItemKind(StrEnum):
    UPLOAD_BATCH = "upload_batch"
    CURSOR_CHECKPOINT = "cursor_checkpoint"
    SCHEMA_HOLD = "schema_hold"


class QueueItemState(StrEnum):
    PENDING = "pending"
    RETRY_WAIT = "retry_wait"
    BLOCKED = "blocked"


class QueueFailureCode(StrEnum):
    NETWORK_UNREACHABLE = "network_unreachable"
    TIMEOUT = "timeout"
    HTTP_RATE_LIMITED = "http_rate_limited"
    HTTP_SERVER_ERROR = "http_server_error"
    HTTP_UNAUTHORIZED = "http_unauthorized"
    HTTP_FORBIDDEN = "http_forbidden"
    HTTP_REJECTED = "http_rejected"
    INVALID_RESPONSE = "invalid_response"
    LOCAL_ERROR = "local_error"
    SOURCE_EXCLUDED = "source_excluded"
    CURSOR_GAP_WORK_LIMIT = "cursor_gap_work_limit"


RETRYABLE_FAILURES = frozenset(
    {
        QueueFailureCode.NETWORK_UNREACHABLE,
        QueueFailureCode.TIMEOUT,
        QueueFailureCode.HTTP_RATE_LIMITED,
        QueueFailureCode.HTTP_SERVER_ERROR,
        QueueFailureCode.CURSOR_GAP_WORK_LIMIT,
    }
)

QUEUE_SCHEMA_V3 = """
CREATE TABLE queue_items (
  item_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('upload_batch', 'cursor_checkpoint', 'schema_hold')),
  state TEXT NOT NULL CHECK (state IN ('pending', 'retry_wait', 'blocked')),
  source_key TEXT NOT NULL CHECK (length(source_key) = 64),
  source_system TEXT NOT NULL CHECK (source_system IN ('codex', 'claude_code', 'grok_build')),
  source_path_hash TEXT NOT NULL CHECK (length(source_path_hash) = 64),
  conversation_id TEXT,
  source_kind TEXT,
  provenance_sha256 TEXT,
  payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
  start_record_ordinal INTEGER NOT NULL CHECK (start_record_ordinal >= 0),
  start_byte_offset INTEGER NOT NULL CHECK (start_byte_offset >= 0),
  end_record_ordinal INTEGER NOT NULL CHECK (end_record_ordinal >= start_record_ordinal),
  end_byte_offset INTEGER NOT NULL CHECK (end_byte_offset >= start_byte_offset),
  start_prefix_sha256 TEXT NOT NULL CHECK (length(start_prefix_sha256) = 64),
  end_prefix_sha256 TEXT NOT NULL CHECK (length(end_prefix_sha256) = 64),
  created_at_epoch INTEGER NOT NULL CHECK (created_at_epoch >= 0),
  expires_at_epoch INTEGER NOT NULL CHECK (expires_at_epoch > created_at_epoch),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at_epoch INTEGER NOT NULL CHECK (next_attempt_at_epoch >= created_at_epoch),
  last_error_code TEXT,
  ciphertext BLOB NOT NULL,
  ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes = length(ciphertext)),
  CHECK (
    (kind IN ('upload_batch', 'cursor_checkpoint') AND conversation_id IS NOT NULL
      AND source_kind IS NOT NULL AND provenance_sha256 IS NOT NULL)
    OR
    (kind = 'schema_hold' AND conversation_id IS NULL
      AND source_kind IS NULL AND provenance_sha256 IS NULL)
  ),
  UNIQUE (
    source_key,
    start_record_ordinal,
    start_byte_offset,
    end_record_ordinal,
    end_byte_offset
  )
);

CREATE INDEX queue_items_due
ON queue_items(state, kind, next_attempt_at_epoch, created_at_epoch);

CREATE INDEX queue_items_source_order
ON queue_items(source_key, start_byte_offset, start_record_ordinal);

CREATE TABLE source_state (
  source_key TEXT PRIMARY KEY CHECK (length(source_key) = 64),
  source_system TEXT NOT NULL CHECK (source_system IN ('codex', 'claude_code', 'grok_build')),
  source_path_hash TEXT NOT NULL CHECK (length(source_path_hash) = 64),
  conversation_id TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  provenance_sha256 TEXT NOT NULL CHECK (length(provenance_sha256) = 64),
  next_record_ordinal INTEGER NOT NULL CHECK (next_record_ordinal >= 0),
  next_byte_offset INTEGER NOT NULL CHECK (next_byte_offset >= 0),
  prefix_sha256 TEXT NOT NULL CHECK (length(prefix_sha256) = 64),
  initialized_at_epoch INTEGER NOT NULL CHECK (initialized_at_epoch >= 0),
  last_success_at_epoch INTEGER
);

CREATE TABLE replay_boundaries (
  source_key TEXT PRIMARY KEY REFERENCES source_state(source_key) ON DELETE CASCADE,
  expected_batch_id TEXT NOT NULL CHECK (length(expected_batch_id) = 70),
  end_record_ordinal INTEGER NOT NULL CHECK (end_record_ordinal >= 0),
  end_byte_offset INTEGER NOT NULL CHECK (end_byte_offset > 0),
  end_prefix_sha256 TEXT NOT NULL CHECK (length(end_prefix_sha256) = 64),
  observed_file_size INTEGER NOT NULL CHECK (observed_file_size >= end_byte_offset),
  file_mtime_ns INTEGER NOT NULL CHECK (file_mtime_ns >= 0),
  expired_at_epoch INTEGER NOT NULL CHECK (expired_at_epoch >= 0)
);
"""

QUEUE_SCAN_SCHEMA = """
CREATE TABLE scan_rotation (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  after_source_key TEXT NOT NULL CHECK (length(after_source_key) = 64)
);
"""
QUEUE_SCHEMA_V4 = QUEUE_SCHEMA_V3 + QUEUE_SCAN_SCHEMA
QUEUE_OBSERVATION_STATEMENTS = (
    "ALTER TABLE scan_rotation ADD COLUMN priority_after_source_key TEXT "
    "CHECK (priority_after_source_key IS NULL OR length(priority_after_source_key) = 64);",
    "ALTER TABLE scan_rotation ADD COLUMN next_priority INTEGER NOT NULL DEFAULT 1 "
    "CHECK (next_priority IN (0, 1));",
    """
    CREATE TABLE file_observations (
      source_key TEXT PRIMARY KEY REFERENCES source_state(source_key) ON DELETE CASCADE,
      file_device INTEGER NOT NULL,
      file_inode INTEGER NOT NULL,
      file_size INTEGER NOT NULL CHECK (file_size >= 0),
      file_mtime_ns INTEGER NOT NULL,
      file_ctime_ns INTEGER NOT NULL,
      end_record_ordinal INTEGER NOT NULL CHECK (end_record_ordinal >= 0),
      end_byte_offset INTEGER NOT NULL CHECK (end_byte_offset BETWEEN 0 AND file_size),
      end_prefix_sha256 TEXT NOT NULL CHECK (length(end_prefix_sha256) = 64),
      complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
      observed_at_epoch INTEGER NOT NULL CHECK (observed_at_epoch >= 0)
    );
    """,
)
QUEUE_SCHEMA_V5 = QUEUE_SCHEMA_V4 + "\n".join(QUEUE_OBSERVATION_STATEMENTS)
QUEUE_SELECTION_SCHEMA = """
CREATE TABLE initial_selections (
  source_key TEXT PRIMARY KEY CHECK (length(source_key) = 64),
  start_record_ordinal INTEGER NOT NULL CHECK (start_record_ordinal > 0),
  start_byte_offset INTEGER NOT NULL CHECK (start_byte_offset >= start_record_ordinal),
  start_prefix_sha256 TEXT NOT NULL CHECK (length(start_prefix_sha256) = 64)
);
"""
QUEUE_SCHEMA = QUEUE_SCHEMA_V5 + QUEUE_SELECTION_SCHEMA


@dataclass(frozen=True)
class FileObservation:
    signature: tuple[int, int, int, int, int]
    end_record_ordinal: int
    end_byte_offset: int
    end_prefix_sha256: str
    complete: bool

    def matches_cursor(self, cursor: SourceCursor | None) -> bool:
        return cursor is not None and (
            cursor.next_record_ordinal,
            cursor.next_byte_offset,
            cursor.prefix_digest,
        ) == (self.end_record_ordinal, self.end_byte_offset, self.end_prefix_sha256)


class QueueCapacityError(RuntimeError):
    pass


class QueueConflictError(RuntimeError):
    pass


@dataclass(frozen=True)
class DueUpload:
    item_id: str
    body: bytes
    attempts: int
    created_at_epoch: int
    expires_at_epoch: int


@dataclass(frozen=True)
class ReplayBoundary:
    expected_batch_id: str
    end_record_ordinal: int
    end_byte_offset: int
    end_prefix_sha256: str
    observed_file_size: int
    file_mtime_ns: int


@dataclass(frozen=True)
class SchemaHold:
    item_id: str
    start_cursor: SourceCursor | InitialSourceCursor | None
    end_record_ordinal: int
    end_byte_offset: int
    end_prefix_sha256: str


@dataclass(frozen=True)
class QueueAttentionItem:
    item_id: str
    source_system: SourceSystem
    source_path_hash: str
    reason: str
    action: str
    last_error_code: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "item_id": self.item_id,
            "source_system": self.source_system.value,
            "source_path_hash": self.source_path_hash,
            "reason": self.reason,
            "action": self.action,
            "last_error_code": self.last_error_code,
        }


@dataclass(frozen=True)
class QueueSourceState:
    source_key: str
    source_system: SourceSystem
    source_path_hash: str
    next_record_ordinal: int
    next_byte_offset: int
    last_success_at_epoch: int | None
    replay_required: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "source_key": self.source_key,
            "source_system": self.source_system.value,
            "source_path_hash": self.source_path_hash,
            "next_record_ordinal": self.next_record_ordinal,
            "next_byte_offset": self.next_byte_offset,
            "last_success_at_epoch": self.last_success_at_epoch,
            "replay_required": self.replay_required,
        }


@dataclass(frozen=True)
class QueueStatus:
    schema_version: int
    queued_items: int
    queued_ciphertext_bytes: int
    max_ciphertext_bytes: int
    oldest_age_seconds: int | None
    schema_holds: int
    blocked_items: int
    retry_wait_items: int
    expired_items: int
    due_uploads: int
    failure_counts: dict[str, int]
    last_success_at_epoch: int | None
    attention_items: tuple[QueueAttentionItem, ...]
    sources: tuple[QueueSourceState, ...]
    initial_selections: dict[str, InitialSourceCursor]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "queued_items": self.queued_items,
            "queued_ciphertext_bytes": self.queued_ciphertext_bytes,
            "max_ciphertext_bytes": self.max_ciphertext_bytes,
            "oldest_age_seconds": self.oldest_age_seconds,
            "schema_holds": self.schema_holds,
            "blocked_items": self.blocked_items,
            "retry_wait_items": self.retry_wait_items,
            "expired_items": self.expired_items,
            "due_uploads": self.due_uploads,
            "failure_counts": self.failure_counts,
            "last_success_at_epoch": self.last_success_at_epoch,
            "attention_items": [item.as_dict() for item in self.attention_items],
            "sources": [source.as_dict() for source in self.sources],
            "initial_selections": {
                key: {
                    "start_record_ordinal": cursor.next_record_ordinal,
                    "start_byte_offset": cursor.next_byte_offset,
                    "start_prefix_sha256": cursor.prefix_digest,
                }
                for key, cursor in self.initial_selections.items()
            },
        }


@dataclass(frozen=True)
class _QueueMetadata:
    item_id: str
    kind: QueueItemKind
    source_key: str
    source_system: SourceSystem
    source_path_hash: str
    conversation_id: str | None
    source_kind: SourceKind | None
    provenance_sha256: str | None
    payload_sha256: str
    start_record_ordinal: int
    start_byte_offset: int
    end_record_ordinal: int
    end_byte_offset: int
    start_prefix_sha256: str
    end_prefix_sha256: str
    created_at_epoch: int
    expires_at_epoch: int


@contextmanager
def exclusive_collector_sync(config: CollectorQueueConfig) -> Generator[None]:
    _validate_config_paths(config)
    _prepare_private_directory(config.root, "collector queue root")
    lock_path = config.root / QUEUE_SYNC_LOCK_FILENAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise ValueError("collector sync lock must be a private regular file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class CollectorQueue:
    def __init__(self, config: CollectorQueueConfig, primitive: AeadPrimitive) -> None:
        self.config = config
        self.root = config.root
        self.key_path = config.key_file
        self.database_path = config.root / QUEUE_DATABASE_FILENAME
        self._primitive = primitive

    @classmethod
    def initialize(cls, config: CollectorQueueConfig) -> CollectorQueue:
        _validate_config_paths(config)
        _prepare_private_directory(config.root, "collector queue root")
        database_path = config.root / QUEUE_DATABASE_FILENAME
        key_exists = config.key_file.exists()
        database_exists = database_path.exists()
        if database_exists and not key_exists:
            raise RuntimeError("collector queue key is missing")
        if not key_exists:
            _prepare_private_directory(config.key_file.parent, "collector queue key directory")
            _write_new_private_file(config.key_file, Keyset.generate_aead().serialize_cleartext())
        if not database_exists:
            _write_new_private_file(database_path, b"")
        queue = cls(config, _load_queue_key(config.key_file).aead())
        queue._initialize_database()
        return queue

    @classmethod
    def open(cls, config: CollectorQueueConfig) -> CollectorQueue:
        _validate_config_paths(config)
        _validate_private_directory(config.root, "collector queue root")
        database_path = config.root / QUEUE_DATABASE_FILENAME
        _validate_private_file(database_path, "collector queue database")
        queue = cls(config, _load_queue_key(config.key_file).aead())
        queue._validate_database()
        return queue

    def scan_after(self, *, priority: bool = False) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT priority_after_source_key, after_source_key "
                "FROM scan_rotation WHERE singleton = 1"
            ).fetchone()
        return None if row is None else cast(str | None, row[0 if priority else 1])

    def next_scan_is_priority(self) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT next_priority FROM scan_rotation WHERE singleton = 1"
            ).fetchone()
        return row is None or bool(row[0])

    def defer_scan_lane(self, *, priority: bool, after_source_key: str | None) -> None:
        if after_source_key is not None:
            _validate_digest(after_source_key, "deferred scan source key")
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE scan_rotation SET
                  after_source_key = CASE WHEN ? THEN after_source_key
                                    ELSE coalesce(?, after_source_key) END,
                  priority_after_source_key = CASE WHEN ? THEN ? ELSE priority_after_source_key END,
                  next_priority = ?
                WHERE singleton = 1
                """,
                (priority, after_source_key, priority, after_source_key, int(priority)),
            )

    def record_scan_attempt(self, source_key: str, *, priority: bool = False) -> None:
        _validate_digest(source_key, "scan source key")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_rotation VALUES (1, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                  after_source_key = CASE WHEN ? THEN scan_rotation.after_source_key
                                    ELSE excluded.after_source_key END,
                  priority_after_source_key = CASE WHEN ? THEN excluded.priority_after_source_key
                                             ELSE scan_rotation.priority_after_source_key END,
                  next_priority = excluded.next_priority
                """,
                (
                    source_key,
                    source_key if priority else None,
                    int(not priority),
                    priority,
                    priority,
                ),
            )

    def file_observations(self) -> dict[str, FileObservation]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM file_observations "
                "ORDER BY observed_at_epoch DESC, source_key LIMIT ?",
                (MAX_FILE_OBSERVATIONS,),
            ).fetchall()
        return {
            _row_str(row, "source_key"): FileObservation(
                signature=(
                    _row_int(row, "file_device"),
                    _row_int(row, "file_inode"),
                    _row_int(row, "file_size"),
                    _row_int(row, "file_mtime_ns"),
                    _row_int(row, "file_ctime_ns"),
                ),
                end_record_ordinal=_row_int(row, "end_record_ordinal"),
                end_byte_offset=_row_int(row, "end_byte_offset"),
                end_prefix_sha256=_row_str(row, "end_prefix_sha256"),
                complete=bool(row["complete"]),
            )
            for row in rows
        }

    def record_file_observation(
        self, source_key: str, observation: FileObservation, *, now_epoch: int
    ) -> None:
        _validate_digest(source_key, "source key")
        _validate_digest(observation.end_prefix_sha256, "observation prefix")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR REPLACE INTO file_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    source_key,
                    *observation.signature,
                    observation.end_record_ordinal,
                    observation.end_byte_offset,
                    observation.end_prefix_sha256,
                    int(observation.complete),
                    _now_epoch(now_epoch),
                ),
            )
            connection.execute(
                "DELETE FROM file_observations WHERE source_key NOT IN "
                "(SELECT source_key FROM file_observations "
                "ORDER BY observed_at_epoch DESC, source_key LIMIT ?)",
                (MAX_FILE_OBSERVATIONS,),
            )
            connection.commit()

    def enqueue_upload(
        self,
        body: bytes,
        *,
        now_epoch: int | None = None,
        revalidated_hold: tuple[str, bytes] | None = None,
        initial_cursor: InitialSourceCursor | None = None,
    ) -> str:
        batch = parse_upload_batch(body)
        metadata = self._upload_metadata(batch, body, now_epoch=now_epoch)
        return self._enqueue(
            metadata, body, revalidated_hold=revalidated_hold, initial_cursor=initial_cursor
        )

    def enqueue_cursor_checkpoint(
        self,
        parsed: ParseResult,
        *,
        source_account_id: str,
        now_epoch: int | None = None,
        revalidated_hold: tuple[str, bytes] | None = None,
    ) -> str:
        if parsed.records or parsed.unknown_record_types or parsed.malformed_records:
            raise ValueError("cursor checkpoint requires a valid non-evidence segment")
        if parsed.segment_end_byte <= parsed.segment_start_byte:
            raise ValueError("cursor checkpoint must advance the source")
        source_path_hash = hashlib.sha256(str(parsed.path).encode()).hexdigest()
        now = _now_epoch(now_epoch)
        metadata = _QueueMetadata(
            item_id=f"queue:{uuid.uuid4().hex}",
            kind=QueueItemKind.CURSOR_CHECKPOINT,
            source_key=source_key_for(
                parsed.source_system,
                source_account_id,
                source_path_hash,
            ),
            source_system=parsed.source_system,
            source_path_hash=source_path_hash,
            conversation_id=parsed.conversation_id,
            source_kind=parsed.source_kind,
            provenance_sha256=_source_provenance_sha256(parsed),
            payload_sha256=hashlib.sha256(CURSOR_CHECKPOINT_PAYLOAD).hexdigest(),
            start_record_ordinal=parsed.segment_start_ordinal,
            start_byte_offset=parsed.segment_start_byte,
            end_record_ordinal=parsed.segment_end_ordinal_exclusive,
            end_byte_offset=parsed.segment_end_byte,
            start_prefix_sha256=parsed.start_prefix_digest,
            end_prefix_sha256=parsed.end_prefix_digest,
            created_at_epoch=now,
            expires_at_epoch=now + self.config.max_age_seconds,
        )
        return self._enqueue(metadata, CURSOR_CHECKPOINT_PAYLOAD, revalidated_hold=revalidated_hold)

    def enqueue_schema_hold(
        self,
        raw_source: bytes,
        *,
        source_system: SourceSystem,
        source_account_id: str,
        source_path_hash: str,
        start_record_ordinal: int,
        start_byte_offset: int,
        end_record_ordinal: int,
        end_byte_offset: int,
        start_prefix_sha256: str,
        end_prefix_sha256: str,
        now_epoch: int | None = None,
        initial_cursor: InitialSourceCursor | None = None,
    ) -> str:
        _validate_native_source(source_system)
        if not raw_source:
            raise ValueError("schema hold payload must not be empty")
        _validate_digest(source_path_hash, "source path hash")
        _validate_digest(start_prefix_sha256, "start prefix digest")
        _validate_digest(end_prefix_sha256, "end prefix digest")
        _validate_segment(
            start_record_ordinal,
            start_byte_offset,
            end_record_ordinal,
            end_byte_offset,
        )
        now = _now_epoch(now_epoch)
        metadata = _QueueMetadata(
            item_id=f"queue:{uuid.uuid4().hex}",
            kind=QueueItemKind.SCHEMA_HOLD,
            source_key=source_key_for(source_system, source_account_id, source_path_hash),
            source_system=source_system,
            source_path_hash=source_path_hash,
            conversation_id=None,
            source_kind=None,
            provenance_sha256=None,
            payload_sha256=hashlib.sha256(raw_source).hexdigest(),
            start_record_ordinal=start_record_ordinal,
            start_byte_offset=start_byte_offset,
            end_record_ordinal=end_record_ordinal,
            end_byte_offset=end_byte_offset,
            start_prefix_sha256=start_prefix_sha256,
            end_prefix_sha256=end_prefix_sha256,
            created_at_epoch=now,
            expires_at_epoch=now + self.config.max_age_seconds,
        )
        return self._enqueue(metadata, raw_source, initial_cursor=initial_cursor)

    def replace_cursor_checkpoint(
        self,
        item_id: str,
        body: bytes,
        *,
        now_epoch: int | None = None,
    ) -> str:
        """Replace an exact legacy boundary without acknowledging it or rewriting successors.

        The caller revalidates the source range before building the empty upload. Retained
        ciphertext authenticates its bound identity and boundaries, including after expiry.
        Exact retries preserve the same item ID, ciphertext, lifetime and transport state.
        """
        batch = parse_upload_batch(body)
        if batch.parsed.records or batch.exclusion_receipts:
            raise ValueError("cursor checkpoint replacement requires an empty upload")
        metadata = replace(self._upload_metadata(batch, body, now_epoch=now_epoch), item_id=item_id)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM queue_items WHERE item_id = ?", (item_id,)
            ).fetchone()
            if row is None:
                raise KeyError("collector queue item not found")
            held = _metadata_from_row(row)
            if held.kind is QueueItemKind.UPLOAD_BATCH:
                retained_body = self._decrypt_payload(held, _row_bytes(row, "ciphertext"))
                self._verify_batch_matches_metadata(
                    parse_upload_batch(retained_body), retained_body, held
                )
                if _payload_identity(held) != _payload_identity(metadata):
                    raise QueueConflictError(
                        "cursor checkpoint replacement conflicts with retained upload"
                    )
                self._verify_source_identity(
                    held, self._source_state_row(connection, held.source_key)
                )
                connection.commit()
                return item_id
            self._verify_cursor_checkpoint(connection, row)
            expected = replace(
                metadata,
                kind=QueueItemKind.CURSOR_CHECKPOINT,
                payload_sha256=hashlib.sha256(CURSOR_CHECKPOINT_PAYLOAD).hexdigest(),
            )
            if _payload_identity(held) != _payload_identity(expected):
                raise QueueConflictError(
                    "cursor checkpoint replacement does not match retained boundary"
                )
            ciphertext = self._primitive.encrypt(body, _associated_data(metadata))
            queued_bytes = cast(
                int,
                connection.execute(
                    "SELECT COALESCE(SUM(length(ciphertext)), 0) FROM queue_items"
                ).fetchone()[0],
            )
            if (
                queued_bytes - _row_int(row, "ciphertext_bytes") + len(ciphertext)
                > self.config.max_bytes
            ):
                raise QueueCapacityError("collector queue is at its byte limit")
            # In-place replacement bypasses append-only admission only for this authenticated range.
            connection.execute(
                """
                UPDATE queue_items
                SET kind = ?, state = ?, payload_sha256 = ?, created_at_epoch = ?,
                    expires_at_epoch = ?, next_attempt_at_epoch = ?, attempts = 0,
                    last_error_code = NULL, ciphertext = ?, ciphertext_bytes = ?
                WHERE item_id = ?
                """,
                (
                    metadata.kind.value,
                    QueueItemState.PENDING.value,
                    metadata.payload_sha256,
                    metadata.created_at_epoch,
                    metadata.expires_at_epoch,
                    metadata.created_at_epoch,
                    ciphertext,
                    len(ciphertext),
                    item_id,
                ),
            )
            connection.commit()
        return item_id

    def replace_unsent_claude_fork_prefix(
        self, item_id: str, body: bytes, *, expected_payload_sha256: str
    ) -> str:
        return self.replace_unsent_claude_fork_prefixes(
            ((item_id, body, expected_payload_sha256),)
        )[0]

    def replace_unsent_claude_fork_prefixes(
        self, replacements: tuple[tuple[str, bytes, str], ...]
    ) -> tuple[str, ...]:
        """Atomically repair the complete initial chain of 0.4.0 copied-parent prefixes.

        Maintenance callers must stop collection, hold exclusive_collector_sync, retain an
        encrypted queue backup, and independently verify that the node has no receipt or
        stream for this source. Zero local attempts alone cannot prove remote absence.
        Each tuple supplies an item ID, replacement envelope, and expected old payload hash.
        Only untouched uploads or single operator LOCAL_ERROR holds qualify. Holds remain
        held; this never advances a cursor, retries work, or repairs acknowledged history.
        """
        item_ids = tuple(item_id for item_id, _body, _sha in replacements)
        if not 1 <= len(item_ids) <= MAX_DUE_UPLOADS or len(set(item_ids)) != len(item_ids):
            raise QueueConflictError("fork repair requires a bounded unique prefix chain")
        batches: list[UploadBatch] = []
        for _item_id, body, expected_payload_sha256 in replacements:
            _validate_digest(expected_payload_sha256, "expected payload digest")
            batch = parse_upload_batch(body)
            parsed = batch.parsed
            if (
                parsed.source_system is not SourceSystem.CLAUDE_CODE
                or parsed.parser_version not in {"0.4.1", "0.4.2"}
                or parsed.source_kind is not SourceKind.INTERACTIVE
                or not parsed.parent_conversation_id
                or parsed.branch_id != parsed.conversation_id
                or parsed.records
                or batch.exclusion_receipts
            ):
                raise QueueConflictError("fork repair requires a verified empty Claude prefix")
            batches.append(batch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM queue_items WHERE item_id = ?", (item_ids[0],)
            ).fetchone()
            if row is None:
                raise KeyError("collector queue item not found")
            first = _metadata_from_row(row)
            _require_initial_cursor(first)
            state = self._source_state_row(connection, first.source_key)
            self._verify_source_state(first, state)
            rows = connection.execute(
                "SELECT * FROM queue_items WHERE source_key = ? ORDER BY start_byte_offset",
                (first.source_key,),
            ).fetchall()
            if (
                state is None
                or state["last_success_at_epoch"] is not None
                or tuple(_row_str(item, "item_id") for item in rows) != item_ids
                or connection.execute(
                    "SELECT 1 FROM replay_boundaries WHERE source_key = ?", (first.source_key,)
                ).fetchone()
                is not None
            ):
                raise QueueConflictError("fork repair requires the complete unacknowledged chain")
            updates: list[tuple[_QueueMetadata, bytes, int]] = []
            exact_replays = 0
            boundary = (0, 0, EMPTY_SHA256)
            new_identity: tuple[object, ...] | None = None
            for row, (item_id, body, expected_payload_sha256), batch in zip(
                rows, replacements, batches, strict=True
            ):
                held = _metadata_from_row(row)
                self._verify_source_identity(held, state)
                untouched = (
                    _row_int(row, "attempts") == 0
                    and _row_str(row, "state") == QueueItemState.PENDING.value
                    and row["last_error_code"] is None
                )
                operator_hold = (
                    _row_int(row, "attempts") == 1
                    and _row_str(row, "state") == QueueItemState.BLOCKED.value
                    and row["last_error_code"] == QueueFailureCode.LOCAL_ERROR.value
                )
                if (
                    held.kind is not QueueItemKind.UPLOAD_BATCH
                    or not (untouched or operator_hold)
                    or (held.start_record_ordinal, held.start_byte_offset, held.start_prefix_sha256)
                    != boundary
                ):
                    raise QueueConflictError("fork repair requires contiguous unsent prefixes")
                boundary = (
                    held.end_record_ordinal,
                    held.end_byte_offset,
                    held.end_prefix_sha256,
                )
                metadata = replace(
                    self._upload_metadata(batch, body, now_epoch=held.created_at_epoch),
                    item_id=item_id,
                    expires_at_epoch=held.expires_at_epoch,
                )
                parsed = batch.parsed
                identity = (
                    metadata.source_key,
                    metadata.conversation_id,
                    metadata.source_kind,
                    metadata.provenance_sha256,
                    parsed.file_mtime_ns,
                    parsed.observed_file_size,
                )
                if new_identity is not None and identity != new_identity:
                    raise QueueConflictError("fork repair replacement identities differ")
                new_identity = identity
                retained_body = self._decrypt_payload(held, _row_bytes(row, "ciphertext"))
                retained = parse_upload_batch(retained_body)
                self._verify_batch_matches_metadata(retained, retained_body, held)
                if _payload_identity(held) == _payload_identity(metadata):
                    exact_replays += 1
                    continue
                old = retained.parsed
                expected = replace(
                    metadata,
                    conversation_id=held.conversation_id,
                    provenance_sha256=held.provenance_sha256,
                    payload_sha256=expected_payload_sha256,
                )
                if (
                    _payload_identity(expected) != _payload_identity(held)
                    or old.parser_version != "0.4.0"
                    or not old.records
                    or old.parent_conversation_id is not None
                    or parsed.parent_conversation_id != old.conversation_id
                    or parsed.conversation_id == old.conversation_id
                    or batch.provenance != retained.provenance
                    or parsed.file_mtime_ns != old.file_mtime_ns
                    or parsed.observed_file_size != old.observed_file_size
                ):
                    raise QueueConflictError("fork repair differs from the retained prefix")
                ciphertext = self._primitive.encrypt(body, _associated_data(metadata))
                updates.append((metadata, ciphertext, _row_int(row, "ciphertext_bytes")))
            if exact_replays == len(replacements):
                connection.commit()
                return item_ids
            if exact_replays:
                raise QueueConflictError("fork repair refuses a partially replaced chain")
            queued_bytes = connection.execute(
                "SELECT COALESCE(SUM(length(ciphertext)), 0) FROM queue_items"
            ).fetchone()[0]
            if (
                queued_bytes
                + sum(len(ciphertext) - old_bytes for _, ciphertext, old_bytes in updates)
                > self.config.max_bytes
            ):
                raise QueueCapacityError("collector queue is at its byte limit")
            for metadata, ciphertext, _old_bytes in updates:
                connection.execute(
                    """UPDATE queue_items SET conversation_id = ?, provenance_sha256 = ?,
                   payload_sha256 = ?, ciphertext = ?, ciphertext_bytes = ? WHERE item_id = ?""",
                    (
                        metadata.conversation_id,
                        metadata.provenance_sha256,
                        metadata.payload_sha256,
                        ciphertext,
                        len(ciphertext),
                        metadata.item_id,
                    ),
                )
            metadata = updates[0][0]
            connection.execute(
                """UPDATE source_state SET conversation_id = ?, provenance_sha256 = ?
                   WHERE source_key = ?""",
                (metadata.conversation_id, metadata.provenance_sha256, metadata.source_key),
            )
            connection.execute(
                "DELETE FROM file_observations WHERE source_key = ?", (metadata.source_key,)
            )
            connection.commit()
        return item_ids

    def replace_unsent_admission_batch(
        self, item_id: str, body: bytes, *, expected_payload_sha256: str
    ) -> str:
        """Repair admission only, preserving identity, bounds, lifetime, hold and cursor.

        Maintenance callers stop collection, hold exclusive_collector_sync, back up the
        encrypted queue, reverify the source prefix, and independently establish no node
        receipt/stream for this source. Only its initial untouched/operator-held batch
        qualifies. This operation neither retries work nor acknowledges or repairs history.
        """
        _validate_digest(expected_payload_sha256, "expected payload digest")
        batch = parse_upload_batch(body)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM queue_items WHERE item_id = ?", (item_id,)
            ).fetchone()
            if row is None:
                raise KeyError("collector queue item not found")
            held = _metadata_from_row(row)
            _require_initial_cursor(held)
            state = self._source_state_row(connection, held.source_key)
            self._verify_source_state(held, state)
            untouched = (
                _row_int(row, "attempts") == 0
                and row["state"] == QueueItemState.PENDING.value
                and row["last_error_code"] is None
            )
            operator_hold = (
                _row_int(row, "attempts") == 1
                and row["state"] == QueueItemState.BLOCKED.value
                and row["last_error_code"] == QueueFailureCode.LOCAL_ERROR.value
            )
            if (
                held.kind is not QueueItemKind.UPLOAD_BATCH
                or not (untouched or operator_hold)
                or state is None
                or state["last_success_at_epoch"] is not None
                or connection.execute(
                    "SELECT 1 FROM replay_boundaries WHERE source_key = ?", (held.source_key,)
                ).fetchone()
                is not None
            ):
                raise QueueConflictError("admission repair requires an unsent initial batch")
            retained = self._decrypt_payload(held, _row_bytes(row, "ciphertext"))
            if hashlib.sha256(retained).hexdigest() != held.payload_sha256:
                raise QueueConflictError("retained admission payload digest changed")
            metadata = replace(held, payload_sha256=hashlib.sha256(body).hexdigest())
            self._verify_batch_matches_metadata(batch, body, metadata)
            if retained == body:
                connection.commit()
                return item_id
            if (
                held.payload_sha256 != expected_payload_sha256
                or reclassify_upload_batch(retained) != body
            ):
                raise QueueConflictError("admission repair differs from retained evidence")
            ciphertext = self._primitive.encrypt(body, _associated_data(metadata))
            queued_bytes = connection.execute(
                "SELECT COALESCE(SUM(length(ciphertext)), 0) FROM queue_items"
            ).fetchone()[0]
            if (
                queued_bytes - _row_int(row, "ciphertext_bytes") + len(ciphertext)
                > self.config.max_bytes
            ):
                raise QueueCapacityError("collector queue is at its byte limit")
            connection.execute(
                "UPDATE queue_items SET payload_sha256 = ?, ciphertext = ?, ciphertext_bytes = ? "
                "WHERE item_id = ?",
                (metadata.payload_sha256, ciphertext, len(ciphertext), item_id),
            )
            connection.commit()
        return item_id

    def due_uploads(
        self,
        *,
        now_epoch: int | None = None,
        limit: int = MAX_DUE_UPLOADS,
    ) -> tuple[DueUpload, ...]:
        if limit <= 0 or limit > MAX_DUE_UPLOADS:
            raise ValueError("due upload limit is invalid")
        now = _now_epoch(now_epoch)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT item.*
                FROM queue_items AS item
                JOIN source_state AS source ON source.source_key = item.source_key
                WHERE item.kind = '{QueueItemKind.UPLOAD_BATCH.value}'
                  AND item.state IN ('{QueueItemState.PENDING.value}',
                                     '{QueueItemState.RETRY_WAIT.value}')
                  AND item.next_attempt_at_epoch <= ?
                  AND item.expires_at_epoch > ?
                  AND item.start_record_ordinal = source.next_record_ordinal
                  AND item.start_byte_offset = source.next_byte_offset
                  AND item.start_prefix_sha256 = source.prefix_sha256
                  AND item.conversation_id = source.conversation_id
                  AND item.source_kind = source.source_kind
                  AND item.provenance_sha256 = source.provenance_sha256
                  AND NOT EXISTS (
                    SELECT 1 FROM queue_items AS blocker
                    WHERE blocker.source_key = item.source_key
                      AND blocker.kind = '{QueueItemKind.SCHEMA_HOLD.value}'
                      AND blocker.start_byte_offset <= item.start_byte_offset
                  )
                ORDER BY item.created_at_epoch, item.item_id
                LIMIT ?
                """,
                (now, now, limit),
            ).fetchall()
        uploads: list[DueUpload] = []
        for row in rows:
            typed_row = cast(sqlite3.Row, row)
            metadata = _metadata_from_row(typed_row)
            body = self._decrypt_payload(metadata, _row_bytes(typed_row, "ciphertext"))
            self._verify_batch_matches_metadata(parse_upload_batch(body), body, metadata)
            uploads.append(
                DueUpload(
                    item_id=metadata.item_id,
                    body=body,
                    attempts=_row_int(typed_row, "attempts"),
                    created_at_epoch=metadata.created_at_epoch,
                    expires_at_epoch=metadata.expires_at_epoch,
                )
            )
        return tuple(uploads)

    def mark_failure(
        self,
        item_id: str,
        error_code: QueueFailureCode,
        *,
        now_epoch: int | None = None,
    ) -> int | None:
        now = _now_epoch(now_epoch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT kind, state, attempts FROM queue_items WHERE item_id = ?",
                (item_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError("collector queue item not found")
            if cast(str, row[0]) != QueueItemKind.UPLOAD_BATCH.value:
                connection.rollback()
                raise ValueError("only upload batches can record transport failures")
            if cast(str, row[1]) == QueueItemState.BLOCKED.value:
                connection.rollback()
                raise ValueError("blocked queue item requires an explicit retry")
            attempts = cast(int, row[2]) + 1
            if error_code in RETRYABLE_FAILURES:
                delay = min(
                    BACKOFF_MAX_SECONDS,
                    BACKOFF_BASE_SECONDS * 2 ** min(attempts - 1, 16),
                )
                next_attempt: int | None = now + delay
                state = QueueItemState.RETRY_WAIT
            else:
                next_attempt = None
                state = QueueItemState.BLOCKED
            connection.execute(
                """
                UPDATE queue_items
                SET state = ?, attempts = ?, next_attempt_at_epoch = ?, last_error_code = ?
                WHERE item_id = ?
                """,
                (
                    state.value,
                    attempts,
                    now if next_attempt is None else next_attempt,
                    error_code.value,
                    item_id,
                ),
            )
            connection.commit()
        return next_attempt

    def advance_ready_checkpoints(
        self,
        *,
        now_epoch: int | None = None,
        limit: int = MAX_DUE_UPLOADS,
    ) -> int:
        """Compatibility no-op: only an acknowledged ordinary upload may advance a cursor."""
        if limit <= 0 or limit > MAX_DUE_UPLOADS:
            raise ValueError("cursor checkpoint limit is invalid")
        _now_epoch(now_epoch)
        return 0

    def retry_blocked(self, item_id: str, *, now_epoch: int | None = None) -> None:
        now = _now_epoch(now_epoch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """
                UPDATE queue_items
                SET state = ?, next_attempt_at_epoch = ?, last_error_code = NULL
                WHERE item_id = ? AND kind = ? AND state = ?
                """,
                (
                    QueueItemState.PENDING.value,
                    now,
                    item_id,
                    QueueItemKind.UPLOAD_BATCH.value,
                    QueueItemState.BLOCKED.value,
                ),
            ).rowcount
            if changed != 1:
                connection.rollback()
                raise ValueError("collector queue item is not blocked")
            connection.commit()

    def mark_success(self, item_id: str, *, now_epoch: int | None = None) -> SourceCursor:
        now = _now_epoch(now_epoch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM queue_items WHERE item_id = ?",
                (item_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError("collector queue item not found")
            typed_row = cast(sqlite3.Row, row)
            metadata = _metadata_from_row(typed_row)
            if (
                metadata.kind is not QueueItemKind.UPLOAD_BATCH
                or _row_str(typed_row, "state") == QueueItemState.BLOCKED.value
            ):
                connection.rollback()
                raise ValueError("queue item cannot be marked successful")
            state = self._source_state_row(connection, metadata.source_key)
            self._verify_source_state(metadata, state)
            blocker = connection.execute(
                """
                SELECT 1 FROM queue_items
                WHERE source_key = ? AND kind = ? AND start_byte_offset <= ?
                LIMIT 1
                """,
                (
                    metadata.source_key,
                    QueueItemKind.SCHEMA_HOLD.value,
                    metadata.start_byte_offset,
                ),
            ).fetchone()
            if blocker is not None:
                connection.rollback()
                raise QueueConflictError("collector queue source is blocked by a schema hold")
            body = self._decrypt_payload(metadata, _row_bytes(typed_row, "ciphertext"))
            batch = parse_upload_batch(body)
            self._verify_batch_matches_metadata(batch, body, metadata)
            replay = connection.execute(
                """
                SELECT expected_batch_id, end_record_ordinal, end_byte_offset,
                       end_prefix_sha256, observed_file_size, file_mtime_ns
                FROM replay_boundaries WHERE source_key = ?
                """,
                (metadata.source_key,),
            ).fetchone()
            if replay is not None:
                if (
                    cast(str, replay[0]),
                    cast(int, replay[1]),
                    cast(int, replay[2]),
                    cast(str, replay[3]),
                ) != (
                    batch.batch_id,
                    metadata.end_record_ordinal,
                    metadata.end_byte_offset,
                    metadata.end_prefix_sha256,
                ):
                    connection.rollback()
                    raise QueueConflictError("collector replay boundary does not match the batch")
                connection.execute(
                    "DELETE FROM replay_boundaries WHERE source_key = ?",
                    (metadata.source_key,),
                )
            connection.execute("DELETE FROM queue_items WHERE item_id = ?", (item_id,))
            connection.execute(
                """
                UPDATE source_state
                SET next_record_ordinal = ?, next_byte_offset = ?, prefix_sha256 = ?,
                    last_success_at_epoch = ?
                WHERE source_key = ?
                """,
                (
                    metadata.end_record_ordinal,
                    metadata.end_byte_offset,
                    metadata.end_prefix_sha256,
                    now,
                    metadata.source_key,
                ),
            )
            connection.commit()
        return SourceCursor(
            source_stream_id=metadata.source_key,
            conversation_id=cast(str, metadata.conversation_id),
            source_kind=cast(SourceKind, metadata.source_kind),
            next_record_ordinal=metadata.end_record_ordinal,
            next_byte_offset=metadata.end_byte_offset,
            prefix_digest=metadata.end_prefix_sha256,
        )

    def cursor(self, source_key: str) -> SourceCursor | None:
        _validate_digest(source_key, "source key")
        with self._connect() as connection:
            row = self._source_state_row(connection, source_key)
        if row is None:
            return None
        return SourceCursor(
            source_stream_id=source_key,
            conversation_id=_row_str(row, "conversation_id"),
            source_kind=SourceKind(_row_str(row, "source_kind")),
            next_record_ordinal=_row_int(row, "next_record_ordinal"),
            next_byte_offset=_row_int(row, "next_byte_offset"),
            prefix_digest=_row_str(row, "prefix_sha256"),
        )

    def validate_initial_cursor(
        self, source_key: str, configured: InitialSourceCursor | None
    ) -> None:
        """Refuse a changed selection, including removal, without changing queue state."""
        _validate_digest(source_key, "source key")
        with self._connect() as connection:
            self._validate_initial_selection(connection, source_key, configured)

    def _initial_selection(
        self, connection: sqlite3.Connection, source_key: str
    ) -> InitialSourceCursor | None:
        version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
        if version < 6:
            return None
        row = connection.execute(
            "SELECT * FROM initial_selections WHERE source_key = ?", (source_key,)
        ).fetchone()
        return None if row is None else _initial_cursor_from_row(row)

    def _validate_initial_selection(
        self,
        connection: sqlite3.Connection,
        source_key: str,
        configured: InitialSourceCursor | None,
    ) -> None:
        retained = self._initial_selection(connection, source_key)
        if retained is not None:
            if configured != retained:
                raise QueueConflictError("collector initial selection changed or was removed")
        elif configured is not None and (
            self._source_state_row(connection, source_key) is not None
            or connection.execute(
                "SELECT 1 FROM queue_items WHERE source_key = ? LIMIT 1", (source_key,)
            ).fetchone()
            is not None
        ):
            raise QueueConflictError("collector initial selection requires an uninitialized source")

    def scan_cursor(self, source_key: str) -> SourceCursor | None:
        _validate_digest(source_key, "source key")
        with self._connect() as connection:
            blocker = connection.execute(
                "SELECT kind FROM queue_items WHERE source_key = ? AND kind IN (?, ?) LIMIT 1",
                (
                    source_key,
                    QueueItemKind.CURSOR_CHECKPOINT.value,
                    QueueItemKind.SCHEMA_HOLD.value,
                ),
            ).fetchone()
            if blocker is not None:
                kind = QueueItemKind(cast(str, blocker[0]))
                label = (
                    "cursor checkpoint"
                    if kind is QueueItemKind.CURSOR_CHECKPOINT
                    else "schema hold"
                )
                raise QueueConflictError(f"collector queue source is blocked by a {label}")
            latest = connection.execute(
                """
                SELECT kind, conversation_id, source_kind, end_record_ordinal,
                       end_byte_offset, end_prefix_sha256
                FROM queue_items WHERE source_key = ?
                ORDER BY end_byte_offset DESC, end_record_ordinal DESC LIMIT 1
                """,
                (source_key,),
            ).fetchone()
            if latest is not None:
                conversation_id = cast(str | None, latest[1])
                source_kind = cast(str | None, latest[2])
                if conversation_id is None or source_kind is None:
                    raise RuntimeError("collector queue upload identity is missing")
                return SourceCursor(
                    source_stream_id=source_key,
                    conversation_id=conversation_id,
                    source_kind=SourceKind(source_kind),
                    next_record_ordinal=cast(int, latest[3]),
                    next_byte_offset=cast(int, latest[4]),
                    prefix_digest=cast(str, latest[5]),
                )
            row = self._source_state_row(connection, source_key)
        if row is None:
            return None
        return SourceCursor(
            source_stream_id=source_key,
            conversation_id=_row_str(row, "conversation_id"),
            source_kind=SourceKind(_row_str(row, "source_kind")),
            next_record_ordinal=_row_int(row, "next_record_ordinal"),
            next_byte_offset=_row_int(row, "next_byte_offset"),
            prefix_digest=_row_str(row, "prefix_sha256"),
        )

    def schema_hold(self, source_key: str) -> SchemaHold | None:
        return self._retained_boundary(source_key, QueueItemKind.SCHEMA_HOLD)

    def cursor_checkpoint(self, source_key: str) -> SchemaHold | None:
        """Return the earliest authenticated legacy checkpoint in the schema-hold shape."""
        return self._retained_boundary(source_key, QueueItemKind.CURSOR_CHECKPOINT)

    def _retained_boundary(self, source_key: str, kind: QueueItemKind) -> SchemaHold | None:
        _validate_digest(source_key, "source key")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM queue_items WHERE source_key = ? AND kind = ? "
                "ORDER BY start_byte_offset, start_record_ordinal LIMIT 1",
                (source_key, kind.value),
            ).fetchone()
            if row is None:
                return None
            metadata = _metadata_from_row(row)
            if kind is QueueItemKind.CURSOR_CHECKPOINT:
                self._verify_cursor_checkpoint(connection, row)
            state = self._source_state_row(connection, source_key)
            selected = self._initial_selection(connection, source_key)
        cursor: SourceCursor | InitialSourceCursor | None
        if metadata.start_byte_offset == 0:
            _require_initial_cursor(metadata)
            cursor = None
        elif state is not None:
            cursor = SourceCursor(
                source_stream_id=source_key,
                conversation_id=_row_str(state, "conversation_id"),
                source_kind=SourceKind(_row_str(state, "source_kind")),
                next_record_ordinal=metadata.start_record_ordinal,
                next_byte_offset=metadata.start_byte_offset,
                prefix_digest=metadata.start_prefix_sha256,
            )
        elif selected is not None and (
            metadata.start_record_ordinal,
            metadata.start_byte_offset,
            metadata.start_prefix_sha256,
        ) == (
            selected.next_record_ordinal,
            selected.next_byte_offset,
            selected.prefix_digest,
        ):
            cursor = selected
        else:
            raise QueueConflictError("schema hold is missing its preceding source identity")
        return SchemaHold(
            metadata.item_id,
            cursor,
            metadata.end_record_ordinal,
            metadata.end_byte_offset,
            metadata.end_prefix_sha256,
        )

    def replay_boundary(self, source_key: str) -> ReplayBoundary | None:
        _validate_digest(source_key, "source key")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT expected_batch_id, end_record_ordinal, end_byte_offset,
                       end_prefix_sha256, observed_file_size, file_mtime_ns
                FROM replay_boundaries WHERE source_key = ?
                """,
                (source_key,),
            ).fetchone()
        if row is None:
            return None
        return ReplayBoundary(
            expected_batch_id=cast(str, row[0]),
            end_record_ordinal=cast(int, row[1]),
            end_byte_offset=cast(int, row[2]),
            end_prefix_sha256=cast(str, row[3]),
            observed_file_size=cast(int, row[4]),
            file_mtime_ns=cast(int, row[5]),
        )

    def queued_replay_matches(self, source_key: str, replay: ReplayBoundary) -> bool:
        """Authenticate the reconstructed head without clearing its acknowledgement gate."""
        _validate_digest(source_key, "source key")
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT * FROM queue_items WHERE source_key = ? "
                "ORDER BY start_byte_offset, start_record_ordinal LIMIT 1",
                (source_key,),
            ).fetchone()
            if row is None:
                return False
            metadata = _metadata_from_row(row)
            if metadata.kind is not QueueItemKind.UPLOAD_BATCH:
                raise QueueConflictError("collector replay head is not an upload")
            self._verify_source_state(metadata, self._source_state_row(connection, source_key))
            body = self._decrypt_payload(metadata, _row_bytes(row, "ciphertext"))
            batch = parse_upload_batch(body)
            self._verify_batch_matches_metadata(batch, body, metadata)
            if (
                batch.batch_id,
                metadata.end_record_ordinal,
                metadata.end_byte_offset,
                metadata.end_prefix_sha256,
                batch.parsed.observed_file_size,
                batch.parsed.file_mtime_ns,
            ) != (
                replay.expected_batch_id,
                replay.end_record_ordinal,
                replay.end_byte_offset,
                replay.end_prefix_sha256,
                replay.observed_file_size,
                replay.file_mtime_ns,
            ):
                raise QueueConflictError("queued upload differs from its expired replay boundary")
        return True

    def expire(self, *, now_epoch: int | None = None) -> int:
        """Expire ordinary work without dropping or acknowledging legacy checkpoints.

        A source with retained checkpoints keeps its entire chain, still bounded by max_bytes,
        even past max_age_seconds. This preserves successors and preceding replay inputs until
        exact checkpoint replacement; ordinary age-based expiry then resumes. Expired retained
        items remain visible in status and are never due for upload.
        """
        now = _now_epoch(now_epoch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            deleted = self._expire_with_connection(connection, now)
            connection.commit()
        return deleted

    def status(self, *, now_epoch: int | None = None) -> QueueStatus:
        now = _now_epoch(now_epoch)
        with self._connect() as connection:
            schema_version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
            totals = connection.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(length(ciphertext)), 0), MIN(created_at_epoch),
                       COALESCE(SUM(CASE WHEN kind = ? THEN 1 ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN state = ? THEN 1 ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN state = ? THEN 1 ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN expires_at_epoch <= ? THEN 1 ELSE 0 END), 0)
                FROM queue_items
                """,
                (
                    QueueItemKind.SCHEMA_HOLD.value,
                    QueueItemState.BLOCKED.value,
                    QueueItemState.RETRY_WAIT.value,
                    now,
                ),
            ).fetchone()
            due = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM queue_items AS item
                JOIN source_state AS source ON source.source_key = item.source_key
                WHERE item.kind = '{QueueItemKind.UPLOAD_BATCH.value}'
                  AND item.state IN ('{QueueItemState.PENDING.value}',
                                     '{QueueItemState.RETRY_WAIT.value}')
                  AND item.next_attempt_at_epoch <= ? AND item.expires_at_epoch > ?
                  AND item.start_record_ordinal = source.next_record_ordinal
                  AND item.start_byte_offset = source.next_byte_offset
                  AND item.start_prefix_sha256 = source.prefix_sha256
                  AND item.conversation_id = source.conversation_id
                  AND item.source_kind = source.source_kind
                  AND item.provenance_sha256 = source.provenance_sha256
                  AND NOT EXISTS (
                    SELECT 1 FROM queue_items AS blocker
                    WHERE blocker.source_key = item.source_key
                      AND blocker.kind = '{QueueItemKind.SCHEMA_HOLD.value}'
                      AND blocker.start_byte_offset <= item.start_byte_offset
                  )
                """,
                (now, now),
            ).fetchone()
            last_success = connection.execute(
                "SELECT MAX(last_success_at_epoch) FROM source_state"
            ).fetchone()
            failures = connection.execute(
                """
                SELECT last_error_code, COUNT(*) FROM queue_items
                WHERE last_error_code IS NOT NULL
                GROUP BY last_error_code ORDER BY last_error_code
                """
            ).fetchall()
            attention_rows = connection.execute(
                """
                SELECT item_id, kind, state, source_system, source_path_hash,
                       last_error_code, expires_at_epoch
                FROM queue_items
                WHERE kind = ? OR state = ? OR expires_at_epoch <= ?
                ORDER BY created_at_epoch, item_id
                """,
                (
                    QueueItemKind.SCHEMA_HOLD.value,
                    QueueItemState.BLOCKED.value,
                    now,
                ),
            ).fetchall()
            source_rows = connection.execute(
                """
                SELECT source.source_key, source.source_system, source.source_path_hash,
                       source.next_record_ordinal, source.next_byte_offset,
                       source.last_success_at_epoch,
                       replay.source_key IS NOT NULL AS replay_required
                FROM source_state AS source
                LEFT JOIN replay_boundaries AS replay ON replay.source_key = source.source_key
                ORDER BY source.source_system, source.source_path_hash
                """
            ).fetchall()
            selections = (
                {
                    _row_str(row, "source_key"): _initial_cursor_from_row(row)
                    for row in connection.execute("SELECT * FROM initial_selections")
                }
                if schema_version >= 6
                else {}
            )
        if totals is None or due is None or last_success is None:
            raise RuntimeError("collector queue status metadata is missing")
        oldest = cast(int | None, totals[2])
        return QueueStatus(
            schema_version=schema_version,
            queued_items=cast(int, totals[0]),
            queued_ciphertext_bytes=cast(int, totals[1]),
            max_ciphertext_bytes=self.config.max_bytes,
            oldest_age_seconds=None if oldest is None else max(0, now - oldest),
            schema_holds=cast(int, totals[3]),
            blocked_items=cast(int, totals[4]),
            retry_wait_items=cast(int, totals[5]),
            expired_items=cast(int, totals[6]),
            due_uploads=cast(int, due[0]),
            failure_counts={cast(str, row[0]): cast(int, row[1]) for row in failures},
            last_success_at_epoch=cast(int | None, last_success[0]),
            attention_items=tuple(_attention_item(row, now=now) for row in attention_rows),
            sources=tuple(_source_status(row) for row in source_rows),
            initial_selections=selections,
        )

    def _enqueue(
        self,
        metadata: _QueueMetadata,
        plaintext: bytes,
        *,
        revalidated_hold: tuple[str, bytes] | None = None,
        initial_cursor: InitialSourceCursor | None = None,
    ) -> str:
        ciphertext = self._primitive.encrypt(plaintext, _associated_data(metadata))
        if len(ciphertext) > self.config.max_bytes:
            raise QueueCapacityError("collector queue payload exceeds its byte limit")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_initial_selection(connection, metadata.source_key, initial_cursor)
            if (
                initial_cursor is not None
                and self._initial_selection(connection, metadata.source_key) is None
            ):
                if metadata.source_system is not SourceSystem.CODEX:
                    raise QueueConflictError("collector initial selection supports Codex only")
                _require_initial_cursor(metadata, initial_cursor)
                connection.execute(
                    "INSERT INTO initial_selections VALUES (?, ?, ?, ?)",
                    (
                        metadata.source_key,
                        initial_cursor.next_record_ordinal,
                        initial_cursor.next_byte_offset,
                        initial_cursor.prefix_digest,
                    ),
                )
            self._expire_with_connection(connection, metadata.created_at_epoch)
            existing = connection.execute(
                """
                SELECT * FROM queue_items
                WHERE source_key = ? AND start_record_ordinal = ? AND start_byte_offset = ?
                  AND end_record_ordinal = ? AND end_byte_offset = ?
                """,
                (
                    metadata.source_key,
                    metadata.start_record_ordinal,
                    metadata.start_byte_offset,
                    metadata.end_record_ordinal,
                    metadata.end_byte_offset,
                ),
            ).fetchone()
            if revalidated_hold is not None:
                if existing is None or metadata.kind is QueueItemKind.SCHEMA_HOLD:
                    raise QueueConflictError("schema hold replacement does not match retained work")
                held = _metadata_from_row(existing)
                item_id, verified_source = revalidated_hold
                if (
                    held.kind is not QueueItemKind.SCHEMA_HOLD
                    or held.item_id != item_id
                    or held.start_prefix_sha256 != metadata.start_prefix_sha256
                    or held.end_prefix_sha256 != metadata.end_prefix_sha256
                    or hashlib.sha256(verified_source).hexdigest() != held.payload_sha256
                    or self._decrypt_payload(held, _row_bytes(existing, "ciphertext"))
                    != verified_source
                ):
                    raise QueueConflictError("schema hold replacement failed source validation")
                # Removal and normal admission share one transaction; any failure retains the hold.
                connection.execute("DELETE FROM queue_items WHERE item_id = ?", (held.item_id,))
                existing = None
            if existing is not None:
                existing_metadata = _metadata_from_row(cast(sqlite3.Row, existing))
                if _payload_identity(existing_metadata) != _payload_identity(metadata):
                    connection.rollback()
                    raise QueueConflictError(
                        "collector queue segment conflicts with existing payload identity"
                    )
                connection.commit()
                return existing_metadata.item_id
            self._validate_enqueue_chain(connection, metadata)
            # BLOB length uses record metadata; the trailing size column needs overflow reads.
            queued_bytes = cast(
                int,
                connection.execute(
                    "SELECT COALESCE(SUM(length(ciphertext)), 0) FROM queue_items"
                ).fetchone()[0],
            )
            if queued_bytes + len(ciphertext) > self.config.max_bytes:
                connection.rollback()
                raise QueueCapacityError("collector queue is at its byte limit")
            connection.execute(
                """
                INSERT INTO queue_items(
                  item_id, kind, state, source_key, source_system, source_path_hash,
                  conversation_id, source_kind, provenance_sha256, payload_sha256,
                  start_record_ordinal, start_byte_offset, end_record_ordinal, end_byte_offset,
                  start_prefix_sha256, end_prefix_sha256, created_at_epoch, expires_at_epoch,
                  next_attempt_at_epoch, ciphertext, ciphertext_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    metadata.item_id,
                    metadata.kind.value,
                    QueueItemState.PENDING.value,
                    metadata.source_key,
                    metadata.source_system.value,
                    metadata.source_path_hash,
                    metadata.conversation_id,
                    None if metadata.source_kind is None else metadata.source_kind.value,
                    metadata.provenance_sha256,
                    metadata.payload_sha256,
                    metadata.start_record_ordinal,
                    metadata.start_byte_offset,
                    metadata.end_record_ordinal,
                    metadata.end_byte_offset,
                    metadata.start_prefix_sha256,
                    metadata.end_prefix_sha256,
                    metadata.created_at_epoch,
                    metadata.expires_at_epoch,
                    metadata.created_at_epoch,
                    ciphertext,
                    len(ciphertext),
                ),
            )
            connection.commit()
        return metadata.item_id

    def _validate_enqueue_chain(
        self,
        connection: sqlite3.Connection,
        metadata: _QueueMetadata,
    ) -> None:
        state = self._source_state_row(connection, metadata.source_key)
        initial = self._initial_selection(connection, metadata.source_key)
        if metadata.kind in {
            QueueItemKind.UPLOAD_BATCH,
            QueueItemKind.CURSOR_CHECKPOINT,
        }:
            if state is None:
                _require_initial_cursor(metadata, initial)
                connection.execute(
                    """
                    INSERT INTO source_state(
                      source_key, source_system, source_path_hash, conversation_id, source_kind,
                      provenance_sha256, next_record_ordinal, next_byte_offset, prefix_sha256,
                      initialized_at_epoch, last_success_at_epoch
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        metadata.source_key,
                        metadata.source_system.value,
                        metadata.source_path_hash,
                        metadata.conversation_id,
                        cast(SourceKind, metadata.source_kind).value,
                        metadata.provenance_sha256,
                        metadata.start_record_ordinal,
                        metadata.start_byte_offset,
                        metadata.start_prefix_sha256,
                        metadata.created_at_epoch,
                    ),
                )
                state = self._source_state_row(connection, metadata.source_key)
            self._verify_source_identity(metadata, state)
        pending = connection.execute(
            """
            SELECT kind, end_record_ordinal, end_byte_offset, end_prefix_sha256
            FROM queue_items WHERE source_key = ?
            ORDER BY end_byte_offset DESC, end_record_ordinal DESC LIMIT 1
            """,
            (metadata.source_key,),
        ).fetchone()
        if pending is not None:
            if cast(str, pending[0]) == QueueItemKind.SCHEMA_HOLD.value:
                raise QueueConflictError("collector queue source is blocked by a schema hold")
            expected = (cast(int, pending[1]), cast(int, pending[2]), cast(str, pending[3]))
        elif state is not None:
            expected = (
                _row_int(state, "next_record_ordinal"),
                _row_int(state, "next_byte_offset"),
                _row_str(state, "prefix_sha256"),
            )
        else:
            _require_initial_cursor(metadata, initial)
            expected = (
                metadata.start_record_ordinal,
                metadata.start_byte_offset,
                metadata.start_prefix_sha256,
            )
        if expected != (
            metadata.start_record_ordinal,
            metadata.start_byte_offset,
            metadata.start_prefix_sha256,
        ):
            raise QueueConflictError("collector queue segment is not contiguous with source state")

    def _upload_metadata(
        self,
        batch: UploadBatch,
        body: bytes,
        *,
        now_epoch: int | None,
    ) -> _QueueMetadata:
        now = _now_epoch(now_epoch)
        parsed = batch.parsed
        return _QueueMetadata(
            item_id=f"queue:{uuid.uuid4().hex}",
            kind=QueueItemKind.UPLOAD_BATCH,
            source_key=source_key_for(
                parsed.source_system,
                batch.source_account_id,
                batch.source_path_hash,
            ),
            source_system=parsed.source_system,
            source_path_hash=batch.source_path_hash,
            conversation_id=parsed.conversation_id,
            source_kind=parsed.source_kind,
            provenance_sha256=_source_provenance_sha256(parsed),
            payload_sha256=hashlib.sha256(body).hexdigest(),
            start_record_ordinal=parsed.segment_start_ordinal,
            start_byte_offset=parsed.segment_start_byte,
            end_record_ordinal=parsed.segment_end_ordinal_exclusive,
            end_byte_offset=parsed.segment_end_byte,
            start_prefix_sha256=parsed.start_prefix_digest,
            end_prefix_sha256=parsed.end_prefix_digest,
            created_at_epoch=now,
            expires_at_epoch=now + self.config.max_age_seconds,
        )

    def _verify_batch_matches_metadata(
        self,
        batch: UploadBatch,
        body: bytes,
        metadata: _QueueMetadata,
    ) -> None:
        expected = self._upload_metadata(batch, body, now_epoch=metadata.created_at_epoch)
        if _payload_identity(expected) != _payload_identity(metadata):
            raise RuntimeError("collector queue payload metadata does not match its envelope")

    def _verify_source_state(
        self,
        metadata: _QueueMetadata,
        state: sqlite3.Row | None,
    ) -> None:
        self._verify_source_identity(metadata, state)
        if state is None or (
            _row_int(state, "next_record_ordinal"),
            _row_int(state, "next_byte_offset"),
            _row_str(state, "prefix_sha256"),
        ) != (
            metadata.start_record_ordinal,
            metadata.start_byte_offset,
            metadata.start_prefix_sha256,
        ):
            raise QueueConflictError("collector queue source cursor does not match the batch")

    def _verify_cursor_checkpoint(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> None:
        metadata = _metadata_from_row(row)
        if metadata.kind is not QueueItemKind.CURSOR_CHECKPOINT:
            raise ValueError("collector queue item is not a cursor checkpoint")
        state = self._source_state_row(connection, metadata.source_key)
        self._verify_source_identity(metadata, state)
        payload = self._decrypt_payload(metadata, _row_bytes(row, "ciphertext"))
        if (
            payload != CURSOR_CHECKPOINT_PAYLOAD
            or hashlib.sha256(payload).hexdigest() != metadata.payload_sha256
        ):
            raise RuntimeError("collector cursor checkpoint payload is invalid")

    def _verify_source_identity(
        self,
        metadata: _QueueMetadata,
        state: sqlite3.Row | None,
    ) -> None:
        if state is None or (
            _row_str(state, "source_system"),
            _row_str(state, "source_path_hash"),
            _row_str(state, "conversation_id"),
            _row_str(state, "source_kind"),
            _row_str(state, "provenance_sha256"),
        ) != (
            metadata.source_system.value,
            metadata.source_path_hash,
            metadata.conversation_id,
            cast(SourceKind, metadata.source_kind).value,
            metadata.provenance_sha256,
        ):
            raise QueueConflictError("collector queue source provenance changed")

    def _source_state_row(
        self,
        connection: sqlite3.Connection,
        source_key: str,
    ) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM source_state WHERE source_key = ?",
                (source_key,),
            ).fetchone(),
        )

    def _decrypt_payload(self, metadata: _QueueMetadata, ciphertext: bytes) -> bytes:
        try:
            return self._primitive.decrypt(ciphertext, _associated_data(metadata))
        except Exception as error:
            raise RuntimeError("collector queue payload failed integrity validation") from error

    def _expire_with_connection(self, connection: sqlite3.Connection, now: int) -> int:
        expired = connection.execute(
            "SELECT 1 FROM queue_items WHERE expires_at_epoch <= ? LIMIT 1",
            (now,),
        ).fetchone()
        if expired is None:
            return 0
        expired_sources = connection.execute(
            """
            SELECT DISTINCT source_key FROM queue_items
            WHERE expires_at_epoch <= ? ORDER BY source_key
            """,
            (now,),
        ).fetchall()
        deleted = 0
        for source_row in expired_sources:
            source_key = cast(str, source_row[0])
            checkpoints = connection.execute(
                "SELECT * FROM queue_items WHERE source_key = ? AND kind = ?",
                (source_key, QueueItemKind.CURSOR_CHECKPOINT.value),
            ).fetchall()
            if checkpoints:
                for checkpoint in checkpoints:
                    self._verify_cursor_checkpoint(connection, checkpoint)
                continue
            row = connection.execute(
                "SELECT * FROM queue_items WHERE source_key = ? "
                "ORDER BY start_byte_offset, start_record_ordinal LIMIT 1",
                (source_key,),
            ).fetchone()
            if row is None:
                continue
            metadata = _metadata_from_row(row)
            if metadata.expires_at_epoch > now:
                continue
            if metadata.kind is QueueItemKind.UPLOAD_BATCH:
                body = self._decrypt_payload(metadata, _row_bytes(row, "ciphertext"))
                batch = parse_upload_batch(body)
                self._verify_batch_matches_metadata(batch, body, metadata)
                existing = connection.execute(
                    """
                    SELECT expected_batch_id, end_record_ordinal, end_byte_offset,
                           end_prefix_sha256, observed_file_size, file_mtime_ns
                    FROM replay_boundaries WHERE source_key = ?
                    """,
                    (source_key,),
                ).fetchone()
                replay_identity = (
                    batch.batch_id,
                    metadata.end_record_ordinal,
                    metadata.end_byte_offset,
                    metadata.end_prefix_sha256,
                    batch.parsed.observed_file_size,
                    batch.parsed.file_mtime_ns,
                )
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO replay_boundaries(
                          source_key, expected_batch_id, end_record_ordinal,
                          end_byte_offset, end_prefix_sha256, observed_file_size,
                          file_mtime_ns, expired_at_epoch
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (source_key, *replay_identity, now),
                    )
                elif tuple(existing) != replay_identity:
                    raise QueueConflictError("expired upload conflicts with its replay boundary")
            start_byte = metadata.start_byte_offset
            start_ordinal = metadata.start_record_ordinal
            deleted += connection.execute(
                """
                DELETE FROM queue_items WHERE source_key = ? AND (
                  start_byte_offset > ? OR
                  (start_byte_offset = ? AND start_record_ordinal >= ?)
                )
                """,
                (source_key, start_byte, start_byte, start_ordinal),
            ).rowcount
        return deleted

    def _initialize_database(self) -> None:
        _validate_private_file(self.database_path, "collector queue database")
        with self._connect(validate_schema=False) as connection:
            version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
            if version == 0:
                existing = cast(
                    int,
                    connection.execute(
                        "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                    ).fetchone()[0],
                )
                if existing:
                    raise RuntimeError("collector queue database has an unknown unversioned schema")
                try:
                    connection.executescript(
                        "BEGIN IMMEDIATE;\n"
                        + QUEUE_SCHEMA
                        + f"\nPRAGMA user_version = {QUEUE_SCHEMA_VERSION};\nCOMMIT;"
                    )
                except sqlite3.Error:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
            elif version in {3, 4, 5}:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    if _schema_signature(connection) != _expected_schema_signature(version):
                        raise RuntimeError("collector queue database has an unknown legacy schema")
                    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
                    if integrity != "ok":
                        raise RuntimeError("collector queue database integrity check failed")
                    if version == 3:
                        connection.execute(QUEUE_SCAN_SCHEMA)
                    if version < 5:
                        for statement in QUEUE_OBSERVATION_STATEMENTS:
                            connection.execute(statement)
                    connection.execute(QUEUE_SELECTION_SCHEMA)
                    connection.execute(f"PRAGMA user_version = {QUEUE_SCHEMA_VERSION}")
                    connection.commit()
                except (sqlite3.Error, RuntimeError):
                    connection.rollback()
                    raise
            elif version != QUEUE_SCHEMA_VERSION:
                raise RuntimeError("collector queue database schema is unsupported")
        self.database_path.chmod(0o600)
        self._validate_database()

    def _validate_database(self) -> None:
        with self._connect(validate_schema=False) as connection:
            version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {3, 4, 5, QUEUE_SCHEMA_VERSION}:
                raise RuntimeError("collector queue database schema is unsupported")
            integrity = cast(str, connection.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity != "ok":
                raise RuntimeError("collector queue database integrity check failed")
            if _schema_signature(connection) != _expected_schema_signature(version):
                raise RuntimeError(
                    "collector queue database schema does not match the pinned schema"
                )

    @contextmanager
    def _connect(self, *, validate_schema: bool = True) -> Generator[sqlite3.Connection]:
        if validate_schema:
            _validate_private_file(self.database_path, "collector queue database")
        connection = sqlite3.connect(self.database_path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            yield connection
        finally:
            connection.close()


def source_key_for(
    source_system: SourceSystem,
    source_account_id: str,
    source_path_hash: str,
) -> str:
    _validate_native_source(source_system)
    if (
        not source_account_id
        or source_account_id.strip() != source_account_id
        or len(source_account_id.encode()) > 1024
    ):
        raise ValueError("source account id is invalid")
    _validate_digest(source_path_hash, "source path hash")
    payload = json.dumps(
        [source_system.value, source_account_id, source_path_hash],
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _source_provenance_sha256(parsed: ParseResult) -> str:
    history_base = parsed.history_base
    value = [
        parsed.conversation_id,
        parsed.branch_id,
        parsed.parent_conversation_id,
        parsed.source_kind.value,
        None
        if history_base is None
        else [
            history_base.thread_id,
            history_base.end_ordinal_exclusive,
            history_base.end_byte_offset,
        ],
    ]
    return hashlib.sha256(
        json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _metadata_from_row(row: sqlite3.Row) -> _QueueMetadata:
    conversation_id = _row_optional_str(row, "conversation_id")
    source_kind_value = _row_optional_str(row, "source_kind")
    return _QueueMetadata(
        item_id=_row_str(row, "item_id"),
        kind=QueueItemKind(_row_str(row, "kind")),
        source_key=_row_str(row, "source_key"),
        source_system=SourceSystem(_row_str(row, "source_system")),
        source_path_hash=_row_str(row, "source_path_hash"),
        conversation_id=conversation_id,
        source_kind=None if source_kind_value is None else SourceKind(source_kind_value),
        provenance_sha256=_row_optional_str(row, "provenance_sha256"),
        payload_sha256=_row_str(row, "payload_sha256"),
        start_record_ordinal=_row_int(row, "start_record_ordinal"),
        start_byte_offset=_row_int(row, "start_byte_offset"),
        end_record_ordinal=_row_int(row, "end_record_ordinal"),
        end_byte_offset=_row_int(row, "end_byte_offset"),
        start_prefix_sha256=_row_str(row, "start_prefix_sha256"),
        end_prefix_sha256=_row_str(row, "end_prefix_sha256"),
        created_at_epoch=_row_int(row, "created_at_epoch"),
        expires_at_epoch=_row_int(row, "expires_at_epoch"),
    )


def _attention_item(row: sqlite3.Row, *, now: int) -> QueueAttentionItem:
    kind = QueueItemKind(_row_str(row, "kind"))
    state = QueueItemState(_row_str(row, "state"))
    if _row_int(row, "expires_at_epoch") <= now:
        reason = "expired"
        action = "reconcile_source"
    elif kind is QueueItemKind.SCHEMA_HOLD:
        reason = "schema_hold"
        action = "upgrade_parser"
    elif _row_optional_str(row, "last_error_code") == QueueFailureCode.SOURCE_EXCLUDED.value:
        reason = "source_excluded"
        action = "reconcile_source_exclusion"
    elif state is QueueItemState.BLOCKED:
        reason = "upload_blocked"
        action = "retry_blocked"
    else:  # pragma: no cover - query guard
        raise RuntimeError("collector queue attention state is invalid")
    return QueueAttentionItem(
        item_id=_row_str(row, "item_id"),
        source_system=SourceSystem(_row_str(row, "source_system")),
        source_path_hash=_row_str(row, "source_path_hash"),
        reason=reason,
        action=action,
        last_error_code=_row_optional_str(row, "last_error_code"),
    )


def _source_status(row: sqlite3.Row) -> QueueSourceState:
    last_success = row["last_success_at_epoch"]
    if last_success is not None and (
        isinstance(last_success, bool) or not isinstance(last_success, int)
    ):
        raise RuntimeError("collector queue last success is invalid")
    replay_value = row["replay_required"]
    if replay_value not in {0, 1}:
        raise RuntimeError("collector queue replay state is invalid")
    return QueueSourceState(
        source_key=_row_str(row, "source_key"),
        source_system=SourceSystem(_row_str(row, "source_system")),
        source_path_hash=_row_str(row, "source_path_hash"),
        next_record_ordinal=_row_int(row, "next_record_ordinal"),
        next_byte_offset=_row_int(row, "next_byte_offset"),
        last_success_at_epoch=last_success,
        replay_required=bool(replay_value),
    )


def _payload_identity(metadata: _QueueMetadata) -> tuple[object, ...]:
    return (
        metadata.kind,
        metadata.source_key,
        metadata.source_system,
        metadata.source_path_hash,
        metadata.conversation_id,
        metadata.source_kind,
        metadata.provenance_sha256,
        metadata.payload_sha256,
        metadata.start_record_ordinal,
        metadata.start_byte_offset,
        metadata.end_record_ordinal,
        metadata.end_byte_offset,
        metadata.start_prefix_sha256,
        metadata.end_prefix_sha256,
    )


def _associated_data(metadata: _QueueMetadata) -> bytes:
    return json.dumps(
        {
            "format_version": QUEUE_PAYLOAD_FORMAT_VERSION,
            "item_id": metadata.item_id,
            "kind": metadata.kind.value,
            "source_key": metadata.source_key,
            "source_system": metadata.source_system.value,
            "source_path_hash": metadata.source_path_hash,
            "conversation_id": metadata.conversation_id,
            "source_kind": None if metadata.source_kind is None else metadata.source_kind.value,
            "provenance_sha256": metadata.provenance_sha256,
            "payload_sha256": metadata.payload_sha256,
            "start_record_ordinal": metadata.start_record_ordinal,
            "start_byte_offset": metadata.start_byte_offset,
            "end_record_ordinal": metadata.end_record_ordinal,
            "end_byte_offset": metadata.end_byte_offset,
            "start_prefix_sha256": metadata.start_prefix_sha256,
            "end_prefix_sha256": metadata.end_prefix_sha256,
            "created_at_epoch": metadata.created_at_epoch,
            "expires_at_epoch": metadata.expires_at_epoch,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def _initial_cursor_from_row(row: sqlite3.Row) -> InitialSourceCursor:
    return InitialSourceCursor(
        next_record_ordinal=_row_int(row, "start_record_ordinal"),
        next_byte_offset=_row_int(row, "start_byte_offset"),
        prefix_digest=_row_str(row, "start_prefix_sha256"),
    )


def _require_initial_cursor(
    metadata: _QueueMetadata, selected: InitialSourceCursor | None = None
) -> None:
    expected = (
        (0, 0, EMPTY_SHA256)
        if selected is None
        else (selected.next_record_ordinal, selected.next_byte_offset, selected.prefix_digest)
    )
    if (
        metadata.start_record_ordinal,
        metadata.start_byte_offset,
        metadata.start_prefix_sha256,
    ) != expected:
        raise QueueConflictError(
            "collector queue requires an initial zero cursor"
            if selected is None
            else "collector queue requires its exact selected initial cursor"
        )


def _validate_config_paths(config: CollectorQueueConfig) -> None:
    if not config.root.is_absolute() or not config.key_file.is_absolute():
        raise ValueError("collector queue paths must be absolute")
    _reject_symlink_components(config.root, "collector queue root")
    _reject_symlink_components(config.key_file, "collector queue key")
    if config.key_file == config.root or config.key_file.is_relative_to(config.root):
        raise ValueError("collector queue key must be outside the queue root")
    if config.max_bytes <= 0 or config.max_age_seconds <= 0:
        raise ValueError("collector queue bounds must be positive")


def _prepare_private_directory(path: Path, label: str) -> None:
    _reject_symlink_components(path, label)
    if path.exists():
        _validate_private_directory(path, label)
        return
    path.mkdir(mode=0o700, parents=True)
    path.chmod(0o700)
    _validate_private_directory(path, label)


def _validate_private_directory(path: Path, label: str) -> None:
    _reject_symlink_components(path, label)
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError(f"{label} must be a private directory")
    if metadata.st_uid != os.getuid():
        raise ValueError(f"{label} must be owned by the current user")


def _write_new_private_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _load_queue_key(path: Path) -> Keyset:
    _validate_private_file(path, "collector queue key")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            serialized = handle.read(MAX_QUEUE_KEY_BYTES + 1)
    finally:
        os.close(descriptor)
    if not serialized or len(serialized) > MAX_QUEUE_KEY_BYTES:
        raise ValueError("collector queue key is invalid")
    try:
        return Keyset.read_cleartext(serialized)
    except Exception as error:
        raise ValueError("collector queue key is invalid") from error


def _validate_private_file(path: Path, label: str) -> None:
    _reject_symlink_components(path, label)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError(f"{label} must be a private regular file")
    if metadata.st_uid != os.getuid():
        raise ValueError(f"{label} must be owned by the current user")


def _reject_symlink_components(path: Path, label: str) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError(f"{label} must not contain symlinks")


def _validate_segment(
    start_record_ordinal: int,
    start_byte_offset: int,
    end_record_ordinal: int,
    end_byte_offset: int,
) -> None:
    values = (start_record_ordinal, start_byte_offset, end_record_ordinal, end_byte_offset)
    if any(isinstance(value, bool) or value < 0 for value in values):
        raise ValueError("collector queue segment boundaries are invalid")
    if end_record_ordinal < start_record_ordinal or end_byte_offset < start_byte_offset:
        raise ValueError("collector queue segment boundaries are invalid")


def _validate_native_source(source_system: SourceSystem) -> None:
    if source_system not in {
        SourceSystem.CODEX,
        SourceSystem.CLAUDE_CODE,
        SourceSystem.GROK_BUILD,
    }:
        raise ValueError("collector queue supports native sources only")


def _validate_digest(value: str, label: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} is invalid")


def _now_epoch(value: int | None) -> int:
    now = int(time.time()) if value is None else value
    if isinstance(now, bool) or now < 0:
        raise ValueError("collector queue time is invalid")
    return now


def _row_str(row: sqlite3.Row, field: str) -> str:
    value = row[field]
    if not isinstance(value, str):
        raise RuntimeError(f"collector queue {field} is invalid")
    return value


def _row_optional_str(row: sqlite3.Row, field: str) -> str | None:
    value = row[field]
    if value is None or isinstance(value, str):
        return value
    raise RuntimeError(f"collector queue {field} is invalid")


def _row_int(row: sqlite3.Row, field: str) -> int:
    value = row[field]
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"collector queue {field} is invalid")
    return value


def _row_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if not isinstance(value, bytes):
        raise RuntimeError(f"collector queue {field} is invalid")
    return value


def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[str, str, str], ...]:
    rows = connection.execute(
        """
        SELECT type, name, sql FROM sqlite_master
        WHERE type IN ('table', 'index', 'trigger', 'view') AND name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    return tuple(
        (cast(str, row[0]), cast(str, row[1]), " ".join(cast(str, row[2]).split())) for row in rows
    )


@lru_cache(maxsize=4)
def _expected_schema_signature(version: int) -> tuple[tuple[str, str, str], ...]:
    with sqlite3.connect(":memory:") as connection:
        connection.executescript(
            QUEUE_SCHEMA_V3
            if version == 3
            else QUEUE_SCHEMA_V4
            if version == 4
            else QUEUE_SCHEMA_V5
            if version == 5
            else QUEUE_SCHEMA
        )
        return _schema_signature(connection)
