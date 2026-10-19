from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import time
import uuid
from collections import Counter
from collections.abc import Callable, Generator, Iterable, Mapping, Sequence
from contextlib import closing, contextmanager, nullcontext
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypedDict, TypeVar, cast

from pydantic_core import PydanticSerializationError, to_json

if TYPE_CHECKING:
    from _hashlib import HASH

from cross_assistant_memory.admission import (
    TEXT_ATTACHMENT_MEDIA_TYPES,
    classify_attachment,
    classify_record,
    is_admission_exclusion_reason,
    raw_record_has_uninspected_attachment,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import (
    EncryptedObjectManifest,
    ObjectState,
)
from cross_assistant_memory.evidence_deletion import (
    EncryptedDeletionTarget,
    EncryptedEvidencePurger,
    PreparationCleanup,
    inspect_preparation_cleanup,
)
from cross_assistant_memory.evidence_locations import (
    ENCRYPTED_LOCATION_SCHEMA,
    EncryptedEvidenceReader,
    read_location,
)
from cross_assistant_memory.evidence_publication import (
    EvidencePublication,
    require_mapping_state,
    same_encrypted_object,
)
from cross_assistant_memory.evidence_rotation import (
    LEGACY_ROTATION_SCHEMA,
    ROTATION_SCHEMA,
    check_rotation_access,
    require_rotation_access,
)
from cross_assistant_memory.ingest import (
    DEFAULT_MAX_FILE_BYTES,
    EMPTY_SHA256,
    NATIVE_SOURCE_SYSTEMS,
    NativeFilePrefix,
    parse_file,
)
from cross_assistant_memory.models import (
    CLIENT_KIND_CAPABILITIES,
    MAX_PROPOSAL_EVIDENCE_EVENTS,
    MAX_PROPOSAL_STATEMENT_BYTES,
    Access,
    Authority,
    CandidateReviewOperation,
    CandidateReviewReason,
    Capability,
    ClientKind,
    CollectorProvenance,
    ContextFilter,
    ContextKind,
    DeletionKind,
    EventCorrection,
    EvidencePreview,
    EvidenceRelation,
    ExclusionReceipt,
    IngestionReport,
    MemoryLifecycle,
    MemoryType,
    ObservationRetirement,
    ParsedRecord,
    ParseResult,
    PendingWebEvidenceClaim,
    Privacy,
    QueryMode,
    RetrievalCandidate,
    RetrievalControl,
    Scope,
    SearchResult,
    SourceCursor,
    SourceCursorGap,
    SourceKind,
    SourceSchemaProvenance,
    SourceSystem,
    UploadReceipt,
    VerifiedClient,
    WebExportArchiveMemberProvenance,
    WebExportAttachmentReferenceProvenance,
    WebExportBatchProvenance,
    WebExportConversationObservation,
)
from cross_assistant_memory.native_file_import import finish_attempt, load_attempt, retain_attempt
from cross_assistant_memory.object_writes import (
    JOURNAL_NAME,
    ObjectWriteJournal,
    ObjectWriteScope,
    check_object_write_access,
)
from cross_assistant_memory.publication_work import (
    PUBLICATION_WORK_SCHEMA,
    EvidencePublicationPending,
    EvidencePublicationPolicy,
    EvidencePublicationYielded,
    enqueue_publication_work,
    publication_key_sha256,
)
from cross_assistant_memory.retrieval import (
    MAX_EVIDENCE_PREVIEW_CHARACTERS,
    MAX_WORKSET_CANDIDATES,
    MAX_WORKSET_RELATIONS,
    assemble_evidence_workset,
    effective_context_filters,
    lexical_score,
)
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
    publish_file_no_replace_at,
    remove_owned_directory_at,
    secure_path_stat,
)

_AdmissionResult = TypeVar("_AdmissionResult")

SCHEMA_VERSION = 24
LEGACY_RECOVERY_SCHEMA_VERSIONS = frozenset(
    {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
)
LEGACY_SCHEMA_UPGRADE_VERSIONS = LEGACY_RECOVERY_SCHEMA_VERSIONS | {3}
SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
SUPPORTED_GENERATION_SCHEMA_VERSIONS = LEGACY_RECOVERY_SCHEMA_VERSIONS | {SCHEMA_VERSION}
DEFAULT_MAX_RECORD_BYTES = 1024 * 1024
MAX_WEB_EXPORT_RECEIPT_BYTES = 64 * 1024
MAX_QUERY_RESULTS = 20
FTS_TOKEN = re.compile(r"[^\W]+", re.UNICODE)
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
UPLOAD_BATCH_ID = re.compile(r"batch:[0-9a-f]{64}")
DELETION_OPERATION_ID = re.compile(r"deletion:[0-9a-f]{64}")
SUPPORTED_QUERY_MODES = {
    QueryMode.FIND_EVIDENCE,
    QueryMode.WHERE_DID_I_LEAVE_OFF,
    QueryMode.WHAT_DID_I_SAY,
    QueryMode.WHAT_DID_I_THINK,
}
CLIENT_TOKEN_PREFIX = "cam1"
CLIENT_TOKEN_MAX_BYTES = 512
ENROLLMENT_CODE_PREFIX = "came1"
ENROLLMENT_CODE_MAX_BYTES = 512
MAX_ENROLLMENT_LIFETIME = 60 * 60
MAX_DEVICE_CREDENTIAL_LIFETIME = 365 * 24 * 60 * 60
MAX_EVIDENCE_ATTACHMENT_MANIFESTS = 100
MAX_EVIDENCE_ATTACHMENT_REFERENCES = 500
FTS_WORKSET_CANDIDATE_ID = "first-party-sqlite-fts5"
MAX_WORKSET_CONTEXT_FILTERS = 32
MAX_ADMIN_ROWS = 200
MAX_RESIDENCY_OBJECTS = 10_000
CANDIDATE_REVIEW_POLICY_VERSION = "candidate-review-v1"
CANDIDATE_CREATION_POLICY_VERSION = "candidate-proposal-v1"


class LocalCopyObservation(TypedDict):
    scope: Literal["registered_object_paths"]
    inspection_limit: int
    inspected_objects: int
    uninspected_objects: int
    present_objects: int
    logical_file_bytes: int
    encrypted_mapped_present_objects: int
    encrypted_mapped_present_bytes: int
    absent_encrypted_objects: int
    missing_local_objects: int
    uninspectable_objects: int
    size_mismatch_objects: int


class AttachmentAuditItem(TypedDict):
    attachment_id_sha256: str
    byte_length: int
    finding: str
    hash_verified: bool


class AttachmentAudit(TypedDict):
    text_free: Literal[True]
    scope: Literal["registered_local_attachments"]
    generation_digest: str
    registered_attachments: int
    unchecked_attachments: int
    read_budget_reserved_bytes: int
    findings: dict[str, int]
    items: list[AttachmentAuditItem]
    admission_policy_changed: Literal[False]


_WORKSET_SELECT_COLUMNS = """
  e.event_id,
  substr(e.content_text, 1, 4000) AS content_text,
  e.event_type,
  e.actor_kind,
  e.assistant,
  e.authority,
  e.scope,
  e.project_id,
  e.conversation_id,
  e.branch_id,
  e.occurred_at,
  sf.source_system,
  sr.object_id,
  sr.record_ordinal,
  sr.byte_start,
  sr.byte_end
"""
_WORKSET_JOINS = """
FROM events_current e
JOIN event_access ea ON ea.event_id = e.event_id
JOIN source_records sr ON sr.source_record_id = e.source_record_id
JOIN source_files sf ON sf.source_file_id = sr.source_file_id
"""
_WORKSET_RESULT_COLUMNS = """
  event_id,
  content_text,
  event_type,
  actor_kind,
  assistant,
  authority,
  scope,
  project_id,
  conversation_id,
  branch_id,
  occurred_at,
  source_system,
  object_id,
  record_ordinal,
  byte_start,
  byte_end,
  score,
  correction_id,
  corrected_at
"""


class ExclusiveWriterToken:
    def __init__(
        self,
        database_path: Path,
        descriptor: int,
        database_identity: tuple[int, int] | None,
    ) -> None:
        self.database_path = database_path
        self.descriptor = descriptor
        self.database_identity = database_identity
        self.active = True


@dataclass(frozen=True)
class _NormalizedPendingWebEvidenceClaim:
    source_account_id: str
    source_system: SourceSystem
    family_key: str
    conversation_id: str
    message_id: str
    parent_message_id: str | None
    branch_id: str | None
    content_digest: str


@dataclass(frozen=True)
class _EvidenceReadState:
    row: tuple[object, ...]
    policy: dict[str, Any]
    web_export: tuple[object, ...] | None
    attachment_rows: tuple[tuple[object, ...], ...]
    attachment_counts: tuple[int, int, int, int]
    location: tuple[str, EncryptedObjectManifest] | None


@dataclass(frozen=True)
class _WorksetPolicy:
    accesses: tuple[Access, ...]
    scopes: tuple[Scope, ...]
    authorities: tuple[Authority, ...]
    contexts: tuple[ContextFilter, ...]
    predicates: tuple[str, ...]
    parameters: tuple[object, ...]


@dataclass(frozen=True)
class _DeletionSelector:
    kind: DeletionKind
    source_system: SourceSystem
    source_account_digests: tuple[str, ...]
    conversation_digest: str | None
    retirement_pairs: tuple[ObservationRetirement, ...] = ()


@dataclass(frozen=True)
class _DeletionTarget:
    source_account_ids: frozenset[str]
    source_stream_ids: frozenset[str]
    source_file_ids: frozenset[str]
    source_record_ids: frozenset[str]
    event_ids: frozenset[str]
    memory_ids: frozenset[str]
    memory_claim_ids: frozenset[str]
    upload_batch_ids: frozenset[str]
    touched_web_batch_ids: frozenset[str]
    deleted_web_batch_ids: frozenset[str]
    web_observation_ids: frozenset[str]
    web_source_object_ids: frozenset[str]
    web_attachment_link_ids: frozenset[str]
    web_attachment_object_ids: frozenset[str]
    web_archive_member_ids: frozenset[str]
    object_candidate_ids: frozenset[str]
    deletable_object_ids: frozenset[str]
    web_container_retirement_ids: frozenset[str] = frozenset()
    record_tombstones: frozenset[tuple[str, str, str]] = frozenset()
    observation_retirement_ids: frozenset[str] = frozenset()
    retained_replacement_event_ids: frozenset[str] = frozenset()

    def digest(self, selector: _DeletionSelector) -> str:
        members = {
            "deleted_web_batch_ids": sorted(self.deleted_web_batch_ids),
            "deletable_object_ids": sorted(self.deletable_object_ids),
            "event_ids": sorted(self.event_ids),
            "memory_claim_ids": sorted(self.memory_claim_ids),
            "memory_ids": sorted(self.memory_ids),
            "object_candidate_ids": sorted(self.object_candidate_ids),
            "source_account_ids": sorted(self.source_account_ids),
            "source_file_ids": sorted(self.source_file_ids),
            "source_record_ids": sorted(self.source_record_ids),
            "source_stream_ids": sorted(self.source_stream_ids),
            "touched_web_batch_ids": sorted(self.touched_web_batch_ids),
            "upload_batch_ids": sorted(self.upload_batch_ids),
            "web_archive_member_ids": sorted(self.web_archive_member_ids),
            "web_attachment_link_ids": sorted(self.web_attachment_link_ids),
            "web_attachment_object_ids": sorted(self.web_attachment_object_ids),
            "web_observation_ids": sorted(self.web_observation_ids),
            "web_source_object_ids": sorted(self.web_source_object_ids),
        }
        payload = {
            "kind": selector.kind.value,
            "source_system": selector.source_system.value,
            "source_account_digests": list(selector.source_account_digests),
            "conversation_digest": selector.conversation_digest,
            "members": members,
        }
        if self.web_container_retirement_ids:
            members["web_container_retirement_ids"] = sorted(self.web_container_retirement_ids)
        if self.record_tombstones:
            members["record_tombstones"] = sorted(":".join(item) for item in self.record_tombstones)
        if self.observation_retirement_ids:
            members["observation_retirement_ids"] = sorted(self.observation_retirement_ids)
            members["retained_replacement_event_ids"] = sorted(self.retained_replacement_event_ids)
            members["retirement_pairs"] = [
                f"{pair.event_id}:{pair.replacement_event_id}" for pair in selector.retirement_pairs
            ]
        return _sha256_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        )

    def counts(self) -> dict[str, int]:
        counts = {
            "source_accounts": len(self.source_account_ids),
            "source_streams": len(self.source_stream_ids),
            "source_files": len(self.source_file_ids),
            "source_records": len(self.source_record_ids),
            "events": len(self.event_ids),
            "memory_candidates": len(self.memory_ids),
            "upload_batches": len(self.upload_batch_ids),
            "web_batches_touched": len(self.touched_web_batch_ids),
            "web_batches_deleted": len(self.deleted_web_batch_ids),
            "web_conversation_observations": len(self.web_observation_ids),
            "object_candidates": len(self.object_candidate_ids),
            "objects_deleted": len(self.deletable_object_ids),
            "shared_objects_retained": len(self.object_candidate_ids - self.deletable_object_ids),
        }
        if self.web_container_retirement_ids:
            counts["web_container_references"] = len(self.web_container_retirement_ids)
        if self.record_tombstones:
            counts["record_erasure_matches"] = len(self.record_tombstones)
        if self.observation_retirement_ids:
            counts["obsolete_observations"] = len(self.observation_retirement_ids)
            counts["retained_replacements"] = len(self.retained_replacement_event_ids)
        return counts


class _WriterLockedConnection(sqlite3.Connection):
    writer_lock_descriptor: int | None = None
    rotation_close_guard: Callable[[], None] | None = None

    def close(self) -> None:
        descriptor = self.writer_lock_descriptor
        self.writer_lock_descriptor = None
        guard = self.rotation_close_guard
        self.rotation_close_guard = None
        try:
            super().close()
        finally:
            if descriptor is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
        if guard is not None:
            guard()


class LedgerWriterBusy(RuntimeError):
    pass


def _acquire_writer_lock(descriptor: int, mode: int, *, wait: bool) -> None:
    try:
        fcntl.flock(descriptor, mode if wait else mode | fcntl.LOCK_NB)
    except BlockingIOError:
        raise LedgerWriterBusy("ledger writer is busy; retry later") from None


def _open_writer_lock(settings: Settings) -> int:
    lock_path = settings.run_root / "ledger-writer.lock"
    if lock_path.is_symlink():
        raise ValueError("ledger writer lock must not be a symlink")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    details = os.fstat(descriptor)
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        os.close(descriptor)
        raise ValueError("ledger writer lock must be a private regular file")
    os.fchmod(descriptor, 0o600)
    return descriptor


def _regular_path_identity(path: Path) -> tuple[int, int]:
    if path.is_symlink():
        raise ValueError("ledger database must not be a symlink")
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode):
        raise ValueError("ledger database must be a regular file")
    if details.st_nlink != 1:
        raise ValueError("ledger database must have exactly one hard link")
    return details.st_dev, details.st_ino


def open_maintenance_inspection(
    settings: Settings, *, require_checkpointed: bool = False
) -> sqlite3.Connection:
    """Inspect existing maintenance state without creating a checkpointed source's sidecars."""
    database = settings.database_path
    _regular_path_identity(database)
    if require_checkpointed:
        _reject_read_only_sidecars(database)
        connection = sqlite3.connect(
            database.resolve(strict=True).as_uri() + "?mode=ro&immutable=1", uri=True
        )
        connection.execute("PRAGMA query_only=ON")
        return connection
    _validate_live_read_only_sidecars(database)
    wal_paths = [Path(f"{database}{suffix}") for suffix in ("-wal", "-shm")]
    journal = Path(f"{database}-journal")
    complete_wal = all(path.is_file() and not path.is_symlink() for path in wal_paths)
    if not complete_wal or journal.exists() or journal.is_symlink():
        _reject_read_only_sidecars(database)
    query = "?mode=ro" if complete_wal else "?mode=ro&immutable=1"
    connection = sqlite3.connect(database.resolve(strict=True).as_uri() + query, uri=True)
    connection.execute("PRAGMA query_only=ON")
    return connection


def maintenance_generation(connection: sqlite3.Connection) -> str:
    return _ledger_generation_digest(connection)


def recover_maintenance_database(settings: Settings, token: ExclusiveWriterToken) -> None:
    """Only explicit maintenance may ask SQLite to recover its own interrupted transaction."""
    database = settings.database_path
    if (
        not token.active
        or token.database_path != database.resolve()
        or token.database_identity != _regular_path_identity(database)
    ):
        raise RuntimeError("maintenance recovery requires the exact exclusive writer")
    for suffix in SQLITE_SIDECAR_SUFFIXES:
        sidecar = Path(f"{database}{suffix}")
        if sidecar.exists() or sidecar.is_symlink():
            details = secure_path_stat(sidecar, "maintenance SQLite sidecar")
            if details.st_nlink != 1 or details.st_uid != os.geteuid():
                raise RuntimeError("maintenance SQLite sidecar is unsafe")
    with closing(
        sqlite3.connect(database.resolve(strict=True).as_uri() + "?mode=rw", uri=True)
    ) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("SELECT phase FROM evidence_rotation WHERE singleton=1").fetchone()
    if token.database_identity != _regular_path_identity(database):
        raise RuntimeError("maintenance database changed during SQLite recovery")


def record_rotation_mutation(
    connection: sqlite3.Connection,
    operation_id: str,
    previous_generation: str,
    new_generation: str,
    *,
    rollback: bool,
) -> None:
    if not connection.in_transaction:
        raise RuntimeError("rotation receipt requires the mapping transaction")
    connection.execute(
        "INSERT INTO mutation_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()),
            operation_id,
            "rollback_encrypted_evidence_rotation" if rollback else "rotate_encrypted_evidence",
            previous_generation,
            new_generation,
            "local:cli",
            "primary-evidence-maintenance",
            "restore journaled primary evidence" if rollback else "rewrap primary evidence",
            _now(),
            _latest_mutation_digest(connection),
        ),
    )


@contextmanager
def exclusive_ledger_writer(
    settings: Settings, *, wait: bool = True
) -> Generator[ExclusiveWriterToken]:
    settings.ensure_directories()
    database = settings.database_path
    if database.is_symlink():
        raise ValueError("ledger database must not be a symlink")
    descriptor = _open_writer_lock(settings)
    token: ExclusiveWriterToken | None = None
    try:
        _acquire_writer_lock(descriptor, fcntl.LOCK_EX, wait=wait)
        database_identity = _regular_path_identity(database) if database.exists() else None
        token = ExclusiveWriterToken(
            database.resolve(),
            descriptor,
            database_identity,
        )
        yield token
    finally:
        if token is not None:
            token.active = False
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


SCHEMA = (
    """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS installations (
  installation_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL REFERENCES installations(installation_id),
  label TEXT NOT NULL,
  platform TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_accounts (
  source_account_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL REFERENCES installations(installation_id),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  source_system TEXT NOT NULL,
  legacy_account_key TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (installation_id, device_id, source_system, legacy_account_key)
);

CREATE TABLE IF NOT EXISTS contexts (
  context_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL REFERENCES installations(installation_id),
  kind TEXT NOT NULL,
  context_key TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (installation_id, kind, context_key)
);

CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL REFERENCES installations(installation_id),
  label TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('assistant', 'collector', 'scheduler', 'local_admin')),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS client_capabilities (
  client_id TEXT NOT NULL REFERENCES clients(client_id),
  capability TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (client_id, capability)
);

CREATE TABLE IF NOT EXISTS client_credentials (
  credential_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(client_id),
  token_digest TEXT NOT NULL CHECK (length(token_digest) = 64),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS client_credentials_client_idx
ON client_credentials(client_id, revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS client_devices (
  client_id TEXT PRIMARY KEY REFERENCES clients(client_id),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS client_devices_device_idx
ON client_devices(device_id);

CREATE TABLE IF NOT EXISTS device_enrollments (
  enrollment_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL REFERENCES installations(installation_id),
  code_digest TEXT NOT NULL UNIQUE CHECK (length(code_digest) = 64),
  device_label TEXT NOT NULL,
  device_platform TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  credential_expires_at TEXT NOT NULL,
  redeemed_at TEXT,
  redeemed_device_id TEXT REFERENCES devices(device_id),
  redeemed_client_id TEXT REFERENCES clients(client_id),
  CHECK (
    (redeemed_at IS NULL AND redeemed_device_id IS NULL AND redeemed_client_id IS NULL)
    OR
    (redeemed_at IS NOT NULL AND redeemed_device_id IS NOT NULL AND redeemed_client_id IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS device_enrollments_state_idx
ON device_enrollments(redeemed_at, expires_at);

CREATE TABLE IF NOT EXISTS source_account_policies (
  source_account_id TEXT PRIMARY KEY REFERENCES source_accounts(source_account_id),
  scope TEXT NOT NULL,
  project_id TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (
    (scope = 'project' AND project_id IS NOT NULL)
    OR
    (scope != 'project' AND project_id IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS upload_batches (
  batch_id TEXT PRIMARY KEY,
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
  client_id TEXT NOT NULL REFERENCES clients(client_id),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  source_account_id TEXT NOT NULL REFERENCES source_accounts(source_account_id),
  source_file_id TEXT NOT NULL REFERENCES source_files(source_file_id),
  conversation_id TEXT NOT NULL,
  event_count INTEGER NOT NULL CHECK (event_count >= 0),
  quarantined_records INTEGER NOT NULL CHECK (quarantined_records >= 0),
  quarantine_reasons_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS upload_batches_source_idx
ON upload_batches(source_account_id, created_at);

CREATE TABLE IF NOT EXISTS objects (
  object_id TEXT PRIMARY KEY,
  plaintext_digest TEXT NOT NULL UNIQUE,
  byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
  media_type TEXT NOT NULL,
  object_path TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  storage_kind TEXT NOT NULL DEFAULT 'local' CHECK (storage_kind IN ('local', 'encrypted'))
);

CREATE TABLE IF NOT EXISTS source_files (
  source_file_id TEXT PRIMARY KEY,
  source_system TEXT NOT NULL,
  source_account TEXT NOT NULL,
  source_path TEXT NOT NULL,
  source_path_hash TEXT NOT NULL,
  file_digest TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  file_mtime_ns INTEGER NOT NULL,
  conversation_id TEXT NOT NULL,
  branch_id TEXT,
  captured_at TEXT,
  ingested_at TEXT NOT NULL,
  parser_name TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  history_base_thread_id TEXT,
  history_base_end_ordinal INTEGER,
  history_base_end_byte_offset INTEGER,
  unknown_record_types_json TEXT NOT NULL,
  malformed_records INTEGER NOT NULL,
  status TEXT NOT NULL,
  UNIQUE (source_system, source_account, source_path_hash, file_digest, parser_version)
);

CREATE TABLE IF NOT EXISTS source_capture_metadata (
  batch_id TEXT PRIMARY KEY REFERENCES upload_batches(batch_id),
  source_file_id TEXT NOT NULL REFERENCES source_files(source_file_id),
  source_client TEXT NOT NULL,
  source_client_version TEXT NOT NULL,
  capture_capability TEXT NOT NULL,
  adapter_name TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  parser_name TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  schema_fingerprint TEXT NOT NULL CHECK (length(schema_fingerprint) = 64),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS source_capture_metadata_source_idx
ON source_capture_metadata(source_file_id, created_at);

CREATE TABLE IF NOT EXISTS source_schema_authorizations (
  authorization_id TEXT PRIMARY KEY,
  source_account_id TEXT NOT NULL REFERENCES source_accounts(source_account_id),
  source_system TEXT NOT NULL,
  schema_fingerprint TEXT NOT NULL CHECK (length(schema_fingerprint) = 64),
  source_client TEXT NOT NULL,
  source_client_version TEXT NOT NULL,
  capture_capability TEXT NOT NULL,
  adapter_name TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  parser_versions_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  authorized_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (
    source_account_id, source_system, schema_fingerprint, source_client,
    source_client_version, capture_capability, adapter_name, adapter_version,
    parser_versions_json
  )
);

CREATE INDEX IF NOT EXISTS source_schema_authorizations_source_idx
ON source_schema_authorizations(source_account_id, status, created_at);

CREATE TABLE IF NOT EXISTS web_export_batches (
  batch_id TEXT PRIMARY KEY,
  source_account_id TEXT NOT NULL REFERENCES source_accounts(source_account_id),
  source_system TEXT NOT NULL,
  authorization_id TEXT NOT NULL REFERENCES source_schema_authorizations(authorization_id),
  manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64),
  code_revision TEXT NOT NULL,
  prepared_at TEXT NOT NULL,
  archive_sha256 TEXT NOT NULL CHECK (length(archive_sha256) = 64),
  archive_byte_length INTEGER NOT NULL CHECK (archive_byte_length >= 0),
  selected_member_name_sha256 TEXT NOT NULL CHECK (length(selected_member_name_sha256) = 64),
  selected_member_sha256 TEXT NOT NULL CHECK (length(selected_member_sha256) = 64),
  selected_member_byte_length INTEGER NOT NULL CHECK (selected_member_byte_length >= 0),
  created_at TEXT NOT NULL,
  UNIQUE (
    source_account_id, source_system, authorization_id, archive_sha256,
    selected_member_name_sha256, selected_member_sha256
  )
);

CREATE TABLE IF NOT EXISTS web_export_archive_members (
  archive_member_id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES web_export_batches(batch_id),
  archive_member_index INTEGER NOT NULL CHECK (archive_member_index >= 0),
  locator TEXT NOT NULL,
  name_sha256 TEXT NOT NULL CHECK (length(name_sha256) = 64),
  content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
  compressed_bytes INTEGER NOT NULL CHECK (compressed_bytes >= 0),
  byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
  compression_method INTEGER NOT NULL CHECK (compression_method >= 0),
  media_type_hint TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (batch_id, archive_member_index)
);

CREATE TABLE IF NOT EXISTS web_export_attachment_links (
  attachment_link_id TEXT PRIMARY KEY,
  archive_member_id TEXT NOT NULL REFERENCES web_export_archive_members(archive_member_id),
  batch_id TEXT NOT NULL REFERENCES web_export_batches(batch_id),
  conversation_index INTEGER NOT NULL CHECK (conversation_index >= 0),
  source_record_ordinal INTEGER NOT NULL CHECK (source_record_ordinal >= 0),
  reference_ordinal INTEGER NOT NULL CHECK (reference_ordinal >= 0),
  reference_sha256 TEXT NOT NULL CHECK (length(reference_sha256) = 64),
  created_at TEXT NOT NULL,
  UNIQUE (
    archive_member_id, conversation_index, source_record_ordinal,
    reference_ordinal, reference_sha256
  )
);

CREATE INDEX IF NOT EXISTS web_export_attachment_links_conversation_idx
ON web_export_attachment_links(
  batch_id, conversation_index, source_record_ordinal, archive_member_id
);

CREATE TABLE IF NOT EXISTS web_export_attachment_objects (
  attachment_source_object_id TEXT PRIMARY KEY,
  archive_member_id TEXT NOT NULL UNIQUE
    REFERENCES web_export_archive_members(archive_member_id),
  batch_id TEXT NOT NULL REFERENCES web_export_batches(batch_id),
  object_id TEXT NOT NULL REFERENCES objects(object_id),
  plaintext_sha256 TEXT NOT NULL CHECK (length(plaintext_sha256) = 64),
  byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
  media_type TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS web_export_source_objects (
  source_object_id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES web_export_batches(batch_id),
  object_kind TEXT NOT NULL CHECK (
    object_kind IN ('official_export_archive', 'selected_export_member', 'conversation_split')
  ),
  conversation_index INTEGER,
  object_id TEXT REFERENCES objects(object_id),
  plaintext_sha256 TEXT NOT NULL CHECK (length(plaintext_sha256) = 64),
  byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
  media_type TEXT NOT NULL,
  conversation_id TEXT,
  branch_id TEXT,
  captured_at TEXT,
  parser_name TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  schema_fingerprint TEXT NOT NULL CHECK (length(schema_fingerprint) = 64),
  created_at TEXT NOT NULL,
  UNIQUE (batch_id, object_kind, conversation_index),
  CHECK (
    (object_kind = 'conversation_split' AND conversation_index IS NOT NULL
      AND conversation_id IS NOT NULL)
    OR
    (object_kind != 'conversation_split' AND conversation_index IS NULL
      AND conversation_id IS NULL AND branch_id IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS web_export_conversation_observations (
  observation_id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES web_export_batches(batch_id),
  source_file_id TEXT NOT NULL REFERENCES source_files(source_file_id),
  source_object_id TEXT NOT NULL REFERENCES web_export_source_objects(source_object_id),
  conversation_index INTEGER NOT NULL CHECK (conversation_index >= 0),
  source_byte_start INTEGER NOT NULL CHECK (source_byte_start >= 0),
  source_byte_end INTEGER NOT NULL CHECK (source_byte_end >= source_byte_start),
  conversation_sha256 TEXT NOT NULL CHECK (length(conversation_sha256) = 64),
  source_locator TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (batch_id, conversation_index)
);

CREATE TABLE IF NOT EXISTS source_streams (
  source_stream_id TEXT PRIMARY KEY,
  source_system TEXT NOT NULL,
  source_account TEXT NOT NULL,
  source_path TEXT NOT NULL,
  source_path_hash TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  branch_id TEXT,
  parent_conversation_id TEXT,
  source_kind TEXT NOT NULL,
  source_label TEXT,
  scope TEXT NOT NULL,
  project_id TEXT,
  initial_record_ordinal INTEGER NOT NULL CHECK (initial_record_ordinal >= 0),
  initial_byte_offset INTEGER NOT NULL CHECK (initial_byte_offset >= 0),
  initial_prefix_digest TEXT NOT NULL,
  parser_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (source_system, source_account, source_path_hash)
);

CREATE TABLE IF NOT EXISTS source_segments (
  source_file_id TEXT PRIMARY KEY REFERENCES source_files(source_file_id),
  source_stream_id TEXT NOT NULL REFERENCES source_streams(source_stream_id),
  start_record_ordinal INTEGER NOT NULL CHECK (start_record_ordinal >= 0),
  start_byte_offset INTEGER NOT NULL CHECK (start_byte_offset >= 0),
  end_record_ordinal INTEGER NOT NULL CHECK (end_record_ordinal >= start_record_ordinal),
  end_byte_offset INTEGER NOT NULL CHECK (end_byte_offset >= start_byte_offset),
  start_prefix_digest TEXT NOT NULL,
  end_prefix_digest TEXT NOT NULL,
  UNIQUE (source_stream_id, start_byte_offset, end_byte_offset, end_prefix_digest)
);

CREATE TABLE IF NOT EXISTS source_cursors (
  source_stream_id TEXT PRIMARY KEY REFERENCES source_streams(source_stream_id),
  next_record_ordinal INTEGER NOT NULL CHECK (next_record_ordinal >= 0),
  next_byte_offset INTEGER NOT NULL CHECK (next_byte_offset >= 0),
  prefix_digest TEXT NOT NULL,
  last_source_file_id TEXT NOT NULL REFERENCES source_files(source_file_id),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_records (
  source_record_id TEXT PRIMARY KEY,
  source_file_id TEXT NOT NULL REFERENCES source_files(source_file_id),
  object_id TEXT NOT NULL REFERENCES objects(object_id),
  record_ordinal INTEGER NOT NULL,
  byte_start INTEGER NOT NULL,
  byte_end INTEGER NOT NULL,
  message_id TEXT,
  parent_message_id TEXT,
  UNIQUE (source_file_id, record_ordinal)
);

CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  source_record_id TEXT NOT NULL UNIQUE REFERENCES source_records(source_record_id),
  event_type TEXT NOT NULL,
  actor_kind TEXT NOT NULL,
  assistant TEXT,
  authority TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  branch_id TEXT,
  occurred_at TEXT,
  mentioned_at TEXT,
  ingested_at TEXT NOT NULL,
  scope TEXT NOT NULL,
  project_id TEXT,
  privacy TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  content_text TEXT NOT NULL,
  parser_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS web_export_reconciled_events (
  reconciliation_key TEXT PRIMARY KEY CHECK (length(reconciliation_key) = 64),
  event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
  family_key TEXT NOT NULL CHECK (length(family_key) = 64),
  source_account_id TEXT NOT NULL REFERENCES source_accounts(source_account_id),
  source_system TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  message_id_kind TEXT NOT NULL,
  parent_message_id TEXT,
  branch_id TEXT,
  object_id TEXT NOT NULL REFERENCES objects(object_id),
  event_type TEXT NOT NULL,
  actor_kind TEXT NOT NULL,
  assistant TEXT,
  authority TEXT NOT NULL,
  occurred_at TEXT,
  scope TEXT NOT NULL,
  project_id TEXT,
  privacy TEXT NOT NULL,
  content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
  created_at TEXT NOT NULL,
  UNIQUE (reconciliation_key, event_id)
);

CREATE INDEX IF NOT EXISTS web_export_reconciled_events_family_idx
ON web_export_reconciled_events(family_key, event_id);

CREATE TABLE IF NOT EXISTS web_export_event_observations (
  source_record_id TEXT PRIMARY KEY REFERENCES source_records(source_record_id),
  event_id TEXT NOT NULL REFERENCES events(event_id),
  reconciliation_key TEXT REFERENCES web_export_reconciled_events(reconciliation_key),
  created_at TEXT NOT NULL,
  FOREIGN KEY (reconciliation_key, event_id)
    REFERENCES web_export_reconciled_events(reconciliation_key, event_id)
);

CREATE INDEX IF NOT EXISTS web_export_event_observations_event_idx
ON web_export_event_observations(event_id);

CREATE TABLE IF NOT EXISTS event_relations (
  relation_id TEXT PRIMARY KEY,
  from_event_id TEXT NOT NULL REFERENCES events(event_id),
  to_event_id TEXT NOT NULL REFERENCES events(event_id),
  relation_type TEXT NOT NULL CHECK (
    relation_type IN ('source_variant', 'contradiction', 'correction', 'supersession')
  ),
  basis TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (from_event_id, to_event_id, relation_type),
  CHECK (from_event_id != to_event_id)
);

CREATE TABLE IF NOT EXISTS event_corrections (
  correction_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  correction_id TEXT NOT NULL UNIQUE,
  event_id TEXT NOT NULL REFERENCES events(event_id),
  event_type TEXT NOT NULL,
  actor_kind TEXT NOT NULL,
  assistant TEXT,
  authority TEXT NOT NULL,
  scope TEXT NOT NULL,
  project_id TEXT,
  privacy TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  content_text TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  previous_state_digest TEXT NOT NULL,
  new_state_digest TEXT NOT NULL,
  reason TEXT NOT NULL,
  authorized_by TEXT NOT NULL,
  authorization_scope TEXT NOT NULL,
  created_at TEXT NOT NULL,
  previous_correction_id TEXT REFERENCES event_corrections(correction_id)
);

CREATE INDEX IF NOT EXISTS event_corrections_event_idx
ON event_corrections(event_id, correction_sequence DESC);

CREATE VIEW IF NOT EXISTS current_event_corrections AS
SELECT correction.*
FROM event_corrections correction
WHERE NOT EXISTS (
  SELECT 1
  FROM event_corrections newer
  WHERE newer.event_id = correction.event_id
    AND newer.correction_sequence > correction.correction_sequence
);

CREATE VIEW IF NOT EXISTS events_current AS
SELECT
  event.event_id,
  event.source_record_id,
  CASE WHEN correction.correction_id IS NULL THEN event.event_type ELSE correction.event_type END
    AS event_type,
  CASE WHEN correction.correction_id IS NULL THEN event.actor_kind ELSE correction.actor_kind END
    AS actor_kind,
  CASE WHEN correction.correction_id IS NULL THEN event.assistant ELSE correction.assistant END
    AS assistant,
  CASE WHEN correction.correction_id IS NULL THEN event.authority ELSE correction.authority END
    AS authority,
  event.conversation_id,
  event.branch_id,
  event.occurred_at,
  event.mentioned_at,
  event.ingested_at,
  CASE WHEN correction.correction_id IS NULL THEN event.scope ELSE correction.scope END AS scope,
  CASE WHEN correction.correction_id IS NULL THEN event.project_id ELSE correction.project_id END
    AS project_id,
  CASE WHEN correction.correction_id IS NULL THEN event.privacy ELSE correction.privacy END
    AS privacy,
  CASE
    WHEN correction.correction_id IS NULL THEN event.content_digest
    ELSE correction.content_digest
  END AS content_digest,
  CASE
    WHEN correction.correction_id IS NULL THEN event.content_text
    ELSE correction.content_text
  END AS content_text,
  CASE
    WHEN correction.correction_id IS NULL THEN event.parser_version
    ELSE correction.parser_version
  END AS parser_version,
  correction.correction_id,
  correction.reason AS correction_reason,
  correction.authorized_by AS correction_authorized_by,
  correction.authorization_scope AS correction_authorization_scope,
  correction.created_at AS corrected_at
FROM events event
LEFT JOIN current_event_corrections correction ON correction.event_id = event.event_id;

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  event_id UNINDEXED,
  content_text,
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE IF NOT EXISTS quarantines (
  quarantine_id TEXT PRIMARY KEY,
  source_file_id TEXT NOT NULL REFERENCES source_files(source_file_id),
  record_ordinal INTEGER NOT NULL,
  byte_start INTEGER NOT NULL,
  byte_end INTEGER NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (source_file_id, record_ordinal, reason)
);

CREATE TABLE IF NOT EXISTS memory_candidates (
  memory_id TEXT PRIMARY KEY,
  memory_type TEXT NOT NULL,
  statement TEXT NOT NULL,
  statement_digest TEXT NOT NULL,
  authority TEXT NOT NULL,
  lifecycle TEXT NOT NULL CHECK (lifecycle = 'candidate'),
  scope TEXT NOT NULL,
  project_id TEXT,
  temporal_status TEXT NOT NULL,
  evidence_event_ids_json TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_candidate_evidence_claims (
  claim_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL UNIQUE REFERENCES memory_candidates(memory_id),
  source_account_id TEXT NOT NULL REFERENCES source_accounts(source_account_id),
  source_system TEXT NOT NULL CHECK (
    source_system IN ('chatgpt_web', 'claude_web', 'grok_web')
  ),
  family_key TEXT NOT NULL CHECK (length(family_key) = 64),
  conversation_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  message_id_kind TEXT NOT NULL CHECK (message_id_kind = 'provider_message_id'),
  parent_message_id TEXT,
  branch_id TEXT,
  content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS memory_candidate_evidence_claims_match_idx
ON memory_candidate_evidence_claims(
  family_key, parent_message_id, branch_id, content_digest, claim_id
);

CREATE TABLE IF NOT EXISTS memory_candidate_evidence_links (
  claim_id TEXT PRIMARY KEY REFERENCES memory_candidate_evidence_claims(claim_id),
  event_id TEXT NOT NULL REFERENCES events(event_id),
  reconciliation_key TEXT NOT NULL,
  previous_evidence_event_ids_json TEXT NOT NULL,
  evidence_event_ids_json TEXT NOT NULL,
  previous_authority TEXT NOT NULL,
  authority TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (reconciliation_key, event_id)
    REFERENCES web_export_reconciled_events(reconciliation_key, event_id)
);

CREATE TABLE IF NOT EXISTS source_stream_access (
  source_stream_id TEXT PRIMARY KEY REFERENCES source_streams(source_stream_id),
  access TEXT NOT NULL,
  derived_from_legacy_scope INTEGER NOT NULL CHECK (derived_from_legacy_scope IN (0, 1)),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_stream_contexts (
  source_stream_id TEXT NOT NULL REFERENCES source_streams(source_stream_id),
  context_id TEXT NOT NULL REFERENCES contexts(context_id),
  assignment_kind TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (source_stream_id, context_id)
);

CREATE TABLE IF NOT EXISTS event_access (
  event_id TEXT PRIMARY KEY REFERENCES events(event_id),
  access TEXT NOT NULL,
  derived_from_legacy_scope INTEGER NOT NULL CHECK (derived_from_legacy_scope IN (0, 1)),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_contexts (
  event_id TEXT NOT NULL REFERENCES events(event_id),
  context_id TEXT NOT NULL REFERENCES contexts(context_id),
  assignment_kind TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (event_id, context_id)
);

CREATE TABLE IF NOT EXISTS memory_candidate_access (
  memory_id TEXT PRIMARY KEY REFERENCES memory_candidates(memory_id),
  access TEXT NOT NULL,
  derived_from_legacy_scope INTEGER NOT NULL CHECK (derived_from_legacy_scope IN (0, 1)),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_candidate_contexts (
  memory_id TEXT NOT NULL REFERENCES memory_candidates(memory_id),
  context_id TEXT NOT NULL REFERENCES contexts(context_id),
  assignment_kind TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (memory_id, context_id)
);

CREATE TABLE IF NOT EXISTS memory_candidate_proposal_receipts (
  proposal_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  proposal_id TEXT NOT NULL UNIQUE,
  memory_id TEXT NOT NULL UNIQUE,
  candidate_creation_digest TEXT NOT NULL CHECK (length(candidate_creation_digest) = 64),
  proposed_by TEXT NOT NULL CHECK (length(proposed_by) > 0),
  proposer_kind TEXT NOT NULL CHECK (proposer_kind IN ('assistant', 'local_admin')),
  authorization_scope TEXT NOT NULL CHECK (authorization_scope = 'memory:propose-write'),
  policy_version TEXT NOT NULL CHECK (policy_version = 'candidate-proposal-v1'),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_candidate_review_transitions (
  review_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  transition_id TEXT NOT NULL UNIQUE,
  memory_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('qualify', 'approve', 'reject')),
  previous_lifecycle TEXT NOT NULL CHECK (previous_lifecycle IN ('candidate', 'qualified')),
  new_lifecycle TEXT NOT NULL CHECK (new_lifecycle IN ('qualified', 'approved', 'rejected')),
  candidate_basis_digest TEXT NOT NULL CHECK (length(candidate_basis_digest) = 64),
  previous_transition_id TEXT,
  review_policy_version TEXT NOT NULL CHECK (review_policy_version = 'candidate-review-v1'),
  authorized_by TEXT NOT NULL CHECK (length(authorized_by) > 0),
  authorization_scope TEXT NOT NULL CHECK (authorization_scope = 'memory:curate'),
  reason_code TEXT NOT NULL CHECK (
    reason_code IN (
      'deterministic_checks_passed', 'owner_approved', 'duplicate', 'incorrect',
      'out_of_scope', 'superseded', 'insufficient_evidence'
    )
  ),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS memory_candidate_review_memory_idx
ON memory_candidate_review_transitions(memory_id, review_sequence DESC);

CREATE TABLE IF NOT EXISTS mutation_receipts (
  mutation_id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  previous_version_digest TEXT NOT NULL,
  new_version_digest TEXT NOT NULL,
  authorized_by TEXT NOT NULL,
  authorization_scope TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  previous_mutation_digest TEXT
);

CREATE TABLE IF NOT EXISTS web_export_import_receipts (
  batch_sha256 TEXT PRIMARY KEY,
  receipt_json TEXT NOT NULL CHECK (length(CAST(receipt_json AS BLOB)) <= 65536)
);

CREATE TABLE IF NOT EXISTS query_receipts (
  query_id TEXT PRIMARY KEY,
  query_mode TEXT NOT NULL,
  query_digest TEXT NOT NULL,
  principal TEXT NOT NULL,
  filters_json TEXT NOT NULL,
  result_event_ids_json TEXT NOT NULL,
  omitted_counts_json TEXT NOT NULL,
  latency_ms REAL NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deletion_tombstones (
  tombstone_id TEXT PRIMARY KEY,
  deletion_kind TEXT NOT NULL CHECK (
    deletion_kind IN ('conversation', 'source_account')
  ),
  source_system TEXT NOT NULL,
  source_account_digest TEXT NOT NULL CHECK (length(source_account_digest) = 64),
  conversation_digest TEXT CHECK (
    conversation_digest IS NULL OR length(conversation_digest) = 64
  ),
  operation_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (
    (deletion_kind = 'conversation' AND conversation_digest IS NOT NULL)
    OR
    (deletion_kind = 'source_account' AND conversation_digest IS NULL)
  ),
  UNIQUE (
    deletion_kind, source_system, source_account_digest, conversation_digest
  )
);

CREATE INDEX IF NOT EXISTS deletion_tombstones_lookup_idx
ON deletion_tombstones(source_system, source_account_digest, conversation_digest);

CREATE TABLE IF NOT EXISTS record_deletion_tombstones (
  source_system TEXT NOT NULL,
  source_account_digest TEXT NOT NULL CHECK (length(source_account_digest) = 64),
  conversation_digest TEXT NOT NULL CHECK (length(conversation_digest) = 64),
  match_kind TEXT NOT NULL CHECK (match_kind IN ('raw_record', 'provider_message_id')),
  match_digest TEXT NOT NULL CHECK (length(match_digest) = 64),
  operation_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (
    source_system, source_account_digest, conversation_digest, match_kind, match_digest
  )
);

CREATE TABLE IF NOT EXISTS deletion_operations (
  operation_id TEXT PRIMARY KEY,
  plan_sha256 TEXT NOT NULL UNIQUE CHECK (length(plan_sha256) = 64),
  deletion_kind TEXT NOT NULL CHECK (
    deletion_kind IN ('conversation', 'source_account', 'web_containers', 'no_memory_records',
                     'obsolete_observations')
  ),
  source_system TEXT NOT NULL,
  target_digest TEXT NOT NULL CHECK (length(target_digest) = 64),
  previous_generation_digest TEXT NOT NULL CHECK (
    length(previous_generation_digest) = 64
  ),
  new_generation_digest TEXT CHECK (
    new_generation_digest IS NULL OR length(new_generation_digest) = 64
  ),
  status TEXT NOT NULL CHECK (status IN ('purging', 'complete')),
  target_counts_json TEXT NOT NULL,
  authorized_by TEXT NOT NULL,
  authorization_scope TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS deletion_object_work (
  operation_id TEXT NOT NULL REFERENCES deletion_operations(operation_id),
  object_id TEXT NOT NULL,
  object_path TEXT NOT NULL,
  byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
  status TEXT NOT NULL CHECK (status IN ('pending', 'deleted')),
  completed_at TEXT,
  encrypted_purge_json TEXT CHECK (
    encrypted_purge_json IS NULL OR length(encrypted_purge_json) <= 1048576
  ),
  PRIMARY KEY (operation_id, object_id)
);

CREATE INDEX IF NOT EXISTS events_scope_project_idx
ON events(scope, project_id, privacy, occurred_at);
CREATE INDEX IF NOT EXISTS events_authority_idx
ON events(authority, actor_kind);
CREATE INDEX IF NOT EXISTS source_files_conversation_idx
ON source_files(source_system, conversation_id, ingested_at);
CREATE INDEX IF NOT EXISTS source_accounts_lookup_idx
ON source_accounts(source_system, legacy_account_key);
CREATE INDEX IF NOT EXISTS contexts_kind_key_idx
ON contexts(kind, context_key);
CREATE INDEX IF NOT EXISTS event_contexts_context_idx
ON event_contexts(context_id, event_id);
"""
    + ENCRYPTED_LOCATION_SCHEMA
    + PUBLICATION_WORK_SCHEMA
    + ROTATION_SCHEMA
)

_SCHEMA_14_OBJECTS = (
    ("table", "memory_candidate_proposal_receipts"),
    ("table", "memory_candidate_review_transitions"),
    ("index", "memory_candidate_review_memory_idx"),
)


def _normalized_schema_sql(value: str) -> str:
    return " ".join(value.split())


@lru_cache(maxsize=1)
def _expected_schema_14_objects() -> dict[tuple[str, str], str]:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(SCHEMA)
        return _schema_14_objects(connection)


def _schema_14_objects(connection: sqlite3.Connection) -> dict[tuple[str, str], str]:
    names = tuple(name for _, name in _SCHEMA_14_OBJECTS)
    placeholders = ",".join("?" for _ in names)
    rows = connection.execute(
        f"""
        SELECT type, name, sql
        FROM sqlite_master
        WHERE name IN ({placeholders})
        """,
        names,
    ).fetchall()
    return {
        (cast(str, row[0]), cast(str, row[1])): _normalized_schema_sql(cast(str, row[2]))
        for row in rows
        if row[2] is not None
    }


def validate_current_schema_objects(connection: sqlite3.Connection) -> None:
    validate_schema20_objects(connection, current_deletion_schema=True)
    if _rotation_schema(connection) != _expected_rotation_schema():
        raise RuntimeError("ledger schema 24 rotation journal is invalid")
    if _web_export_receipt_schema(connection) != _expected_web_export_receipt_schema():
        raise RuntimeError("ledger schema 23 web export receipt table is invalid")


def validate_schema23_objects(connection: sqlite3.Connection) -> None:
    validate_schema20_objects(connection, current_deletion_schema=True)
    if _rotation_schema(connection) != _expected_legacy_rotation_schema():
        raise RuntimeError("ledger schema 23 rotation journal is invalid")
    if _web_export_receipt_schema(connection) != _expected_web_export_receipt_schema():
        raise RuntimeError("ledger schema 23 web export receipt table is invalid")


def validate_schema22_objects(connection: sqlite3.Connection) -> None:
    validate_schema20_objects(connection, current_deletion_schema=True)
    if _rotation_schema(connection) != _expected_legacy_rotation_schema():
        raise RuntimeError("ledger schema 21 rotation journal is invalid")
    if _web_export_receipt_schema(connection) is not None:
        raise RuntimeError("legacy ledger contains unexpected web export receipts")


def validate_schema21_objects(connection: sqlite3.Connection) -> None:
    validate_schema20_objects(connection)
    if _rotation_schema(connection) != _expected_legacy_rotation_schema():
        raise RuntimeError("ledger schema 21 rotation journal is invalid")
    if _web_export_receipt_schema(connection) is not None:
        raise RuntimeError("legacy ledger contains unexpected web export receipts")


def validate_schema20_objects(
    connection: sqlite3.Connection, *, current_deletion_schema: bool = False
) -> None:
    if _schema_14_objects(connection) != _expected_schema_14_objects():
        raise RuntimeError("ledger schema 14 candidate-review objects are invalid")
    if _web_container_schema(connection) != _expected_web_container_schema():
        raise RuntimeError("ledger schema 15 web-container objects are invalid")
    deletion_schema = _expected_deletion_operation_schema()
    if not current_deletion_schema:
        deletion_schema = deletion_schema.replace(", 'obsolete_observations'", "")
    if _deletion_operation_schema(connection) != deletion_schema:
        raise RuntimeError("ledger schema 17 deletion-operation objects are invalid")
    if _record_tombstone_schema(connection) != _expected_record_tombstone_schema():
        raise RuntimeError("ledger schema 17 record-tombstone objects are invalid")
    if _encrypted_location_schema(connection) != _expected_encrypted_location_schema():
        raise RuntimeError("ledger schema 18 encrypted-object locations are invalid")
    if _object_storage_kind_column(connection) != ("TEXT", 1, "'local'", 0):
        raise RuntimeError("ledger schema 18 object storage-kind column is invalid")
    if _encrypted_purge_column(connection) != ("TEXT", 0, None, 0):
        raise RuntimeError("ledger schema 19 deletion-work column is invalid")
    if _publication_work_schema(connection) != _expected_publication_work_schema():
        raise RuntimeError("ledger schema 20 publication-work objects are invalid")


def legacy_snapshot_generation(connection: sqlite3.Connection) -> str:
    """Inspect supported old schemas for backup without enabling legacy runtime access."""
    version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    if version == 20 and _rotation_schema(connection) is None:
        validate_schema20_objects(connection)
    elif version == 21:
        validate_schema21_objects(connection)
    elif version == 22:
        validate_schema22_objects(connection)
    elif version == 23:
        validate_schema23_objects(connection)
    else:
        raise RuntimeError("legacy snapshot generation requires unmodified schema 20, 21, 22 or 23")
    return _ledger_generation_digest(connection, schema_version=version)


def _rotation_schema(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='evidence_rotation'"
    ).fetchone()
    return _normalized_schema_sql(cast(str, row[0])) if row is not None else None


def _web_export_receipt_schema(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='web_export_import_receipts'"
    ).fetchone()
    return _normalized_schema_sql(cast(str, row[0])) if row is not None else None


@lru_cache(maxsize=1)
def _expected_web_export_receipt_schema() -> str:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(SCHEMA)
        return cast(str, _web_export_receipt_schema(connection))


@lru_cache(maxsize=1)
def _expected_rotation_schema() -> str:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(ROTATION_SCHEMA)
        return cast(str, _rotation_schema(connection))


@lru_cache(maxsize=1)
def _expected_legacy_rotation_schema() -> str:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(LEGACY_ROTATION_SCHEMA)
        return cast(str, _rotation_schema(connection))


def _require_empty_legacy_rotation(connection: sqlite3.Connection) -> None:
    observed = _rotation_schema(connection)
    if observed is None:
        return
    if observed != _expected_legacy_rotation_schema():
        raise RuntimeError("legacy rotation journal schema is invalid")
    if connection.execute("SELECT 1 FROM evidence_rotation LIMIT 1").fetchone() is not None:
        raise RuntimeError(
            "schema upgrade refuses an extant evidence rotation journal; "
            "retain its original runtime and authenticated rollback scope"
        )


def _publication_work_schema(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'evidence_publication_work'"
    ).fetchone()
    return _normalized_schema_sql(cast(str, row[0])) if row is not None else None


@lru_cache(maxsize=1)
def _expected_publication_work_schema() -> str:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(PUBLICATION_WORK_SCHEMA)
        return cast(str, _publication_work_schema(connection))


def _encrypted_purge_column(connection: sqlite3.Connection) -> tuple[object, ...] | None:
    return next(
        (
            tuple(row[2:])
            for row in connection.execute("PRAGMA table_info(deletion_object_work)")
            if row[1] == "encrypted_purge_json"
        ),
        None,
    )


def _object_storage_kind_column(connection: sqlite3.Connection) -> tuple[object, ...] | None:
    return next(
        (
            tuple(row[2:])
            for row in connection.execute("PRAGMA table_info(objects)")
            if row[1] == "storage_kind"
        ),
        None,
    )


def _encrypted_location_schema(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'encrypted_object_locations'"
    ).fetchone()
    return _normalized_schema_sql(cast(str, row[0])) if row is not None else None


@lru_cache(maxsize=1)
def _expected_encrypted_location_schema() -> str:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(ENCRYPTED_LOCATION_SCHEMA)
        return cast(str, _encrypted_location_schema(connection))


def _record_tombstone_schema(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'record_deletion_tombstones'"
    ).fetchone()
    return _normalized_schema_sql(cast(str, row[0])) if row is not None else None


@lru_cache(maxsize=1)
def _expected_record_tombstone_schema() -> str:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(SCHEMA)
        return cast(str, _record_tombstone_schema(connection))


def _deletion_operation_schema(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'deletion_operations'"
    ).fetchone()
    if row is None:
        return None
    return _normalized_schema_sql(cast(str, row[0])).replace(
        '"deletion_operations"', "deletion_operations"
    )


@lru_cache(maxsize=1)
def _expected_deletion_operation_schema() -> str:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(SCHEMA)
        return cast(str, _deletion_operation_schema(connection))


def _upgrade_deletion_operation_schema(connection: sqlite3.Connection) -> None:
    expected = _expected_deletion_operation_schema()
    observed = _deletion_operation_schema(connection)
    if observed == expected:
        return
    if observed not in _supported_deletion_operation_schemas():
        raise RuntimeError("legacy deletion-operation schema is invalid")
    connection.execute(expected.replace("deletion_operations", "deletion_operations_v17", 1))
    connection.execute("INSERT INTO deletion_operations_v17 SELECT * FROM deletion_operations")
    connection.execute("DROP TABLE deletion_operations")
    connection.execute("ALTER TABLE deletion_operations_v17 RENAME TO deletion_operations")


def _supported_deletion_operation_schemas() -> set[str]:
    expected = _expected_deletion_operation_schema()
    previous = expected.replace(", 'obsolete_observations'", "")
    return {
        expected,
        previous,
        previous.replace(", 'no_memory_records'", ""),
        previous.replace(", 'web_containers', 'no_memory_records'", ""),
    }


def _web_container_schema(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("web_export_source_objects",),
    ).fetchone()
    if row is None:
        return None
    return _normalized_schema_sql(cast(str, row[0])).replace(
        '"web_export_source_objects"', "web_export_source_objects"
    )


@lru_cache(maxsize=1)
def _expected_web_container_schema() -> str:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(SCHEMA)
        return cast(str, _web_container_schema(connection))


def _upgrade_web_container_schema(connection: sqlite3.Connection) -> None:
    expected = _expected_web_container_schema()
    observed = _web_container_schema(connection)
    if observed == expected:
        return
    legacy = expected.replace(
        "object_id TEXT REFERENCES objects", "object_id TEXT NOT NULL REFERENCES objects"
    )
    if observed != legacy:
        raise RuntimeError("legacy web-container schema is invalid")
    # Rebuild only this FK parent, preserving every old object and provenance row.
    connection.execute(
        expected.replace("web_export_source_objects", "web_export_source_objects_v15", 1)
    )
    connection.execute(
        "INSERT INTO web_export_source_objects_v15 SELECT * FROM web_export_source_objects"
    )
    connection.execute("DROP TABLE web_export_source_objects")
    connection.execute(
        "ALTER TABLE web_export_source_objects_v15 RENAME TO web_export_source_objects"
    )


LEGACY_CONTEXT_ASSIGNMENT = "legacy_scope_projection"


def _sync_v4_compatibility_projection(connection: sqlite3.Connection) -> None:
    now = _now()
    installation_id = _ensure_installation(connection, now)
    source_rows = connection.execute(
        """
        SELECT source_system, source_account FROM source_files
        UNION
        SELECT source_system, source_account FROM source_streams
        ORDER BY source_system, source_account
        """
    ).fetchall()
    if source_rows:
        legacy_source_rows: list[tuple[str, str]] = []
        for source_system, source_account in source_rows:
            registered = connection.execute(
                """
                SELECT source_system
                FROM source_accounts
                WHERE source_account_id = ?
                """,
                (source_account,),
            ).fetchone()
            if registered is not None:
                if cast(str, registered[0]) != cast(str, source_system):
                    raise RuntimeError("registered source account has a mismatched source system")
                continue
            legacy_source_rows.append((cast(str, source_system), cast(str, source_account)))
        if legacy_source_rows:
            device_id = _ensure_legacy_device(connection, installation_id, now)
            for source_system, source_account in legacy_source_rows:
                _ensure_source_account(
                    connection,
                    installation_id=installation_id,
                    device_id=device_id,
                    source_system=source_system,
                    legacy_account_key=source_account,
                    now=now,
                )

    stream_rows = connection.execute(
        "SELECT source_stream_id, scope, project_id FROM source_streams"
    ).fetchall()
    for source_stream_id, scope, project_id in stream_rows:
        stream_id = cast(str, source_stream_id)
        _sync_legacy_access(
            connection,
            table="source_stream_access",
            id_column="source_stream_id",
            entity_id=stream_id,
            scope=cast(str, scope),
            now=now,
        )
        _sync_legacy_context(
            connection,
            table="source_stream_contexts",
            id_column="source_stream_id",
            entity_id=stream_id,
            installation_id=installation_id,
            project_id=cast(str | None, project_id),
            now=now,
        )

    event_rows = connection.execute(
        "SELECT event_id, scope, project_id FROM events_current"
    ).fetchall()
    for event_id, scope, project_id in event_rows:
        current_event_id = cast(str, event_id)
        _sync_legacy_access(
            connection,
            table="event_access",
            id_column="event_id",
            entity_id=current_event_id,
            scope=cast(str, scope),
            now=now,
        )
        _sync_legacy_context(
            connection,
            table="event_contexts",
            id_column="event_id",
            entity_id=current_event_id,
            installation_id=installation_id,
            project_id=cast(str | None, project_id),
            now=now,
        )

    candidate_rows = connection.execute(
        "SELECT memory_id, scope, project_id FROM memory_candidates"
    ).fetchall()
    for memory_id, scope, project_id in candidate_rows:
        current_memory_id = cast(str, memory_id)
        _sync_legacy_access(
            connection,
            table="memory_candidate_access",
            id_column="memory_id",
            entity_id=current_memory_id,
            scope=cast(str, scope),
            now=now,
        )
        _sync_legacy_context(
            connection,
            table="memory_candidate_contexts",
            id_column="memory_id",
            entity_id=current_memory_id,
            installation_id=installation_id,
            project_id=cast(str | None, project_id),
            now=now,
        )


def _ensure_installation(connection: sqlite3.Connection, now: str) -> str:
    rows = connection.execute(
        "SELECT installation_id FROM installations ORDER BY installation_id"
    ).fetchall()
    if len(rows) > 1:
        raise RuntimeError("v1 ledger must contain exactly one installation")
    if rows:
        return cast(str, rows[0][0])
    installation_id = f"installation:{uuid.uuid4()}"
    connection.execute(
        "INSERT INTO installations(installation_id, owner_id, created_at) VALUES (?, ?, ?)",
        (installation_id, "owner:primary", now),
    )
    return installation_id


def _ensure_legacy_device(connection: sqlite3.Connection, installation_id: str, now: str) -> str:
    device_id = _stable_id("device", installation_id, "legacy-local")
    connection.execute(
        """
        INSERT OR IGNORE INTO devices(
          device_id, installation_id, label, platform, status, created_at, updated_at
        ) VALUES (?, ?, 'Legacy local sources', 'unknown', 'active', ?, ?)
        """,
        (device_id, installation_id, now, now),
    )
    return device_id


def _ensure_source_account(
    connection: sqlite3.Connection,
    *,
    installation_id: str,
    device_id: str,
    source_system: str,
    legacy_account_key: str,
    now: str,
) -> str:
    source_account_id = _stable_id(
        "source_account", installation_id, device_id, source_system, legacy_account_key
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO source_accounts(
          source_account_id, installation_id, device_id, source_system,
          legacy_account_key, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
        """,
        (
            source_account_id,
            installation_id,
            device_id,
            source_system,
            legacy_account_key,
            now,
            now,
        ),
    )
    return source_account_id


def _sync_legacy_access(
    connection: sqlite3.Connection,
    *,
    table: str,
    id_column: str,
    entity_id: str,
    scope: str,
    now: str,
) -> None:
    allowed_tables = {
        ("source_stream_access", "source_stream_id"),
        ("event_access", "event_id"),
        ("memory_candidate_access", "memory_id"),
    }
    if (table, id_column) not in allowed_tables:
        raise ValueError("unsupported legacy access projection")
    access = _access_from_legacy_scope(scope).value
    row = connection.execute(
        f"SELECT access, derived_from_legacy_scope FROM {table} WHERE {id_column} = ?",
        (entity_id,),
    ).fetchone()
    if row is None:
        connection.execute(
            f"""
            INSERT INTO {table}({id_column}, access, derived_from_legacy_scope, updated_at)
            VALUES (?, ?, 1, ?)
            """,
            (entity_id, access, now),
        )
    elif bool(row[1]) and cast(str, row[0]) != access:
        connection.execute(
            f"""
            UPDATE {table}
            SET access = ?, derived_from_legacy_scope = 1, updated_at = ?
            WHERE {id_column} = ?
            """,
            (access, now, entity_id),
        )


def _sync_legacy_context(
    connection: sqlite3.Connection,
    *,
    table: str,
    id_column: str,
    entity_id: str,
    installation_id: str,
    project_id: str | None,
    now: str,
) -> None:
    allowed_tables = {
        ("source_stream_contexts", "source_stream_id"),
        ("event_contexts", "event_id"),
        ("memory_candidate_contexts", "memory_id"),
    }
    if (table, id_column) not in allowed_tables:
        raise ValueError("unsupported legacy context projection")
    desired_context_id = (
        _ensure_context(
            connection,
            installation_id=installation_id,
            kind=ContextKind.PROJECT,
            context_key=project_id,
            label=project_id,
            now=now,
        )
        if project_id is not None
        else None
    )
    rows = connection.execute(
        f"""
        SELECT context_id FROM {table}
        WHERE {id_column} = ? AND assignment_kind = ?
        """,
        (entity_id, LEGACY_CONTEXT_ASSIGNMENT),
    ).fetchall()
    existing = {cast(str, row[0]) for row in rows}
    for context_id in existing - ({desired_context_id} if desired_context_id else set()):
        connection.execute(
            f"""
            DELETE FROM {table}
            WHERE {id_column} = ? AND context_id = ? AND assignment_kind = ?
            """,
            (entity_id, context_id, LEGACY_CONTEXT_ASSIGNMENT),
        )
    if desired_context_id is not None and desired_context_id not in existing:
        connection.execute(
            f"""
            INSERT INTO {table}({id_column}, context_id, assignment_kind, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (entity_id, desired_context_id, LEGACY_CONTEXT_ASSIGNMENT, now),
        )


def _ensure_context(
    connection: sqlite3.Connection,
    *,
    installation_id: str,
    kind: ContextKind,
    context_key: str,
    label: str,
    now: str,
) -> str:
    if not context_key:
        raise ValueError("context key must not be empty")
    context_id = _stable_id("context", installation_id, kind.value, context_key)
    connection.execute(
        """
        INSERT OR IGNORE INTO contexts(
          context_id, installation_id, kind, context_key, label, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (context_id, installation_id, kind.value, context_key, label, now),
    )
    return context_id


def _access_from_legacy_scope(scope: str) -> Access:
    parsed = Scope(scope)
    if parsed in (Scope.USER_GLOBAL, Scope.PROJECT):
        return Access.OWNER
    if parsed is Scope.ASSISTANT_PRIVATE:
        return Access.ASSISTANT_PRIVATE
    return Access.SESSION


def _normalized_client_capabilities(
    kind: ClientKind,
    capabilities: Sequence[Capability],
) -> tuple[Capability, ...]:
    unique_capabilities = tuple(sorted(set(capabilities), key=lambda item: item.value))
    if not unique_capabilities:
        raise ValueError("at least one client capability is required")
    disallowed = set(unique_capabilities) - CLIENT_KIND_CAPABILITIES[kind]
    if disallowed:
        values = ", ".join(sorted(item.value for item in disallowed))
        raise ValueError(f"{kind.value} client cannot receive capabilities: {values}")
    return unique_capabilities


def _insert_client(
    connection: sqlite3.Connection,
    *,
    installation_id: str,
    label: str,
    kind: ClientKind,
    capabilities: Sequence[Capability],
    created_at: str,
    intent_key: str | None = None,
    allow_create: bool = True,
) -> dict[str, Any]:
    normalized_label = label.strip()
    if not normalized_label:
        raise ValueError("client label is required")
    unique_capabilities = _normalized_client_capabilities(kind, capabilities)
    client_id = (
        _stable_id(
            "client",
            installation_id,
            _bounded_identity_value(intent_key, "client intent key"),
        )
        if intent_key is not None
        else f"client_{uuid.uuid4()}"
    )
    existing = connection.execute(
        """
        SELECT installation_id, label, kind, status, created_at, revoked_at
        FROM clients
        WHERE client_id = ?
        """,
        (client_id,),
    ).fetchone()
    if existing is not None:
        existing_capabilities = tuple(
            Capability(cast(str, row[0]))
            for row in connection.execute(
                """
                SELECT capability
                FROM client_capabilities
                WHERE client_id = ?
                ORDER BY capability
                """,
                (client_id,),
            ).fetchall()
        )
        if (
            intent_key is None
            or cast(str, existing[0]) != installation_id
            or cast(str, existing[1]) != normalized_label
            or cast(str, existing[2]) != kind.value
            or cast(str, existing[3]) != "active"
            or existing[5] is not None
            or existing_capabilities != unique_capabilities
        ):
            raise RuntimeError("client intent conflicts with an existing client")
        return {
            "client_id": client_id,
            "label": normalized_label,
            "kind": kind.value,
            "capabilities": [item.value for item in unique_capabilities],
            "status": "active",
            "created_at": cast(str, existing[4]),
            "replayed": True,
        }
    if not allow_create:
        raise RuntimeError("ledger generation changed before client registration")
    connection.execute(
        """
        INSERT INTO clients(
          client_id, installation_id, label, kind, status, created_at, revoked_at
        ) VALUES (?, ?, ?, ?, 'active', ?, NULL)
        """,
        (client_id, installation_id, normalized_label, kind.value, created_at),
    )
    connection.executemany(
        """
        INSERT INTO client_capabilities(client_id, capability, created_at)
        VALUES (?, ?, ?)
        """,
        [(client_id, item.value, created_at) for item in unique_capabilities],
    )
    result: dict[str, Any] = {
        "client_id": client_id,
        "label": normalized_label,
        "kind": kind.value,
        "capabilities": [item.value for item in unique_capabilities],
        "status": "active",
        "created_at": created_at,
    }
    if intent_key is not None:
        result["replayed"] = False
    return result


def _insert_client_credential(
    connection: sqlite3.Connection,
    client_id: str,
    *,
    expires_at: datetime,
    now: datetime,
    token: str | None = None,
    allow_create: bool = True,
    require_existing: bool = False,
) -> dict[str, Any]:
    expiry = _normalized_timestamp(expires_at)
    if expiry <= now:
        raise ValueError("client credential expiry must be in the future")
    client = connection.execute(
        "SELECT status FROM clients WHERE client_id = ?",
        (client_id,),
    ).fetchone()
    if client is None or cast(str, client[0]) != "active":
        raise ValueError("active client not found")
    if token is None:
        credential_token = generate_client_credential_token()
        credential_id, _normalized_token = parse_client_credential_token(credential_token)
    else:
        credential_id, credential_token = parse_client_credential_token(token)
    token_digest = hashlib.sha256(credential_token.encode()).hexdigest()
    created_at = now.isoformat()
    existing = connection.execute(
        """
        SELECT client_id, token_digest, created_at, expires_at, revoked_at
        FROM client_credentials
        WHERE credential_id = ?
        """,
        (credential_id,),
    ).fetchone()
    if existing is not None:
        if (
            token is None
            or cast(str, existing[0]) != client_id
            or not hmac.compare_digest(cast(str, existing[1]), token_digest)
            or _parse_timestamp(cast(str, existing[3])) != expiry
            or existing[4] is not None
        ):
            raise RuntimeError("client credential intent conflicts with an existing credential")
        return {
            "credential_id": credential_id,
            "client_id": client_id,
            "token": credential_token,
            "expires_at": cast(str, existing[3]),
            "created_at": cast(str, existing[2]),
            "replayed": True,
        }
    if require_existing:
        raise RuntimeError("published client credential has no matching ledger row")
    if not allow_create:
        raise RuntimeError("ledger generation changed before client credential creation")
    connection.execute(
        """
        INSERT INTO client_credentials(
          credential_id, client_id, token_digest, created_at, expires_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, NULL)
        """,
        (credential_id, client_id, token_digest, created_at, expiry.isoformat()),
    )
    result: dict[str, Any] = {
        "credential_id": credential_id,
        "client_id": client_id,
        "token": credential_token,
        "expires_at": expiry.isoformat(),
    }
    if token is not None:
        result["created_at"] = created_at
        result["replayed"] = False
    return result


def generate_client_credential_token(*, credential_id: str | None = None) -> str:
    resolved_id = credential_id or f"credential_{uuid.uuid4()}"
    token = f"{CLIENT_TOKEN_PREFIX}.{resolved_id}.{secrets.token_urlsafe(32)}"
    parse_client_credential_token(token)
    return token


def generate_device_enrollment_code(*, enrollment_id: str | None = None) -> str:
    resolved_id = enrollment_id or f"enrollment_{uuid.uuid4()}"
    code = f"{ENROLLMENT_CODE_PREFIX}.{resolved_id}.{secrets.token_urlsafe(32)}"
    _parse_enrollment_code(code)
    return code


def parse_client_credential_token(token: str) -> tuple[str, str]:
    encoded = token.encode()
    parts = token.split(".")
    credential_id = parts[1] if len(parts) == 3 else ""
    secret = parts[2] if len(parts) == 3 else ""
    if (
        not token
        or token.strip() != token
        or len(encoded) > CLIENT_TOKEN_MAX_BYTES
        or len(parts) != 3
        or parts[0] != CLIENT_TOKEN_PREFIX
        or not credential_id.startswith("credential_")
        or len(credential_id) == len("credential_")
        or any(
            not character.isascii() or not (character.isalnum() or character in "_-")
            for character in credential_id
        )
        or not secret
        or any(character.isspace() for character in token)
        or any(
            not character.isascii() or not (character.isalnum() or character in "-_~+/=")
            for character in secret
        )
    ):
        raise ValueError("client credential token is invalid")
    return credential_id, token


def _device_enrollment_result(
    *,
    enrollment_id: str,
    device_id: str,
    device_label: str,
    device_platform: str,
    device_status: str,
    client_id: str,
    client_label: str,
    client_kind: str,
    client_status: str,
    client_created_at: str,
    credential_id: str,
    credential_expires_at: str,
    replayed: bool,
    credential_token: str | None = None,
) -> dict[str, Any]:
    result = {
        "status": "already_enrolled" if replayed else "enrolled",
        "replayed": replayed,
        "enrollment_id": enrollment_id,
        "device": {
            "device_id": device_id,
            "label": device_label,
            "platform": device_platform,
            "status": device_status,
        },
        "client": {
            "client_id": client_id,
            "label": client_label,
            "kind": client_kind,
            "capabilities": sorted(
                (Capability.MEMORY_STATUS.value, Capability.SOURCE_UPLOAD.value)
            ),
            "status": client_status,
            "created_at": client_created_at,
        },
        "credential": {
            "credential_id": credential_id,
            "client_id": client_id,
            "expires_at": credential_expires_at,
        },
    }
    if credential_token is not None:
        cast(dict[str, Any], result["credential"])["token"] = credential_token
    return result


def _validate_exclusion_receipts(
    parsed: ParseResult,
    receipts: Sequence[ExclusionReceipt],
) -> None:
    admitted_ordinals = {record.record_ordinal for record in parsed.records}
    seen_ordinals: set[int] = set()
    for receipt in receipts:
        if receipt.record_ordinal in seen_ordinals:
            raise ValueError("exclusion receipts contain a duplicate record ordinal")
        if receipt.record_ordinal in admitted_ordinals:
            raise ValueError("an exclusion receipt overlaps an admitted record")
        if not (
            parsed.segment_start_ordinal
            <= receipt.record_ordinal
            < parsed.segment_end_ordinal_exclusive
        ):
            raise ValueError("exclusion receipt ordinal is outside the source segment")
        if not (
            parsed.segment_start_byte
            <= receipt.byte_start
            < receipt.byte_end
            <= parsed.segment_end_byte
        ):
            raise ValueError("exclusion receipt bytes are outside the source segment")
        if not is_admission_exclusion_reason(receipt.reason):
            raise ValueError("exclusion receipt reason is invalid")
        seen_ordinals.add(receipt.record_ordinal)


def _require_registered_upload_identity(
    connection: sqlite3.Connection,
    *,
    installation_id: str,
    client_id: str,
    device_id: str,
    source_account_id: str,
    source_system: SourceSystem,
    scope: Scope,
    project_id: str | None,
) -> None:
    row = connection.execute(
        """
        SELECT 1
        FROM source_accounts account
        JOIN source_account_policies policy
          ON policy.source_account_id = account.source_account_id
        JOIN devices device ON device.device_id = account.device_id
        JOIN client_devices binding ON binding.device_id = device.device_id
        JOIN clients client ON client.client_id = binding.client_id
        JOIN client_capabilities capability ON capability.client_id = client.client_id
        WHERE account.source_account_id = ?
          AND account.installation_id = ?
          AND account.device_id = ?
          AND account.source_system = ?
          AND policy.scope = ?
          AND policy.project_id IS ?
          AND account.status = 'active'
          AND device.status = 'active'
          AND binding.client_id = ?
          AND client.kind = 'collector'
          AND client.status = 'active'
          AND client.revoked_at IS NULL
          AND capability.capability = 'source:upload'
        """,
        (
            source_account_id,
            installation_id,
            device_id,
            source_system.value,
            scope.value,
            project_id,
            client_id,
        ),
    ).fetchone()
    if row is None:
        raise PermissionError("source account is not authorized for this collector device")


def _require_registered_source_account(
    connection: sqlite3.Connection,
    *,
    installation_id: str,
    source_account_id: str,
    source_system: SourceSystem,
    scope: Scope,
    project_id: str | None,
) -> str:
    normalized_source_account_id = _bounded_identity_value(
        source_account_id,
        "source account id",
    )
    if normalized_source_account_id != source_account_id:
        raise ValueError("source account id must use its exact canonical value")
    row = connection.execute(
        """
        SELECT account.device_id
        FROM source_accounts account
        JOIN source_account_policies policy
          ON policy.source_account_id = account.source_account_id
        JOIN devices device ON device.device_id = account.device_id
        WHERE account.source_account_id = ?
          AND account.installation_id = ?
          AND account.source_system = ?
          AND policy.scope = ?
          AND policy.project_id IS ?
          AND account.status = 'active'
          AND device.status = 'active'
        """,
        (
            normalized_source_account_id,
            installation_id,
            source_system.value,
            scope.value,
            project_id,
        ),
    ).fetchone()
    if row is None:
        raise PermissionError("active registered source account policy not found")
    return cast(str, row[0])


def _require_registered_source_account_for_candidate(
    connection: sqlite3.Connection,
    *,
    installation_id: str,
    source_account_id: str,
    source_system: SourceSystem,
    scope: Scope,
    project_id: str | None,
    allowed_accesses: Sequence[Access] | None,
) -> str:
    normalized_source_account_id = _bounded_identity_value(
        source_account_id,
        "source account id",
    )
    if normalized_source_account_id != source_account_id:
        raise ValueError("source account id must use its exact canonical value")
    row = connection.execute(
        """
        SELECT account.device_id, policy.scope, policy.project_id
        FROM source_accounts account
        JOIN source_account_policies policy
          ON policy.source_account_id = account.source_account_id
        JOIN devices device ON device.device_id = account.device_id
        WHERE account.source_account_id = ?
          AND account.installation_id = ?
          AND account.source_system = ?
          AND account.status = 'active'
          AND device.status = 'active'
        """,
        (
            normalized_source_account_id,
            installation_id,
            source_system.value,
        ),
    ).fetchone()
    if row is None:
        raise PermissionError("active registered source account policy not found")
    if (
        allowed_accesses is not None
        and _access_from_legacy_scope(cast(str, row[1])) not in allowed_accesses
    ):
        raise PermissionError("active registered source account policy not found")
    try:
        _validate_proposal_scope(
            scope,
            project_id,
            [Scope(cast(str, row[1]))],
            [cast(str | None, row[2])],
        )
    except ValueError as error:
        raise PermissionError(
            "registered source account policy cannot support the candidate scope"
        ) from error
    return cast(str, row[0])


def _require_active_source_schema_authorization(
    connection: sqlite3.Connection,
    *,
    source_account_id: str,
    source_system: SourceSystem,
    provenance: SourceSchemaProvenance,
) -> tuple[str, str, str]:
    normalized_source_account_id = _canonical_identity_value(
        source_account_id,
        "source account id",
    )
    normalized_provenance = _normalized_source_schema_provenance(provenance)
    authorization_id = _source_schema_authorization_id(
        source_account_id=normalized_source_account_id,
        source_system=source_system,
        provenance=normalized_provenance,
    )
    row = connection.execute(
        """
        SELECT authorized_by, created_at
        FROM source_schema_authorizations
        WHERE authorization_id = ?
          AND source_account_id = ?
          AND source_system = ?
          AND status = 'active'
        """,
        (
            authorization_id,
            normalized_source_account_id,
            source_system.value,
        ),
    ).fetchone()
    if row is None:
        raise PermissionError(
            "active standing source schema authorization not found; owner approval required"
        )
    return authorization_id, cast(str, row[0]), cast(str, row[1])


def _require_capture_metadata(
    *,
    connection: sqlite3.Connection,
    batch_id: str,
    parser_name: str,
    parser_version: str,
    provenance_values: tuple[str, str, str, str, str, str],
) -> None:
    capture = connection.execute(
        """
        SELECT source_client, source_client_version, capture_capability,
               adapter_name, adapter_version, parser_name, parser_version,
               schema_fingerprint
        FROM source_capture_metadata
        WHERE batch_id = ?
        """,
        (batch_id,),
    ).fetchone()
    expected = (
        *provenance_values[:5],
        parser_name,
        parser_version,
        provenance_values[5],
    )
    if capture is None or tuple(capture) != expected:
        raise RuntimeError("upload batch provenance conflicts with an existing receipt")


@dataclass
class _AdmissionTransaction:
    connection: sqlite3.Connection
    writer_token: ExclusiveWriterToken
    created_object_paths: set[Path]
    expected_generation: str | None = None
    kind: Literal["web_export", "native_upload"] = "web_export"
    failed: bool = False

    def require_active(self) -> None:
        if not self.writer_token.active or not self.connection.in_transaction:
            raise RuntimeError(f"{self.kind.replace('_', ' ')} transaction is inactive")
        if self.failed:
            raise RuntimeError(
                f"{self.kind.replace('_', ' ')} transaction contains a failed admission"
            )


class Ledger:
    def __init__(
        self,
        settings: Settings,
        *,
        read_only: bool = False,
        require_checkpointed: bool = True,
        allow_schema_upgrade: bool = False,
        exclusive_writer_token: ExclusiveWriterToken | None = None,
        encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
        encrypted_evidence_purger: EncryptedEvidencePurger | None = None,
        evidence_publication_policy: EvidencePublicationPolicy | None = None,
        rotation_maintenance: bool = False,
        object_write_scope: ObjectWriteScope | None = None,
        defer_initialization: bool = False,
        fail_fast_on_maintenance: bool = False,
    ):
        if not read_only and not require_checkpointed:
            raise ValueError("require_checkpointed only applies to read-only ledgers")
        if read_only and exclusive_writer_token is not None:
            raise ValueError("exclusive writer tokens apply only to writable ledgers")
        if read_only and allow_schema_upgrade:
            raise ValueError("schema upgrades apply only to writable ledgers")
        if defer_initialization and (read_only or allow_schema_upgrade):
            raise ValueError(
                "deferred initialization requires an existing writable ledger "
                "without schema upgrades"
            )
        if rotation_maintenance and (
            read_only or exclusive_writer_token is None or not exclusive_writer_token.active
        ):
            raise ValueError("rotation maintenance requires an active exclusive writer")
        self._rotation_maintenance = rotation_maintenance
        self._fail_fast_on_maintenance = fail_fast_on_maintenance
        if (
            not rotation_maintenance
            and not allow_schema_upgrade
            and settings.database_path.exists()
        ):
            if read_only and require_checkpointed:
                check_rotation_access(
                    settings, encrypted_evidence_reader, require_checkpointed=True
                )
            else:
                check_rotation_access(settings, encrypted_evidence_reader)
        self.settings = settings
        self.read_only = read_only
        self.require_checkpointed = require_checkpointed
        self.allow_schema_upgrade = allow_schema_upgrade
        self._exclusive_writer_token = exclusive_writer_token
        if object_write_scope is not None and (
            read_only or exclusive_writer_token is None or not exclusive_writer_token.active
        ):
            raise ValueError("object write attempts require an active exclusive writer")
        self._object_write_scope = object_write_scope
        self._object_write_journal: ObjectWriteJournal | None = None
        self._encrypted_evidence_reader = encrypted_evidence_reader
        self._encrypted_evidence_purger = encrypted_evidence_purger
        if evidence_publication_policy is not None and encrypted_evidence_reader is None:
            raise ValueError("remote-primary publication requires explicit evidence access")
        self._evidence_publication_policy = evidence_publication_policy
        self._admission_transaction: _AdmissionTransaction | None = None
        if read_only:
            self._validate_read_only()
        else:
            if defer_initialization:
                self._validate_deferred_write_open()
            self._validate_writable_schema()
            if not defer_initialization:
                self.settings.ensure_directories()
                self.initialize()

    def _validate_deferred_write_open(self) -> None:
        token = self._exclusive_writer_token
        if token is not None and (
            not token.active or token.database_path != self.settings.database_path.resolve()
        ):
            raise RuntimeError("exclusive ledger writer token is inactive or mismatched")
        for path in (
            self.settings.data_root,
            self.settings.data_root / "objects",
            self.settings.object_root,
            self.settings.run_root,
        ):
            descriptor = open_directory_no_symlinks(path, "existing ledger directory")
            try:
                metadata = os.fstat(descriptor)
                if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                    raise RuntimeError("existing ledger directories must be owned and private")
            finally:
                os.close(descriptor)
        descriptor, _path = open_regular_file_no_symlinks(
            self.settings.database_path, "existing ledger database"
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise RuntimeError("existing ledger must be an owned private single-link file")
            if token is not None and token.database_identity != (metadata.st_dev, metadata.st_ino):
                raise RuntimeError("ledger database identity changed under the writer lock")
        finally:
            os.close(descriptor)
        _validate_live_read_only_sidecars(self.settings.database_path)

    @property
    def encrypted_evidence_reader(self) -> EncryptedEvidenceReader | None:
        return self._encrypted_evidence_reader

    @property
    def encrypted_evidence_purger(self) -> EncryptedEvidencePurger | None:
        return self._encrypted_evidence_purger

    def maintenance_connection(self) -> sqlite3.Connection:
        token = self._exclusive_writer_token
        if token is None or not token.active:
            raise RuntimeError("maintenance connection requires an exclusive writer")
        return self._connect()

    def initialize(self) -> None:
        self._require_writable()
        with closing(self._connect()) as connection:
            if self.allow_schema_upgrade:
                connection.execute("PRAGMA foreign_keys = OFF")
            try:
                connection.execute("BEGIN IMMEDIATE")
                current_version: int | None = None
                if connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
                ).fetchone():
                    current_version = cast(
                        int | None,
                        connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[
                            0
                        ],
                    )
                if current_version is not None and current_version > SCHEMA_VERSION:
                    raise RuntimeError(
                        f"ledger schema {current_version} is newer than supported {SCHEMA_VERSION}"
                    )
                if current_version is not None and current_version < SCHEMA_VERSION:
                    if not self.allow_schema_upgrade:
                        raise RuntimeError("ledger schema changed; run an approved schema upgrade")
                    # Recheck under SQLite's write lock before touching the old rollback scope.
                    _require_empty_legacy_rotation(connection)
                    if current_version == 23:
                        validate_schema23_objects(connection)
                    elif current_version == 22:
                        validate_schema22_objects(connection)
                    elif current_version == 21:
                        validate_schema21_objects(connection)
                    if _rotation_schema(connection) is not None:
                        connection.execute("DROP TABLE evidence_rotation")
                # executescript commits an open transaction; execute complete statements instead.
                statement = ""
                for line in SCHEMA.splitlines(keepends=True):
                    statement += line
                    if sqlite3.complete_statement(statement):
                        connection.execute(statement)
                        statement = ""
                if statement.strip() or not connection.in_transaction:
                    raise RuntimeError("ledger schema initialization is not atomic")
                if self.allow_schema_upgrade:
                    _upgrade_web_container_schema(connection)
                    _upgrade_deletion_operation_schema(connection)
                    if _object_storage_kind_column(connection) is None:
                        connection.execute(
                            "ALTER TABLE objects ADD COLUMN storage_kind TEXT NOT NULL "
                            "DEFAULT 'local' "
                            "CHECK (storage_kind IN ('local', 'encrypted'))"
                        )
                    if _encrypted_purge_column(connection) is None:
                        connection.execute(
                            "ALTER TABLE deletion_object_work ADD COLUMN encrypted_purge_json "
                            "TEXT CHECK (encrypted_purge_json IS NULL OR "
                            "length(encrypted_purge_json) <= 1048576)"
                        )
                _sync_v4_compatibility_projection(connection)
                validate_current_schema_objects(connection)
                if (
                    self.allow_schema_upgrade
                    and connection.execute("PRAGMA foreign_key_check").fetchone() is not None
                ):
                    raise RuntimeError("schema upgrade violates foreign keys")
                connection.execute(
                    "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, _now()),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            finally:
                if self.allow_schema_upgrade:
                    connection.execute("PRAGMA foreign_keys = ON")

    def _validate_writable_schema(self) -> None:
        database = self.settings.database_path
        if not database.exists() and not database.is_symlink():
            return
        if database.is_symlink() or not database.is_file():
            raise ValueError("ledger database must be a regular file")
        uri = f"{database.resolve(strict=True).as_uri()}?mode=ro"
        try:
            with closing(sqlite3.connect(uri, timeout=15, uri=True)) as connection:
                row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
                current_version = cast(int | None, row[0] if row is not None else None)
                if self.allow_schema_upgrade and current_version in LEGACY_SCHEMA_UPGRADE_VERSIONS:
                    _require_empty_legacy_rotation(connection)
                if not self._rotation_maintenance:
                    require_rotation_access(
                        connection, self.settings, self._encrypted_evidence_reader
                    )
                if current_version == SCHEMA_VERSION:
                    validate_current_schema_objects(connection)
                    return
                if self.allow_schema_upgrade and current_version == 23:
                    validate_schema23_objects(connection)
                    return
                if self.allow_schema_upgrade and current_version == 22:
                    validate_schema22_objects(connection)
                    return
                if self.allow_schema_upgrade and current_version == 21:
                    validate_schema21_objects(connection)
                    return
                if (
                    self.allow_schema_upgrade
                    and current_version in LEGACY_SCHEMA_UPGRADE_VERSIONS
                    and current_version < 14
                    and _schema_14_objects(connection)
                ):
                    raise RuntimeError(
                        "legacy ledger contains partial schema 14 candidate-review objects"
                    )
                if (
                    self.allow_schema_upgrade
                    and current_version in {14, 15, 16}
                    and _schema_14_objects(connection) != _expected_schema_14_objects()
                ):
                    raise RuntimeError("ledger schema 14 candidate-review objects are invalid")
                if (
                    self.allow_schema_upgrade
                    and current_version in {15, 16}
                    and _web_container_schema(connection) != _expected_web_container_schema()
                ):
                    raise RuntimeError("ledger schema 15 web-container objects are invalid")
                if (
                    self.allow_schema_upgrade
                    and current_version in {15, 16}
                    and _deletion_operation_schema(connection)
                    not in _supported_deletion_operation_schemas()
                ):
                    raise RuntimeError("legacy deletion-operation schema is invalid")
                if self.allow_schema_upgrade and current_version in LEGACY_SCHEMA_UPGRADE_VERSIONS:
                    work_schema = _publication_work_schema(connection)
                    if work_schema not in {None, _expected_publication_work_schema()}:
                        raise RuntimeError("legacy publication-work schema is invalid")
                    if (
                        current_version < 20
                        and work_schema is not None
                        and connection.execute(
                            "SELECT 1 FROM evidence_publication_work LIMIT 1"
                        ).fetchone()
                    ):
                        raise RuntimeError("legacy ledger contains unexpected publication work")
                    if _encrypted_purge_column(connection) not in {None, ("TEXT", 0, None, 0)}:
                        raise RuntimeError("legacy deletion-work column is invalid")
                    if (
                        current_version < 19
                        and _encrypted_purge_column(connection) is not None
                        and connection.execute(
                            "SELECT 1 FROM deletion_object_work "
                            "WHERE encrypted_purge_json IS NOT NULL LIMIT 1"
                        ).fetchone()
                    ):
                        raise RuntimeError(
                            "legacy ledger contains unexpected encrypted deletion work"
                        )
                    kind_column = _object_storage_kind_column(connection)
                    if kind_column not in {None, ("TEXT", 1, "'local'", 0)}:
                        raise RuntimeError("legacy object storage-kind column is invalid")
                    if (
                        current_version < 18
                        and kind_column is not None
                        and connection.execute(
                            "SELECT 1 FROM objects WHERE storage_kind != 'local' LIMIT 1"
                        ).fetchone()
                    ):
                        raise RuntimeError("legacy ledger contains unexpected encrypted objects")
                    location_schema = _encrypted_location_schema(connection)
                    if location_schema not in {None, _expected_encrypted_location_schema()}:
                        raise RuntimeError("legacy encrypted-object location schema is invalid")
                    if (
                        current_version < 18
                        and location_schema is not None
                        and connection.execute(
                            "SELECT 1 FROM encrypted_object_locations LIMIT 1"
                        ).fetchone()
                    ):
                        raise RuntimeError("legacy ledger contains unexpected encrypted locations")
                    observed_tombstones = _record_tombstone_schema(connection)
                    if (
                        current_version >= 17
                        and observed_tombstones != _expected_record_tombstone_schema()
                    ) or observed_tombstones not in {None, _expected_record_tombstone_schema()}:
                        raise RuntimeError("legacy record-tombstone schema is invalid")
                    if current_version >= 17 and (
                        _schema_14_objects(connection) != _expected_schema_14_objects()
                        or _web_container_schema(connection) != _expected_web_container_schema()
                        or _deletion_operation_schema(connection)
                        != _expected_deletion_operation_schema().replace(
                            ", 'obsolete_observations'", ""
                        )
                    ):
                        raise RuntimeError("ledger schema 17 objects are invalid")
                    if current_version >= 18 and (
                        kind_column != ("TEXT", 1, "'local'", 0)
                        or location_schema != _expected_encrypted_location_schema()
                    ):
                        raise RuntimeError("ledger schema 18 encrypted-object objects are invalid")
                    if current_version >= 19 and _encrypted_purge_column(connection) != (
                        "TEXT",
                        0,
                        None,
                        0,
                    ):
                        raise RuntimeError("ledger schema 19 deletion-work column is invalid")
                    if current_version >= 20 and work_schema != _expected_publication_work_schema():
                        raise RuntimeError("ledger schema 20 publication-work objects are invalid")
        except sqlite3.Error as error:
            raise RuntimeError("writable ledger schema is unavailable") from error
        observed = "uninitialized" if current_version is None else str(current_version)
        if self.allow_schema_upgrade and current_version in LEGACY_SCHEMA_UPGRADE_VERSIONS:
            return
        if current_version is not None and current_version > SCHEMA_VERSION:
            raise RuntimeError(
                f"ledger schema {current_version} is newer than supported {SCHEMA_VERSION}"
            )
        raise RuntimeError(
            f"writable ledger requires schema {SCHEMA_VERSION}; found {observed}; "
            "run an approved schema upgrade first"
        )

    def ingest(
        self,
        parsed: ParseResult,
        *,
        source_account: str,
        scope: Scope,
        project_id: str | None,
        source_path: str | None = None,
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
        legacy_fork_replay_source_file_id: str | None = None,
        exclusion_receipts: Sequence[ExclusionReceipt] = (),
        registered_client_id: str | None = None,
        registered_device_id: str | None = None,
        require_registered_source_account: bool = False,
        required_source_schema_provenance: SourceSchemaProvenance | None = None,
        web_export_observation: WebExportConversationObservation | None = None,
    ) -> IngestionReport:
        with self._publication_writer() as ledger:

            def admit() -> IngestionReport:
                if (
                    ledger._admission_transaction is not None
                    and ledger._admission_transaction.kind == "web_export"
                    and parsed.source_system
                    not in {
                        SourceSystem.CHATGPT_WEB,
                        SourceSystem.CLAUDE_WEB,
                        SourceSystem.GROK_WEB,
                    }
                ):
                    raise ValueError("web export transactions accept only guarded web imports")
                return ledger._ingest(
                    parsed,
                    source_account=source_account,
                    scope=scope,
                    project_id=project_id,
                    source_path=source_path,
                    max_record_bytes=max_record_bytes,
                    legacy_fork_replay_source_file_id=legacy_fork_replay_source_file_id,
                    exclusion_receipts=exclusion_receipts,
                    registered_client_id=registered_client_id,
                    registered_device_id=registered_device_id,
                    require_registered_source_account=require_registered_source_account,
                    required_source_schema_provenance=required_source_schema_provenance,
                    web_export_observation=web_export_observation,
                )

            return ledger._admit_and_publish(admit)

    def ingest_native_file(
        self,
        path: Path,
        source_system: SourceSystem,
        *,
        source_account: str,
        scope: Scope,
        project_id: str | None,
        source_path: str,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> tuple[IngestionReport, int]:
        """Retry one immutable input prefix; later appends belong to the next import."""
        self._require_writable()
        if self._admission_transaction is not None:
            raise RuntimeError("standalone file imports cannot nest inside admission")
        if source_system not in NATIVE_SOURCE_SYSTEMS:
            raise ValueError("standalone file imports require a native source")
        if (scope is Scope.PROJECT) != (project_id is not None) or (
            scope is Scope.PROJECT and not project_id
        ):
            raise ValueError("project scope requires a project id, other scopes forbid one")
        if not Path(source_path).is_absolute() or max_file_bytes <= 0:
            raise ValueError("file imports require an absolute source path and positive byte cap")
        path = Path(os.path.abspath(path.expanduser()))
        request = _sha256_text(
            json.dumps(
                (
                    "native-file-v1",
                    str(path),
                    source_path,
                    source_system.value,
                    source_account,
                    scope.value,
                    project_id,
                    max_file_bytes,
                )
            )
        )
        writer = self._exclusive_writer_token
        with (
            nullcontext(writer)
            if writer
            else exclusive_ledger_writer(self.settings, wait=not self._fail_fast_on_maintenance)
        ) as token:
            retained = load_attempt(self.settings.data_root, request)
            prefix = NativeFilePrefix(**retained["prefix"]) if retained is not None else None
            start = (0, 0, EMPTY_SHA256)
            if retained is not None:
                start = tuple(retained["start"])
            else:
                inspected = Ledger(
                    self.settings,
                    read_only=True,
                    require_checkpointed=False,
                    encrypted_evidence_reader=self._encrypted_evidence_reader,
                )
                cursor = inspected.source_cursor(
                    source_system,
                    source_account=source_account,
                    source_path=source_path,
                )
                if cursor is not None:
                    start = (
                        cursor.next_byte_offset,
                        cursor.next_record_ordinal,
                        cursor.prefix_digest,
                    )
            before = secure_path_stat(path, "native source")
            parsed = parse_file(
                path,
                source_system,
                max_file_bytes=max_file_bytes,
                retained_prefix=prefix,
                segment_start=start,
            )
            if prefix is None:
                after = secure_path_stat(path, "native source")
                if _stat_identity(before) != _stat_identity(after) or (
                    after.st_size,
                    after.st_mtime_ns,
                ) != (parsed.file_size, parsed.file_mtime_ns):
                    raise RuntimeError("native source changed before retaining its input boundary")
                prefix = NativeFilePrefix(
                    parsed.file_size,
                    parsed.file_digest,
                    parsed.file_mtime_ns,
                    after.st_dev,
                    after.st_ino,
                )
            write_scope = self._native_object_write_scope(
                parsed,
                operation=(
                    "native-file-v1",
                    request,
                    asdict(prefix),
                    start,
                    parsed.parser_name,
                    parsed.parser_version,
                ),
                max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
            )
            check_object_write_access(self.settings.data_root, write_scope)
            attempt = retain_attempt(self.settings.data_root, request, prefix, write_scope, start)
            ledger = Ledger(
                self.settings,
                exclusive_writer_token=token,
                object_write_scope=write_scope,
                encrypted_evidence_reader=self._encrypted_evidence_reader,
                encrypted_evidence_purger=self._encrypted_evidence_purger,
                evidence_publication_policy=self._evidence_publication_policy,
            )

            def admit() -> IngestionReport:
                with ledger._upload_transaction():
                    with ledger._object_write_transaction(set()) as connection:
                        ledger._start_object_write_attempt(connection)
                    report = ledger._ingest(
                        parsed,
                        source_account=source_account,
                        scope=scope,
                        project_id=project_id,
                        source_path=source_path,
                        retained_file_retry=retained is not None,
                    )
                ledger._finish_native_file_write_attempt(report.source_file_id)
                return report

            report = ledger._admit_and_publish(admit)
            finish_attempt(self.settings.data_root, attempt)
            return report, parsed.segment_end_byte

    def _finish_native_file_write_attempt(self, source_file_id: str) -> None:
        scope = self._object_write_scope
        if scope is None:
            raise RuntimeError("native file completion requires its exact write scope")
        with closing(self._connect()) as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM source_files WHERE source_file_id = ?",
                    (source_file_id,),
                ).fetchone()
                is None
            ):
                raise RuntimeError("object writes have no committed source file")
            with closing(ObjectWriteJournal(self.settings.data_root, scope)) as journal:
                journal.finish(self._registered_object_check(connection))

    def _admit_and_publish(
        self, admit: Callable[[], _AdmissionResult], *, max_publication_objects: int | None = None
    ) -> _AdmissionResult:
        transaction = self._admission_transaction
        if transaction is not None:
            transaction.require_active()
            try:
                return admit()
            except BaseException:
                transaction.failed = True
                raise
        if self._evidence_publication_policy is None:
            return admit()
        completed = 0
        try:
            result = admit()
        except EvidencePublicationPending:
            # A full queue must not prevent its own recovery on the next import.
            completed = self.drain_evidence_publications(max_objects=max_publication_objects)[
                "completed_objects"
            ]
            result = admit()
        remaining = None if max_publication_objects is None else max_publication_objects - completed
        try:
            self.drain_evidence_publications(max_objects=remaining)
        except EvidencePublicationYielded as error:
            raise EvidencePublicationYielded(completed + error.completed_objects) from None
        return result

    @contextmanager
    def _publication_writer(
        self, *, force_exclusive: bool = False, object_write_scope: ObjectWriteScope | None = None
    ) -> Generator[Ledger, None, None]:
        self._require_writable()
        token = self._exclusive_writer_token
        if (
            self._evidence_publication_policy is None
            and not force_exclusive
            and object_write_scope is None
        ) or (
            token is not None
            and (object_write_scope is None or object_write_scope == self._object_write_scope)
        ):
            yield self
            return
        if self._admission_transaction is not None or self._object_write_scope is not None:
            raise RuntimeError("object write scope differs from the active writer")
        with (
            nullcontext(token)
            if token
            else exclusive_ledger_writer(self.settings, wait=not self._fail_fast_on_maintenance)
        ) as token:
            yield Ledger(
                self.settings,
                exclusive_writer_token=token,
                encrypted_evidence_reader=self._encrypted_evidence_reader,
                encrypted_evidence_purger=self._encrypted_evidence_purger,
                evidence_publication_policy=self._evidence_publication_policy,
                object_write_scope=object_write_scope,
            )

    def _ingest(
        self,
        parsed: ParseResult,
        *,
        source_account: str,
        scope: Scope,
        project_id: str | None,
        source_path: str | None = None,
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
        legacy_fork_replay_source_file_id: str | None = None,
        exclusion_receipts: Sequence[ExclusionReceipt] = (),
        registered_client_id: str | None = None,
        registered_device_id: str | None = None,
        require_registered_source_account: bool = False,
        required_source_schema_provenance: SourceSchemaProvenance | None = None,
        web_export_observation: WebExportConversationObservation | None = None,
        retained_file_retry: bool = False,
    ) -> IngestionReport:
        self._require_writable()
        if retained_file_retry and (
            self._object_write_scope is None
            or self._admission_transaction is None
            or self._admission_transaction.kind != "native_upload"
            or parsed.source_system not in NATIVE_SOURCE_SYSTEMS
        ):
            raise RuntimeError("retained file replay requires its scoped native transaction")
        is_web_source = parsed.source_system in {
            SourceSystem.CHATGPT_WEB,
            SourceSystem.CLAUDE_WEB,
            SourceSystem.GROK_WEB,
        }
        if is_web_source and (
            not require_registered_source_account
            or required_source_schema_provenance is None
            or web_export_observation is None
        ):
            raise PermissionError(
                "web sources require the guarded export workflow, exact schema authorization, "
                "and archive observation"
            )
        if not is_web_source and web_export_observation is not None:
            raise ValueError("web export observations apply only to web source systems")
        if (registered_client_id is None) != (registered_device_id is None):
            raise ValueError("registered client and device ids must be provided together")
        if require_registered_source_account and registered_client_id is not None:
            raise ValueError(
                "registered source-account ingestion cannot also name a collector client"
            )
        if required_source_schema_provenance is not None and not require_registered_source_account:
            raise ValueError(
                "source schema authorization requires registered source-account ingestion"
            )
        if scope is Scope.PROJECT and not project_id:
            raise ValueError("project_id is required for project-scoped ingestion")
        if scope is not Scope.PROJECT and project_id is not None:
            raise ValueError("only project-scoped ingestion may carry project_id")
        if (
            parsed.segment_start_ordinal < 0
            or parsed.segment_start_byte < 0
            or parsed.segment_end_ordinal_exclusive < parsed.segment_start_ordinal
            or parsed.segment_end_byte < parsed.segment_start_byte
        ):
            raise ValueError("parsed source segment boundaries are invalid")
        if parsed.end_prefix_digest != parsed.file_digest:
            raise ValueError("parsed source digest must match the consumed prefix digest")
        _validate_exclusion_receipts(parsed, exclusion_receipts)
        logical_source_path = source_path or str(parsed.path)
        if not Path(logical_source_path).is_absolute():
            raise ValueError("source_path must be absolute")
        path_hash = _sha256_text(logical_source_path)
        source_stream_id = _stable_id(
            "source_stream",
            parsed.source_system.value,
            source_account,
            path_hash,
        )
        source_file_id = _stable_id(
            "source_segment",
            source_stream_id,
            str(parsed.segment_start_ordinal),
            str(parsed.segment_start_byte),
            str(parsed.segment_end_ordinal_exclusive),
            str(parsed.segment_end_byte),
            parsed.end_prefix_digest,
            parsed.parser_version,
        )
        now = _now()
        history = parsed.history_base
        normalized_web_observation = (
            _normalized_web_export_observation(web_export_observation)
            if web_export_observation is not None
            else None
        )

        created_object_paths: set[Path] = set()
        with self._object_write_transaction(created_object_paths) as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN IMMEDIATE")
            installation_id = _ensure_installation(connection, now)
            _require_not_tombstoned(
                connection,
                source_system=parsed.source_system,
                source_account=source_account,
                conversation_id=parsed.conversation_id,
            )
            schema_authorization_id: str | None = None
            if require_registered_source_account:
                _require_registered_source_account(
                    connection,
                    installation_id=installation_id,
                    source_account_id=source_account,
                    source_system=parsed.source_system,
                    scope=scope,
                    project_id=project_id,
                )
                if required_source_schema_provenance is not None:
                    schema_authorization_id, _, _ = _require_active_source_schema_authorization(
                        connection,
                        source_account_id=source_account,
                        source_system=parsed.source_system,
                        provenance=required_source_schema_provenance,
                    )
            elif registered_client_id is None or registered_device_id is None:
                device_id = _ensure_legacy_device(connection, installation_id, now)
                _ensure_source_account(
                    connection,
                    installation_id=installation_id,
                    device_id=device_id,
                    source_system=parsed.source_system.value,
                    legacy_account_key=source_account,
                    now=now,
                )
            else:
                _require_registered_upload_identity(
                    connection,
                    installation_id=installation_id,
                    client_id=registered_client_id,
                    device_id=registered_device_id,
                    source_account_id=source_account,
                    source_system=parsed.source_system,
                    scope=scope,
                    project_id=project_id,
                )
            web_export_source_object_id: str | None = None
            if normalized_web_observation is not None:
                if schema_authorization_id is None or required_source_schema_provenance is None:
                    raise RuntimeError("web export schema authorization was not verified")
                web_export_source_object_id = self._register_web_export_source_object(
                    connection,
                    batch_id=normalized_web_observation.batch_id,
                    object_kind="conversation_split",
                    conversation_index=normalized_web_observation.conversation_index,
                    source_path=parsed.path,
                    expected_sha256=normalized_web_observation.conversation_sha256,
                    expected_byte_length=parsed.file_size,
                    media_type="application/json",
                    conversation_id=parsed.conversation_id,
                    branch_id=parsed.branch_id,
                    captured_at=parsed.captured_at,
                    parser_name=parsed.parser_name,
                    parser_version=parsed.parser_version,
                    schema_fingerprint=required_source_schema_provenance.schema_fingerprint,
                    created_at=now,
                )
            stream = connection.execute(
                """
                SELECT conversation_id, branch_id, parent_conversation_id,
                       source_kind, source_label, scope, project_id, parser_name
                FROM source_streams
                WHERE source_stream_id = ?
                """,
                (source_stream_id,),
            ).fetchone()
            if stream is not None and legacy_fork_replay_source_file_id is not None:
                raise RuntimeError("legacy fork replay cannot target a registered source stream")
            if stream is None:
                if legacy_fork_replay_source_file_id is not None:
                    _validate_legacy_fork_replay(
                        connection,
                        parsed,
                        source_file_id=legacy_fork_replay_source_file_id,
                        source_account=source_account,
                        source_path_hash=path_hash,
                    )
                else:
                    legacy = connection.execute(
                        """
                        SELECT legacy.file_size, legacy.file_digest
                        FROM source_files legacy
                        LEFT JOIN source_segments segment
                          ON segment.source_file_id = legacy.source_file_id
                        WHERE legacy.source_system = ?
                          AND legacy.source_account = ?
                          AND legacy.source_path_hash = ?
                          AND segment.source_file_id IS NULL
                        ORDER BY legacy.file_size DESC, legacy.ingested_at DESC
                        LIMIT 1
                        """,
                        (parsed.source_system.value, source_account, path_hash),
                    ).fetchone()
                    if legacy is not None and (
                        parsed.segment_start_byte != cast(int, legacy[0])
                        or parsed.start_prefix_digest != cast(str, legacy[1])
                    ):
                        raise RuntimeError(
                            "legacy source requires an explicit append boundary at its latest "
                            "admitted size and digest"
                        )
                connection.execute(
                    """
                    INSERT INTO source_streams(
                      source_stream_id, source_system, source_account, source_path,
                      source_path_hash, conversation_id, branch_id,
                      parent_conversation_id, source_kind, source_label, scope,
                      project_id, initial_record_ordinal, initial_byte_offset,
                      initial_prefix_digest, parser_name, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_stream_id,
                        parsed.source_system.value,
                        source_account,
                        logical_source_path,
                        path_hash,
                        parsed.conversation_id,
                        parsed.branch_id,
                        parsed.parent_conversation_id,
                        parsed.source_kind.value,
                        parsed.source_label,
                        scope.value,
                        project_id,
                        parsed.segment_start_ordinal,
                        parsed.segment_start_byte,
                        parsed.start_prefix_digest,
                        parsed.parser_name,
                        now,
                        now,
                    ),
                )
            elif tuple(stream) != (
                parsed.conversation_id,
                parsed.branch_id,
                parsed.parent_conversation_id,
                parsed.source_kind.value,
                parsed.source_label,
                scope.value,
                project_id,
                parsed.parser_name,
            ):
                raise RuntimeError("source metadata or scope changed after stream registration")

            _sync_legacy_access(
                connection,
                table="source_stream_access",
                id_column="source_stream_id",
                entity_id=source_stream_id,
                scope=scope.value,
                now=now,
            )
            _sync_legacy_context(
                connection,
                table="source_stream_contexts",
                id_column="source_stream_id",
                entity_id=source_stream_id,
                installation_id=installation_id,
                project_id=project_id,
                now=now,
            )

            committed_file = (
                connection.execute(
                    "SELECT source_file_id FROM source_files WHERE source_file_id = ?",
                    (source_file_id,),
                ).fetchone()
                if retained_file_retry
                else None
            )
            cursor = connection.execute(
                """
                SELECT next_record_ordinal, next_byte_offset, prefix_digest,
                       last_source_file_id
                FROM source_cursors
                WHERE source_stream_id = ?
                """,
                (source_stream_id,),
            ).fetchone()
            if cursor is not None and committed_file is None:
                cursor_ordinal = cast(int, cursor[0])
                cursor_byte = cast(int, cursor[1])
                cursor_digest = cast(str, cursor[2])
                if (
                    parsed.segment_end_ordinal_exclusive == cursor_ordinal
                    and parsed.segment_end_byte == cursor_byte
                    and parsed.end_prefix_digest == cursor_digest
                ):
                    source_file_id = cast(str, cursor[3])
                elif parsed.segment_start_byte < cursor_byte:
                    raise RuntimeError("parsed source segment overlaps the registered cursor")
                elif parsed.segment_start_byte > cursor_byte:
                    raise SourceCursorGap(
                        SourceCursor(
                            source_stream_id=source_stream_id,
                            conversation_id=parsed.conversation_id,
                            source_kind=parsed.source_kind,
                            next_record_ordinal=cursor_ordinal,
                            next_byte_offset=cursor_byte,
                            prefix_digest=cursor_digest,
                        )
                    )
                elif (
                    parsed.segment_start_ordinal != cursor_ordinal
                    or parsed.start_prefix_digest != cursor_digest
                ):
                    raise RuntimeError("parsed source segment does not match the registered cursor")

            existing = connection.execute(
                "SELECT source_file_id FROM source_files WHERE source_file_id = ?",
                (source_file_id,),
            ).fetchone()
            if existing is not None:
                if normalized_web_observation is not None:
                    if schema_authorization_id is None or web_export_source_object_id is None:
                        raise RuntimeError("web export schema authorization was not verified")
                    _record_web_export_conversation_observation(
                        connection,
                        source_file_id=source_file_id,
                        source_account_id=source_account,
                        source_system=parsed.source_system,
                        authorization_id=schema_authorization_id,
                        parsed=parsed,
                        source_object_id=web_export_source_object_id,
                        observation=normalized_web_observation,
                        created_at=now,
                    )
                if normalized_web_observation is not None:
                    event_count = cast(
                        int,
                        connection.execute(
                            """
                            SELECT COUNT(*)
                            FROM web_export_event_observations observation
                            JOIN source_records record
                              ON record.source_record_id = observation.source_record_id
                            WHERE record.source_file_id = ?
                            """,
                            (source_file_id,),
                        ).fetchone()[0],
                    )
                else:
                    event_count = cast(
                        int,
                        connection.execute(
                            """
                            SELECT COUNT(*)
                            FROM events e
                            JOIN source_records sr ON sr.source_record_id = e.source_record_id
                            WHERE sr.source_file_id = ?
                            """,
                            (source_file_id,),
                        ).fetchone()[0],
                    )
                quarantine_rows = connection.execute(
                    """
                    SELECT reason, COUNT(*)
                    FROM quarantines
                    WHERE source_file_id = ?
                    GROUP BY reason
                    """,
                    (source_file_id,),
                ).fetchall()
                reasons = {cast(str, row[0]): cast(int, row[1]) for row in quarantine_rows}
                self._queue_source_evidence_publication(connection, source_file_id)
                return IngestionReport(
                    source_file_id=source_file_id,
                    source_system=parsed.source_system,
                    conversation_id=parsed.conversation_id,
                    status="already_ingested",
                    inserted_events=0,
                    existing_events=event_count,
                    quarantined_records=sum(reasons.values()),
                    quarantine_reasons=reasons,
                )

            connection.execute(
                """
                INSERT INTO source_files(
                  source_file_id, source_system, source_account, source_path,
                  source_path_hash, file_digest, file_size, file_mtime_ns,
                  conversation_id, branch_id, captured_at, ingested_at,
                  parser_name, parser_version, history_base_thread_id,
                  history_base_end_ordinal, history_base_end_byte_offset,
                  unknown_record_types_json, malformed_records, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_file_id,
                    parsed.source_system.value,
                    source_account,
                    logical_source_path,
                    path_hash,
                    parsed.end_prefix_digest,
                    parsed.segment_end_byte,
                    parsed.file_mtime_ns,
                    parsed.conversation_id,
                    parsed.branch_id,
                    parsed.captured_at,
                    now,
                    parsed.parser_name,
                    parsed.parser_version,
                    history.thread_id if history else None,
                    history.end_ordinal_exclusive if history else None,
                    history.end_byte_offset if history else None,
                    json.dumps(parsed.unknown_record_types),
                    parsed.malformed_records,
                    "ingested_segment",
                ),
            )
            connection.execute(
                """
                INSERT INTO source_segments(
                  source_file_id, source_stream_id, start_record_ordinal,
                  start_byte_offset, end_record_ordinal, end_byte_offset,
                  start_prefix_digest, end_prefix_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_file_id,
                    source_stream_id,
                    parsed.segment_start_ordinal,
                    parsed.segment_start_byte,
                    parsed.segment_end_ordinal_exclusive,
                    parsed.segment_end_byte,
                    parsed.start_prefix_digest,
                    parsed.end_prefix_digest,
                ),
            )
            if normalized_web_observation is not None:
                if schema_authorization_id is None or web_export_source_object_id is None:
                    raise RuntimeError("web export schema authorization was not verified")
                _record_web_export_conversation_observation(
                    connection,
                    source_file_id=source_file_id,
                    source_account_id=source_account,
                    source_system=parsed.source_system,
                    authorization_id=schema_authorization_id,
                    parsed=parsed,
                    source_object_id=web_export_source_object_id,
                    observation=normalized_web_observation,
                    created_at=now,
                )

            inserted = 0
            existing_events = 0
            quarantine_reasons: Counter[str] = Counter()
            for receipt in exclusion_receipts:
                quarantine_reasons[receipt.reason] += 1
                connection.execute(
                    """
                    INSERT INTO quarantines(
                      quarantine_id, source_file_id, record_ordinal,
                      byte_start, byte_end, reason, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        _stable_id(
                            "quarantine",
                            source_stream_id,
                            str(receipt.record_ordinal),
                            receipt.reason,
                        ),
                        source_file_id,
                        receipt.record_ordinal,
                        receipt.byte_start,
                        receipt.byte_end,
                        receipt.reason,
                        now,
                    ),
                )
            for record in parsed.records:
                erased = _record_is_erased(
                    connection,
                    source_system=parsed.source_system,
                    source_account=source_account,
                    conversation_id=parsed.conversation_id,
                    raw_digest=hashlib.sha256(record.raw_record).hexdigest(),
                    message_id=record.message_id,
                    message_id_kind=record.message_id_kind,
                )
                decision = classify_record(
                    parsed.source_system,
                    record.content_text,
                    record.raw_record,
                    max_record_bytes=max_record_bytes,
                )
                if erased or not decision.accepted:
                    exclusion_reason = (
                        "no_memory_tombstone" if decision.accepted else decision.reason
                    )
                    if registered_client_id is not None and not decision.accepted:
                        raise ValueError(
                            f"uploaded admitted record failed node admission: {decision.reason}"
                        )
                    quarantine_reasons[exclusion_reason] += 1
                    connection.execute(
                        """
                        INSERT INTO quarantines(
                          quarantine_id, source_file_id, record_ordinal,
                          byte_start, byte_end, reason, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            _stable_id(
                                "quarantine",
                                source_stream_id,
                                str(record.record_ordinal),
                                exclusion_reason,
                            ),
                            source_file_id,
                            record.record_ordinal,
                            record.byte_start,
                            record.byte_end,
                            exclusion_reason,
                            now,
                        ),
                    )
                    continue

                _require_object_not_pending_deletion(
                    connection, f"sha256:{hashlib.sha256(record.raw_record).hexdigest()}"
                )
                object_id, object_path = self._store_object(
                    record.raw_record,
                    connection=connection,
                    created_object_paths=created_object_paths,
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO objects(
                      object_id, plaintext_digest, byte_length, media_type,
                      object_path, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        object_id,
                        object_id.removeprefix("sha256:"),
                        len(record.raw_record),
                        _record_media_type(parsed.source_system),
                        object_path,
                        now,
                    ),
                )
                self._queue_evidence_publication(
                    connection,
                    object_id,
                    newly_created=self.settings.data_root / object_path in created_object_paths,
                )
                source_record_id = _stable_id(
                    "source_record", source_stream_id, str(record.record_ordinal), object_id
                )
                connection.execute(
                    """
                    INSERT INTO source_records(
                      source_record_id, source_file_id, object_id, record_ordinal,
                      byte_start, byte_end, message_id, parent_message_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_record_id,
                        source_file_id,
                        object_id,
                        record.record_ordinal,
                        record.byte_start,
                        record.byte_end,
                        record.message_id,
                        record.parent_message_id,
                    ),
                )
                branch_id = record.branch_id or parsed.branch_id
                content_digest = _sha256_text(record.content_text)
                family_key = (
                    _web_export_family_key(
                        source_account_id=source_account,
                        source_system=parsed.source_system,
                        conversation_id=parsed.conversation_id,
                        message_id=record.message_id,
                        message_id_kind=record.message_id_kind,
                    )
                    if web_export_observation is not None
                    and record.message_id is not None
                    and record.message_id_kind == "provider_message_id"
                    else None
                )
                reconciliation_key = (
                    _web_export_reconciliation_key(
                        family_key=family_key,
                        source_account_id=source_account,
                        source_system=parsed.source_system,
                        conversation_id=parsed.conversation_id,
                        message_id=record.message_id,
                        message_id_kind=record.message_id_kind,
                        parent_message_id=record.parent_message_id,
                        branch_id=branch_id,
                        object_id=object_id,
                        event_type=record.event_type,
                        actor_kind=record.actor_kind,
                        assistant=record.assistant,
                        authority=record.authority.value,
                        occurred_at=record.occurred_at,
                        scope=scope.value,
                        project_id=project_id,
                        privacy=decision.privacy.value,
                        content_digest=content_digest,
                    )
                    if family_key is not None
                    else None
                )
                reconciled_event_id = None
                if reconciliation_key is not None:
                    reconciled_event_id = _find_matching_web_export_event(
                        connection,
                        reconciliation_key=reconciliation_key,
                        family_key=family_key,
                        source_account_id=source_account,
                        source_system=parsed.source_system,
                        conversation_id=parsed.conversation_id,
                        message_id=record.message_id,
                        message_id_kind=record.message_id_kind,
                        parent_message_id=record.parent_message_id,
                        branch_id=branch_id,
                        object_id=object_id,
                        event_type=record.event_type,
                        actor_kind=record.actor_kind,
                        assistant=record.assistant,
                        authority=record.authority.value,
                        occurred_at=record.occurred_at,
                        scope=scope.value,
                        project_id=project_id,
                        privacy=decision.privacy.value,
                        content_digest=content_digest,
                    )
                if reconciled_event_id is not None:
                    connection.execute(
                        """
                        INSERT INTO web_export_event_observations(
                          source_record_id, event_id, reconciliation_key, created_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            source_record_id,
                            reconciled_event_id,
                            reconciliation_key,
                            now,
                        ),
                    )
                    if (
                        reconciliation_key is None
                        or family_key is None
                        or record.message_id is None
                    ):
                        raise RuntimeError("web export reconciliation identity is missing")
                    _reconcile_pending_memory_claims_for_event(
                        connection,
                        event_id=reconciled_event_id,
                        reconciliation_key=reconciliation_key,
                        source_account_id=source_account,
                        source_system=parsed.source_system,
                        family_key=family_key,
                        conversation_id=parsed.conversation_id,
                        message_id=record.message_id,
                        parent_message_id=record.parent_message_id,
                        branch_id=branch_id,
                        content_digest=content_digest,
                        scope=scope,
                        project_id=project_id,
                        created_at=now,
                    )
                    existing_events += 1
                    continue

                event_id = _stable_id("event", source_record_id)
                connection.execute(
                    """
                    INSERT INTO events(
                      event_id, source_record_id, event_type, actor_kind, assistant,
                      authority, conversation_id, branch_id, occurred_at, mentioned_at,
                      ingested_at, scope, project_id, privacy, content_digest,
                      content_text, parser_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        source_record_id,
                        record.event_type,
                        record.actor_kind,
                        record.assistant,
                        record.authority.value,
                        parsed.conversation_id,
                        branch_id,
                        record.occurred_at,
                        record.occurred_at,
                        now,
                        scope.value,
                        project_id,
                        decision.privacy.value,
                        content_digest,
                        record.content_text,
                        parsed.parser_version,
                    ),
                )
                _reconcile_runtime_prompt_authority(
                    connection, parsed, record, event_id=event_id, created_at=now
                )
                connection.execute(
                    "INSERT INTO events_fts(event_id, content_text) VALUES (?, ?)",
                    (event_id, record.content_text),
                )
                _sync_legacy_access(
                    connection,
                    table="event_access",
                    id_column="event_id",
                    entity_id=event_id,
                    scope=scope.value,
                    now=now,
                )
                _sync_legacy_context(
                    connection,
                    table="event_contexts",
                    id_column="event_id",
                    entity_id=event_id,
                    installation_id=installation_id,
                    project_id=project_id,
                    now=now,
                )
                if web_export_observation is not None:
                    if reconciliation_key is not None:
                        if (
                            family_key is None
                            or record.message_id is None
                            or record.message_id_kind is None
                        ):
                            raise RuntimeError("web export reconciliation family is missing")
                        connection.execute(
                            """
                            INSERT INTO web_export_reconciled_events(
                              reconciliation_key, event_id, family_key, source_account_id,
                              source_system, conversation_id, message_id, message_id_kind,
                              parent_message_id, branch_id, object_id, event_type, actor_kind,
                              assistant, authority, occurred_at, scope, project_id, privacy,
                              content_digest, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                reconciliation_key,
                                event_id,
                                family_key,
                                source_account,
                                parsed.source_system.value,
                                parsed.conversation_id,
                                record.message_id,
                                record.message_id_kind,
                                record.parent_message_id,
                                branch_id,
                                object_id,
                                record.event_type,
                                record.actor_kind,
                                record.assistant,
                                record.authority.value,
                                record.occurred_at,
                                scope.value,
                                project_id,
                                decision.privacy.value,
                                content_digest,
                                now,
                            ),
                        )
                        _reconcile_pending_memory_claims_for_event(
                            connection,
                            event_id=event_id,
                            reconciliation_key=reconciliation_key,
                            source_account_id=source_account,
                            source_system=parsed.source_system,
                            family_key=family_key,
                            conversation_id=parsed.conversation_id,
                            message_id=record.message_id,
                            parent_message_id=record.parent_message_id,
                            branch_id=branch_id,
                            content_digest=content_digest,
                            scope=scope,
                            project_id=project_id,
                            created_at=now,
                        )
                        for prior in connection.execute(
                            """
                            SELECT event_id
                            FROM web_export_reconciled_events
                            WHERE family_key = ? AND event_id != ?
                            ORDER BY event_id
                            """,
                            (family_key, event_id),
                        ):
                            prior_event_id = cast(str, prior[0])
                            connection.execute(
                                """
                                INSERT OR IGNORE INTO event_relations(
                                  relation_id, from_event_id, to_event_id, relation_type,
                                  basis, created_at
                                ) VALUES (?, ?, ?, 'source_variant', ?, ?)
                                """,
                                (
                                    _stable_id(
                                        "event_relation",
                                        prior_event_id,
                                        event_id,
                                        "source_variant",
                                    ),
                                    prior_event_id,
                                    event_id,
                                    "same certified provider message id with changed "
                                    "exact evidence",
                                    now,
                                ),
                            )
                    connection.execute(
                        """
                        INSERT INTO web_export_event_observations(
                          source_record_id, event_id, reconciliation_key, created_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (source_record_id, event_id, reconciliation_key, now),
                    )
                inserted += 1

            connection.execute(
                """
                INSERT INTO source_cursors(
                  source_stream_id, next_record_ordinal, next_byte_offset,
                  prefix_digest, last_source_file_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_stream_id) DO UPDATE SET
                  next_record_ordinal = excluded.next_record_ordinal,
                  next_byte_offset = excluded.next_byte_offset,
                  prefix_digest = excluded.prefix_digest,
                  last_source_file_id = excluded.last_source_file_id,
                  updated_at = excluded.updated_at
                """,
                (
                    source_stream_id,
                    parsed.segment_end_ordinal_exclusive,
                    parsed.segment_end_byte,
                    parsed.end_prefix_digest,
                    source_file_id,
                    now,
                ),
            )
            connection.execute(
                "UPDATE source_streams SET updated_at = ? WHERE source_stream_id = ?",
                (now, source_stream_id),
            )

        return IngestionReport(
            source_file_id=source_file_id,
            source_system=parsed.source_system,
            conversation_id=parsed.conversation_id,
            status="ingested",
            inserted_events=inserted,
            existing_events=existing_events,
            quarantined_records=sum(quarantine_reasons.values()),
            quarantine_reasons=dict(quarantine_reasons),
        )

    def search(
        self,
        query: str,
        *,
        mode: QueryMode = QueryMode.FIND_EVIDENCE,
        scopes: Sequence[Scope] = (Scope.USER_GLOBAL, Scope.PROJECT),
        project_id: str | None = None,
        authorities: Sequence[Authority] | None = None,
        accesses: Sequence[Access] | None = None,
        limit: int = 5,
        principal: str = "local:cli",
    ) -> list[SearchResult]:
        started = time.perf_counter()
        if mode not in SUPPORTED_QUERY_MODES:
            raise ValueError(f"query mode is not implemented in the lexical baseline: {mode.value}")
        if mode is QueryMode.WHERE_DID_I_LEAVE_OFF:
            return self._continuity_evidence(
                project_id=project_id,
                scopes=scopes,
                authorities=authorities,
                accesses=accesses,
                limit=limit,
                principal=principal,
                started=started,
            )
        fts_query = _fts_query(query)
        if not fts_query:
            raise ValueError("query must contain at least one searchable token")
        limit = max(1, min(limit, MAX_QUERY_RESULTS))
        effective_authorities = list(authorities or ())
        if mode in (QueryMode.WHAT_DID_I_SAY, QueryMode.WHAT_DID_I_THINK):
            effective_authorities = [Authority.USER_ASSERTION]
        if not scopes:
            raise ValueError("at least one scope is required")

        scope_placeholders = ",".join("?" for _ in scopes)
        predicates = [
            "events_fts MATCH ?",
            "e.privacy = 'included'",
            f"e.scope IN ({scope_placeholders})",
        ]
        parameters: list[object] = [fts_query, *(scope.value for scope in scopes)]
        if project_id:
            predicates.append("(e.scope != 'project' OR e.project_id = ?)")
            parameters.append(project_id)
        else:
            predicates.append("e.scope != 'project'")
        if effective_authorities:
            authority_placeholders = ",".join("?" for _ in effective_authorities)
            predicates.append(f"e.authority IN ({authority_placeholders})")
            parameters.extend(item.value for item in effective_authorities)
        if accesses:
            access_placeholders = ",".join("?" for _ in accesses)
            predicates.append(f"ea.access IN ({access_placeholders})")
            parameters.extend(item.value for item in accesses)
        parameters.append(limit)

        sql = f"""
        SELECT
          e.event_id,
          substr(e.content_text, 1, 4000) AS content_text,
          e.event_type,
          e.actor_kind,
          e.assistant,
          e.authority,
          e.scope,
          e.project_id,
          e.conversation_id,
          e.branch_id,
          e.occurred_at,
          sf.source_system,
          sr.object_id,
          sr.record_ordinal,
          sr.byte_start,
          sr.byte_end,
          bm25(events_fts) AS score,
          e.correction_id,
          e.corrected_at
        FROM events_fts
        JOIN events_current e ON e.event_id = events_fts.event_id
        JOIN event_access ea ON ea.event_id = e.event_id
        JOIN source_records sr ON sr.source_record_id = e.source_record_id
        JOIN source_files sf ON sf.source_file_id = sr.source_file_id
        WHERE {" AND ".join(predicates)}
        ORDER BY score ASC, e.occurred_at DESC, e.event_id ASC
        LIMIT ?
        """
        with closing(self._connect()) as connection:
            rows = connection.execute(sql, parameters).fetchall()
            results = [_search_result(row) for row in rows]
            latency_ms = (time.perf_counter() - started) * 1000
            self._record_query_receipt(
                connection,
                mode=mode,
                query=query,
                principal=principal,
                filters={
                    "scopes": [scope.value for scope in scopes],
                    "project_id": project_id,
                    "access": sorted(
                        item.value
                        for item in (
                            accesses
                            or tuple(_access_from_legacy_scope(scope.value) for scope in scopes)
                        )
                    ),
                    "contexts": (
                        [{"kind": ContextKind.PROJECT.value, "key": project_id}]
                        if project_id
                        else []
                    ),
                    "authorities": [item.value for item in effective_authorities],
                    "limit": limit,
                },
                results=results,
                omitted_counts={},
                latency_ms=latency_ms,
            )
        return results

    def retrieve_workset(
        self,
        query: str,
        *,
        mode: QueryMode = QueryMode.FIND_EVIDENCE,
        scopes: Sequence[Scope] = (Scope.USER_GLOBAL, Scope.PROJECT),
        contexts: Sequence[ContextFilter] = (),
        project_id: str | None = None,
        authorities: Sequence[Authority] | None = None,
        accesses: Sequence[Access] | None = None,
        limit: int = 5,
        control: RetrievalControl = RetrievalControl.AUTO,
        principal: str = "local:cli",
    ) -> dict[str, Any]:
        started = time.perf_counter()
        if control is RetrievalControl.SUPPRESS:
            raise ValueError("suppressed retrieval must not open the ledger")
        policy = _workset_policy(
            mode=mode,
            scopes=scopes,
            contexts=contexts,
            project_id=project_id,
            authorities=authorities,
            accesses=accesses,
        )

        per_source_candidate_limit = MAX_WORKSET_CANDIDATES
        candidate_pool_limit = per_source_candidate_limit * len(SourceSystem)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            if mode is QueryMode.WHERE_DID_I_LEAVE_OFF:
                rows = connection.execute(
                    f"""
                    WITH eligible_recent AS (
                      SELECT {_WORKSET_SELECT_COLUMNS}, 0.0 AS score,
                             e.correction_id, e.corrected_at,
                             COALESCE(e.occurred_at, e.ingested_at) AS ordering_at,
                             ROW_NUMBER() OVER (
                               PARTITION BY sf.source_system
                               ORDER BY COALESCE(e.occurred_at, e.ingested_at) DESC,
                                        sr.record_ordinal DESC,
                                        e.event_id DESC
                             ) AS source_rank,
                             COUNT(*) OVER () AS match_count
                      {_WORKSET_JOINS}
                      WHERE {" AND ".join(policy.predicates)}
                    )
                    SELECT {_WORKSET_RESULT_COLUMNS}, match_count
                    FROM eligible_recent
                    WHERE source_rank <= ?
                    ORDER BY ordering_at DESC, record_ordinal DESC, event_id DESC
                    LIMIT ?
                    """,
                    (*policy.parameters, per_source_candidate_limit, candidate_pool_limit),
                ).fetchall()
            else:
                fts_query = _fts_query(query)
                if not fts_query:
                    raise ValueError("query must contain at least one searchable token")
                rows = connection.execute(
                    f"""
                    WITH eligible_matches AS (
                      SELECT {_WORKSET_SELECT_COLUMNS},
                             -cam_lexical_score(?, e.content_text) AS score,
                             e.correction_id, e.corrected_at,
                             COALESCE(e.occurred_at, e.ingested_at) AS ordering_at
                      FROM events_fts
                      JOIN events_current e ON e.event_id = events_fts.event_id
                      JOIN event_access ea ON ea.event_id = e.event_id
                      JOIN source_records sr ON sr.source_record_id = e.source_record_id
                      JOIN source_files sf ON sf.source_file_id = sr.source_file_id
                      WHERE events_fts MATCH ? AND {" AND ".join(policy.predicates)}
                    ),
                    ranked_matches AS (
                      SELECT *,
                             ROW_NUMBER() OVER (
                               PARTITION BY source_system
                               ORDER BY score ASC, ordering_at DESC, event_id ASC
                             ) AS source_rank,
                             COUNT(*) OVER () AS match_count
                      FROM eligible_matches
                    )
                    SELECT {_WORKSET_RESULT_COLUMNS}, match_count
                    FROM ranked_matches
                    WHERE source_rank <= ?
                    ORDER BY score ASC, ordering_at DESC, event_id ASC
                    LIMIT ?
                    """,
                    (
                        query,
                        fts_query,
                        *policy.parameters,
                        per_source_candidate_limit,
                        candidate_pool_limit,
                    ),
                ).fetchall()
            candidate_match_count = cast(int, rows[0][19]) if rows else 0
            candidate_results = [_search_result(row) for row in rows]
            return self._finish_retrieval_workset(
                connection,
                started=started,
                mode=mode,
                query=query,
                principal=principal,
                policy=policy,
                candidate_id=FTS_WORKSET_CANDIDATE_ID,
                candidate_results=candidate_results,
                candidate_input_count=len(candidate_results),
                candidate_match_count=candidate_match_count,
                candidate_ranks=None,
                policy_filtered_candidate_count=0,
                limit=limit,
                control=control,
            )

    def retrieve_ranked_workset(
        self,
        query: str,
        *,
        candidates: Sequence[RetrievalCandidate],
        candidate_id: str,
        candidate_match_count: int | None = None,
        mode: QueryMode = QueryMode.FIND_EVIDENCE,
        scopes: Sequence[Scope] = (Scope.USER_GLOBAL, Scope.PROJECT),
        contexts: Sequence[ContextFilter] = (),
        project_id: str | None = None,
        authorities: Sequence[Authority] | None = None,
        accesses: Sequence[Access] | None = None,
        limit: int = 5,
        control: RetrievalControl = RetrievalControl.AUTO,
        principal: str = "local:ranked-candidate",
    ) -> dict[str, Any]:
        started = time.perf_counter()
        if control is RetrievalControl.SUPPRESS:
            raise ValueError("suppressed retrieval must not open the ledger")
        normalized_candidate_id = candidate_id.strip()
        if not normalized_candidate_id or len(normalized_candidate_id.encode("utf-8")) > 128:
            raise ValueError("candidate id must contain between 1 and 128 bytes")
        candidate_values = tuple(candidates)
        max_candidates = MAX_WORKSET_CANDIDATES * len(SourceSystem)
        if len(candidate_values) > max_candidates:
            raise ValueError(
                f"ranked candidate input exceeds the bounded limit of {max_candidates}"
            )
        candidate_ids = [item.event_id for item in candidate_values]
        if len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError("ranked candidates must have unique event ids")
        if any(
            candidate_values[index].score < candidate_values[index + 1].score
            for index in range(len(candidate_values) - 1)
        ):
            raise ValueError("ranked candidates must be ordered by descending score")
        policy = _workset_policy(
            mode=mode,
            scopes=scopes,
            contexts=contexts,
            project_id=project_id,
            authorities=authorities,
            accesses=accesses,
        )
        candidate_ranks = {
            candidate.event_id: index for index, candidate in enumerate(candidate_values, start=1)
        }

        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            rows: list[sqlite3.Row] = []
            chunk_size = max(1, 900 - len(policy.parameters))
            for offset in range(0, len(candidate_ids), chunk_size):
                chunk = candidate_ids[offset : offset + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                rows.extend(
                    connection.execute(
                        f"""
                        SELECT {_WORKSET_SELECT_COLUMNS}, 0.0 AS score,
                               e.correction_id, e.corrected_at
                        {_WORKSET_JOINS}
                        WHERE e.event_id IN ({placeholders})
                          AND {" AND ".join(policy.predicates)}
                        """,
                        (*chunk, *policy.parameters),
                    ).fetchall()
                )
            eligible_by_id = {cast(str, row[0]): _search_result(row) for row in rows}
            candidate_results = [
                replace(eligible_by_id[item.event_id], rank=item.score)
                for item in candidate_values
                if item.event_id in eligible_by_id
            ]
            policy_filtered_count = len(candidate_values) - len(candidate_results)
            return self._finish_retrieval_workset(
                connection,
                started=started,
                mode=mode,
                query=query,
                principal=principal,
                policy=policy,
                candidate_id=normalized_candidate_id,
                candidate_results=candidate_results,
                candidate_input_count=len(candidate_values),
                candidate_match_count=candidate_match_count,
                candidate_ranks=candidate_ranks,
                policy_filtered_candidate_count=policy_filtered_count,
                limit=limit,
                control=control,
            )

    def _finish_retrieval_workset(
        self,
        connection: sqlite3.Connection,
        *,
        started: float,
        mode: QueryMode,
        query: str,
        principal: str,
        policy: _WorksetPolicy,
        candidate_id: str,
        candidate_results: Sequence[SearchResult],
        candidate_input_count: int,
        candidate_match_count: int | None,
        candidate_ranks: dict[str, int] | None,
        policy_filtered_candidate_count: int,
        limit: int,
        control: RetrievalControl,
    ) -> dict[str, Any]:
        candidate_ids = [item.event_id for item in candidate_results]
        relation_rows: list[sqlite3.Row] = []
        if candidate_ids:
            placeholders = ",".join("?" for _ in candidate_ids)
            relation_rows = connection.execute(
                f"""
                WITH RECURSIVE
                eligible(event_id) AS (
                  SELECT e.event_id
                  FROM events_current e
                  JOIN event_access ea ON ea.event_id = e.event_id
                  WHERE {" AND ".join(policy.predicates)}
                ),
                reachable(event_id) AS (
                  SELECT event_id FROM eligible WHERE event_id IN ({placeholders})
                  UNION
                  SELECT relation.to_event_id
                  FROM event_relations relation
                  JOIN reachable ON relation.from_event_id = reachable.event_id
                  JOIN eligible ON eligible.event_id = relation.to_event_id
                  UNION
                  SELECT relation.from_event_id
                  FROM event_relations relation
                  JOIN reachable ON relation.to_event_id = reachable.event_id
                  JOIN eligible ON eligible.event_id = relation.from_event_id
                )
                SELECT relation.from_event_id, relation.to_event_id,
                       relation.relation_type
                FROM event_relations relation
                JOIN eligible source ON source.event_id = relation.from_event_id
                JOIN eligible target ON target.event_id = relation.to_event_id
                WHERE relation.from_event_id IN (SELECT event_id FROM reachable)
                   OR relation.to_event_id IN (SELECT event_id FROM reachable)
                ORDER BY relation.relation_type,
                         relation.from_event_id,
                         relation.to_event_id
                LIMIT ?
                """,
                (*policy.parameters, *candidate_ids, MAX_WORKSET_RELATIONS + 1),
            ).fetchall()
            if len(relation_rows) > MAX_WORKSET_RELATIONS:
                raise RuntimeError("retrieval relation component exceeds the bounded limit")
        related_ids = sorted(
            {
                cast(str, row[index])
                for row in relation_rows
                for index in (0, 1)
                if cast(str, row[index]) not in candidate_ids
            }
        )
        related_results: list[SearchResult] = []
        if related_ids:
            placeholders = ",".join("?" for _ in related_ids)
            related_rows = connection.execute(
                f"""
                SELECT {_WORKSET_SELECT_COLUMNS}, 0.0 AS score,
                       e.correction_id, e.corrected_at
                {_WORKSET_JOINS}
                WHERE e.event_id IN ({placeholders})
                  AND {" AND ".join(policy.predicates)}
                ORDER BY COALESCE(e.occurred_at, e.ingested_at), e.event_id
                """,
                (*related_ids, *policy.parameters),
            ).fetchall()
            related_results = [_search_result(row) for row in related_rows]
        visible_ids = {item.event_id for item in (*candidate_results, *related_results)}
        externally_superseded_ids: frozenset[str] = frozenset()
        if mode is QueryMode.WHAT_IS_CURRENT and visible_ids:
            visible_placeholders = ",".join("?" for _ in visible_ids)
            superseded_rows = connection.execute(
                f"""
                WITH eligible(event_id) AS (
                  SELECT e.event_id
                  FROM events_current e
                  JOIN event_access ea ON ea.event_id = e.event_id
                  WHERE {" AND ".join(policy.predicates)}
                )
                SELECT DISTINCT relation.from_event_id
                FROM event_relations relation
                JOIN eligible source ON source.event_id = relation.from_event_id
                JOIN events_current target ON target.event_id = relation.to_event_id
                WHERE relation.relation_type IN ('correction', 'supersession')
                  AND relation.from_event_id IN ({visible_placeholders})
                """,
                (*policy.parameters, *sorted(visible_ids)),
            ).fetchall()
            externally_superseded_ids = frozenset(cast(str, row[0]) for row in superseded_rows)
        relations = [
            EvidenceRelation(
                from_event_id=cast(str, row[0]),
                to_event_id=cast(str, row[1]),
                relation_type=cast(str, row[2]),
            )
            for row in relation_rows
            if cast(str, row[0]) in visible_ids and cast(str, row[1]) in visible_ids
        ]
        workset, selected, omitted_counts = assemble_evidence_workset(
            candidate_results,
            candidate_id=candidate_id,
            related_results=related_results,
            relations=relations,
            mode=mode,
            control=control,
            contexts=policy.contexts,
            limit=limit,
            candidate_input_count=candidate_input_count,
            candidate_match_count=candidate_match_count,
            candidate_ranks=candidate_ranks,
            policy_filtered_candidate_count=policy_filtered_candidate_count,
            externally_superseded_ids=externally_superseded_ids,
        )
        self._add_evidence_previews(connection, workset, query=query, policy=policy)
        context_policy = policy
        if mode is QueryMode.WHAT_IS_CURRENT:
            context_policy = replace(
                policy,
                predicates=(
                    *policy.predicates,
                    "NOT EXISTS (SELECT 1 FROM event_relations relation "
                    "JOIN events_current target ON target.event_id = relation.to_event_id "
                    "WHERE relation.from_event_id = e.event_id "
                    "AND relation.relation_type IN ('correction', 'supersession'))",
                ),
            )
        for item in workset["results"]:
            item["conversation_context"] = self._evidence_context(
                connection, item["event_id"], policy.accesses, search_policy=context_policy
            )
        if candidate_match_count == 0 and mode is not QueryMode.WHERE_DID_I_LEAVE_OFF:
            workset["search_diagnostic"] = (
                "No eligible individual message matched every searched token. Lexical search "
                "requires all extracted tokens (up to the first 24) within one message. Try "
                "fewer keywords; this does not establish that the topic or answer is absent."
            )
            if policy.contexts:
                workset["search_diagnostic"] += (
                    " Only records with all requested assigned context labels are searched. "
                    "Context/project filters match assigned labels, not topic keywords. "
                    "Remove the context/project filter if you meant the topic rather than "
                    "an assigned label; other search filters still apply."
                )
        latency_ms = (time.perf_counter() - started) * 1000
        self._record_query_receipt(
            connection,
            mode=mode,
            query=query,
            principal=principal,
            filters={
                "access": [item.value for item in policy.accesses],
                "scopes": [item.value for item in policy.scopes],
                "contexts": [item.as_dict() for item in policy.contexts],
                "authorities": [item.value for item in policy.authorities],
                "limit": max(1, min(limit, MAX_QUERY_RESULTS)),
                "retrieval_control": control.value,
                "result_kind": "evidence_workset",
                "candidate_id": candidate_id,
            },
            results=selected,
            omitted_counts=omitted_counts,
            latency_ms=latency_ms,
        )
        return workset

    def _add_evidence_previews(
        self,
        connection: sqlite3.Connection,
        workset: dict[str, Any],
        *,
        query: str,
        policy: _WorksetPolicy,
    ) -> None:
        items = cast(list[dict[str, Any]], workset["results"])
        workset["preview_character_limit"] = MAX_EVIDENCE_PREVIEW_CHARACTERS
        if not items:
            return
        event_ids = [item["event_id"] for item in items]
        placeholders = ",".join("?" for _ in event_ids)
        rows = connection.execute(
            f"""
            SELECT e.event_id, substr(e.content_text, 1, ?), length(CAST(e.content_text AS BLOB))
            FROM events_current e
            JOIN event_access ea ON ea.event_id = e.event_id
            WHERE e.event_id IN ({placeholders}) AND {" AND ".join(policy.predicates)}
            """,
            (MAX_EVIDENCE_PREVIEW_CHARACTERS, *event_ids, *policy.parameters),
        ).fetchall()
        previews = {cast(str, row[0]): (cast(str, row[1]), cast(int, row[2])) for row in rows}
        snippets: dict[str, str] = {}
        fts_query = _fts_query(query)
        if fts_query:
            snippet_rows = connection.execute(
                f"""
                SELECT e.event_id, substr(snippet(events_fts, 1, '', '', ' ... ', 64), 1, ?)
                FROM events_fts
                JOIN events_current e ON e.event_id = events_fts.event_id
                JOIN event_access ea ON ea.event_id = e.event_id
                WHERE events_fts MATCH ? AND e.event_id IN ({placeholders})
                  AND length(e.content_text) > ? AND {" AND ".join(policy.predicates)}
                """,
                (
                    MAX_EVIDENCE_PREVIEW_CHARACTERS,
                    fts_query,
                    *event_ids,
                    MAX_EVIDENCE_PREVIEW_CHARACTERS,
                    *policy.parameters,
                ),
            ).fetchall()
            snippets = {cast(str, row[0]): cast(str, row[1]) for row in snippet_rows}
        for item in items:
            event_id = cast(str, item["event_id"])
            prefix, total_utf8_bytes = previews[event_id]
            truncated = len(prefix.encode("utf-8")) < total_utf8_bytes
            item["content_text"] = snippets.get(event_id, prefix)
            preview: EvidencePreview = {
                "strategy": (
                    "query_snippet"
                    if event_id in snippets
                    else "prefix"
                    if truncated
                    else "complete"
                ),
                "truncated": truncated,
                "total_utf8_bytes": total_utf8_bytes,
            }
            item["content_preview"] = preview

    def _continuity_evidence(
        self,
        *,
        project_id: str | None,
        scopes: Sequence[Scope],
        authorities: Sequence[Authority] | None,
        accesses: Sequence[Access] | None,
        limit: int,
        principal: str,
        started: float,
    ) -> list[SearchResult]:
        if not project_id:
            raise ValueError("project_id is required for where_did_i_leave_off")
        if Scope.PROJECT not in scopes:
            raise ValueError("project scope is required for where_did_i_leave_off")
        limit = max(1, min(limit, MAX_QUERY_RESULTS))
        effective_authorities = list(
            authorities or (Authority.USER_ASSERTION, Authority.ASSISTANT_OUTPUT)
        )
        if not effective_authorities:
            raise ValueError("at least one authority is required for continuity evidence")
        authority_placeholders = ",".join("?" for _ in effective_authorities)
        effective_accesses = tuple(accesses or (Access.OWNER,))
        access_placeholders = ",".join("?" for _ in effective_accesses)
        sql = f"""
        SELECT * FROM (
          SELECT
            e.event_id,
            substr(e.content_text, 1, 4000) AS content_text,
            e.event_type,
            e.actor_kind,
            e.assistant,
            e.authority,
            e.scope,
            e.project_id,
            e.conversation_id,
            e.branch_id,
            e.occurred_at,
            sf.source_system,
            sr.object_id,
            sr.record_ordinal,
            sr.byte_start,
            sr.byte_end,
            0.0 AS score,
            e.correction_id,
            e.corrected_at,
            e.ingested_at
          FROM events_current e
          JOIN event_access ea ON ea.event_id = e.event_id
          JOIN source_records sr ON sr.source_record_id = e.source_record_id
          JOIN source_files sf ON sf.source_file_id = sr.source_file_id
          WHERE e.privacy = 'included'
            AND e.scope = 'project'
            AND e.project_id = ?
            AND e.authority IN ({authority_placeholders})
            AND ea.access IN ({access_placeholders})
          ORDER BY COALESCE(e.occurred_at, e.ingested_at) DESC,
                   sr.record_ordinal DESC,
                   e.event_id DESC
          LIMIT ?
        ) recent
        ORDER BY COALESCE(recent.occurred_at, recent.ingested_at) ASC,
                 recent.record_ordinal ASC,
                 recent.event_id ASC
        """
        parameters: list[object] = [
            project_id,
            *(item.value for item in effective_authorities),
            *(item.value for item in effective_accesses),
            limit,
        ]
        with closing(self._connect()) as connection:
            rows = connection.execute(sql, parameters).fetchall()
            results = [_search_result(row) for row in rows]
            latency_ms = (time.perf_counter() - started) * 1000
            self._record_query_receipt(
                connection,
                mode=QueryMode.WHERE_DID_I_LEAVE_OFF,
                query="",
                principal=principal,
                filters={
                    "scopes": [Scope.PROJECT.value],
                    "project_id": project_id,
                    "access": [item.value for item in effective_accesses],
                    "contexts": [{"kind": ContextKind.PROJECT.value, "key": project_id}],
                    "authorities": [item.value for item in effective_authorities],
                    "limit": limit,
                    "result_kind": "evidence_only",
                },
                results=results,
                omitted_counts={"derived_open_threads": "not_available"},
                latency_ms=latency_ms,
            )
        return results

    def get_evidence(
        self,
        event_id: str,
        *,
        allowed_accesses: Sequence[Access] | None = None,
        include_context: bool = False,
    ) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            state = self._evidence_read_state(connection, event_id, allowed_accesses)
            object_id = cast(str, state.row[12])
            raw = self._read_object(
                cast(str, state.row[16]), object_id, cast(int, state.row[17]), connection=connection
            )
        # Recheck the selected evidence after slow I/O, not unrelated ledger publications.
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                current = self._evidence_read_state(connection, event_id, allowed_accesses)
            except KeyError as error:
                raise RuntimeError("selected evidence changed during retrieval") from error
            if current != state:
                raise RuntimeError("selected evidence changed during retrieval")
            context = (
                self._evidence_context(connection, event_id, allowed_accesses)
                if include_context
                else None
            )
        raw_attachment_withheld = raw_record_has_uninspected_attachment(raw)
        row = state.row
        policy = state.policy
        web_export = state.web_export
        web_export_attachment_rows = state.attachment_rows
        (
            web_export_supplemental_member_count,
            web_export_linked_member_count,
            web_export_event_attachment_count,
            web_export_event_attachment_reference_count,
        ) = state.attachment_counts
        native_source_account_id = cast(str | None, row[38])
        native_source_device_id = cast(str | None, row[39])
        web_export_conversation_index = cast(int, web_export[4]) if web_export is not None else None
        if web_export_attachment_rows and web_export_conversation_index is None:
            raise RuntimeError("web export attachment rows lack a conversation observation")
        attachment_manifests_by_id: dict[str, dict[str, Any]] = {}
        for item in web_export_attachment_rows:
            archive_member_id = cast(str, item[0])
            existing_manifest = attachment_manifests_by_id.get(archive_member_id)
            if existing_manifest is None:
                extracted = item[13] is not None
                manifest: dict[str, Any] = {
                    "attachment_manifest_id": archive_member_id,
                    "archive_member_index": cast(int, item[1]),
                    "source_locator": cast(str, item[2]),
                    "name_sha256": cast(str, item[3]),
                    "content_sha256": cast(str, item[4]),
                    "compressed_bytes": cast(int, item[5]),
                    "byte_length": cast(int, item[6]),
                    "compression_method": cast(int, item[7]),
                    "media_type_hint": cast(str, item[8]),
                    "conversation_index": web_export_conversation_index,
                    "classification_status": "provider_attachment",
                    "link_status": "linked",
                    "extraction_status": "extracted" if extracted else "not_extracted",
                    "inspection_status": (
                        "not_verified"
                        if item[8] in TEXT_ATTACHMENT_MEDIA_TYPES
                        else "not_inspected"
                    ),
                    "content_access": "metadata_only",
                    "diagnostic_code": (
                        "provider_attachment_stored"
                        if extracted
                        else "provider_attachment_not_extracted_by_policy"
                    ),
                    "attachment_source_object_id": (cast(str, item[13]) if extracted else None),
                    "storage_object_id": cast(str, item[14]) if extracted else None,
                    "references": [],
                }
                attachment_manifests_by_id[archive_member_id] = manifest
            else:
                manifest = existing_manifest
            cast(list[dict[str, object]], manifest["references"]).append(
                {
                    "attachment_link_id": cast(str, item[9]),
                    "source_record_ordinal": cast(int, item[10]),
                    "reference_ordinal": cast(int, item[11]),
                    "reference_sha256": cast(str, item[12]),
                }
            )
        attachment_manifests = list(attachment_manifests_by_id.values())
        web_export_evidence = (
            {
                "observation_id": cast(str, web_export[0]),
                "batch_id": cast(str, web_export[1]),
                "source_object_id": cast(str, web_export[2]),
                "source_locator": cast(str, web_export[3]),
                "conversation_index": cast(int, web_export[4]),
                "source_byte_start": cast(int, web_export[5]),
                "source_byte_end": cast(int, web_export[6]),
                "conversation_sha256": cast(str, web_export[7]),
                "manifest_sha256": cast(str, web_export[10]),
                "code_revision": cast(str, web_export[11]),
                "prepared_at": cast(str, web_export[12]),
                "archive_sha256": cast(str, web_export[13]),
                "archive_byte_length": cast(int, web_export[14]),
                "selected_member_name_sha256": cast(str, web_export[15]),
                "selected_member_sha256": cast(str, web_export[16]),
                "selected_member_byte_length": cast(int, web_export[17]),
                "split_storage_object_id": cast(str | None, web_export[18]),
                "split_retention": (
                    "retained_legacy_container" if web_export[18] is not None else "metadata_only"
                ),
                "split_plaintext_sha256": cast(str, web_export[19]),
                "split_byte_length": cast(int, web_export[20]),
                "split_media_type": cast(str, web_export[21]),
                "archive_source_object_id": cast(str, web_export[22]),
                "selected_member_source_object_id": cast(str, web_export[23]),
                "source_client": cast(str, web_export[24]),
                "source_client_version": cast(str, web_export[25]),
                "capture_capability": cast(str, web_export[26]),
                "adapter_name": cast(str, web_export[27]),
                "adapter_version": cast(str, web_export[28]),
                "schema_fingerprint": cast(str, web_export[29]),
                "parser_versions": json.loads(cast(str, web_export[30])),
                "supplemental_member_count": web_export_supplemental_member_count,
                "linked_member_count": web_export_linked_member_count,
                "unclassified_member_count": (
                    web_export_supplemental_member_count - web_export_linked_member_count
                ),
                "attachment_manifest_count": web_export_event_attachment_count,
                "attachment_manifests_truncated": (
                    web_export_event_attachment_count > len(attachment_manifests)
                ),
                "attachment_reference_count": web_export_event_attachment_reference_count,
                "attachment_references_truncated": (
                    web_export_event_attachment_reference_count > len(web_export_attachment_rows)
                ),
                "attachment_manifests": attachment_manifests,
            }
            if web_export is not None
            else None
        )
        return {
            **({"conversation_context": context} if include_context else {}),
            "event_id": cast(str, row[0]),
            "content_text": cast(str, row[1]),
            "actor_kind": cast(str, row[2]),
            "assistant": cast(str | None, row[3]),
            "authority": cast(str, row[4]),
            "occurred_at": cast(str | None, row[5]),
            "conversation_id": cast(str, row[6]),
            "branch_id": cast(str | None, row[7]),
            "source_system": cast(str, row[8]),
            "source_path_hash": cast(str, row[9]),
            "source_account_id": (
                native_source_account_id
                if native_source_account_id is not None
                else cast(str, web_export[8])
                if web_export is not None
                else None
            ),
            "source_device_id": (
                native_source_device_id
                if native_source_device_id is not None
                else cast(str, web_export[9])
                if web_export is not None
                else None
            ),
            "source_locator": (cast(str, web_export[3]) if web_export is not None else None),
            "web_export": web_export_evidence,
            "parser_name": cast(str, row[10]),
            "source_parser_version": cast(str, row[11]),
            "source_object_id": object_id,
            "record_ordinal": cast(int, row[13]),
            "byte_start": cast(int, row[14]),
            "byte_end": cast(int, row[15]),
            "raw_record": (None if raw_attachment_withheld else raw.decode("utf-8")),
            "raw_record_access": (
                "withheld_uninspected_attachment" if raw_attachment_withheld else "exact"
            ),
            "parser_version": cast(str, row[18]),
            "event_type": cast(str, row[33]),
            "scope": cast(str, row[34]),
            "project_id": cast(str | None, row[35]),
            "access": policy["access"],
            "contexts": policy["contexts"],
            "privacy": cast(str, row[36]),
            "content_digest": cast(str, row[37]),
            "correction": (
                {
                    "correction_id": cast(str, row[19]),
                    "reason": cast(str, row[20]),
                    "authorized_by": cast(str, row[21]),
                    "authorization_scope": cast(str, row[22]),
                    "original": {
                        "event_type": cast(str, row[23]),
                        "actor_kind": cast(str, row[24]),
                        "assistant": cast(str | None, row[25]),
                        "authority": cast(str, row[26]),
                        "scope": cast(str, row[27]),
                        "project_id": cast(str | None, row[28]),
                        "privacy": cast(str, row[29]),
                        "content_digest": cast(str, row[30]),
                        "content_text": cast(str, row[31]),
                        "parser_version": cast(str, row[32]),
                    },
                }
                if row[19] is not None
                else None
            ),
        }

    def _evidence_context(
        self,
        connection: sqlite3.Connection,
        event_id: str,
        allowed_accesses: Sequence[Access] | None,
        *,
        search_policy: _WorksetPolicy | None = None,
    ) -> dict[str, Any]:
        policy = search_policy or _workset_policy(
            mode=QueryMode.FIND_EVIDENCE,
            scopes=tuple(Scope),
            contexts=(),
            project_id=None,
            authorities=None,
            accesses=allowed_accesses,
        )
        preceding_only = search_policy is not None
        items: list[dict[str, Any]] = []
        parent_links: list[dict[str, str]] = []
        anchor = connection.execute(
            """
            SELECT sf.source_system, sr.source_file_id, e.conversation_id,
                   sr.source_record_id, sr.message_id, sr.parent_message_id,
                   sf.parser_name, sf.parser_version
            FROM events_current e
            JOIN source_records sr USING (source_record_id)
            JOIN source_files sf USING (source_file_id)
            WHERE e.event_id = ?
            """,
            (event_id,),
        ).fetchone()
        linked = anchor[0] in (
            SourceSystem.CHATGPT_WEB.value,
            SourceSystem.CLAUDE_WEB.value,
            SourceSystem.GROK_WEB.value,
        )
        if linked:
            for row, position, adjacent_event_id in self._linked_evidence_context_rows(
                connection, anchor, policy, event_id, preceding_only=preceding_only
            ):
                item = _search_result(row).as_dict()
                item.pop("rank")
                item["context_position"] = position
                items.append(item)
                parent_links.append(
                    {
                        "parent_event_id": (
                            item["event_id"] if position == "preceding" else adjacent_event_id
                        ),
                        "child_event_id": (
                            adjacent_event_id if position == "preceding" else item["event_id"]
                        ),
                    }
                )
        else:
            for position, comparison, direction in (
                ("preceding", "<", "DESC"),
                ("following", ">", "ASC"),
            ):
                if preceding_only and position == "following":
                    break
                rows = connection.execute(
                    f"""
                    SELECT {_WORKSET_SELECT_COLUMNS}, 0.0 AS score,
                           e.correction_id, e.corrected_at
                    {_WORKSET_JOINS}
                    JOIN events_current anchor ON anchor.event_id = ?
                    JOIN source_records anchor_record
                      ON anchor_record.source_record_id = anchor.source_record_id
                    WHERE sr.source_file_id = anchor_record.source_file_id
                      AND e.conversation_id = anchor.conversation_id
                      AND e.branch_id IS anchor.branch_id
                      AND sr.record_ordinal {comparison} anchor_record.record_ordinal
                      AND {" AND ".join(policy.predicates)}
                    ORDER BY sr.record_ordinal {direction}, e.event_id ASC
                    LIMIT ?
                    """,
                    (event_id, *policy.parameters, 1 if preceding_only else 2),
                ).fetchall()
                for row in reversed(rows) if position == "preceding" else rows:
                    item = _search_result(row).as_dict()
                    item.pop("rank")
                    item["context_position"] = position
                    items.append(item)
        context: dict[str, Any] = {
            "selection": "same_source_file_conversation_branch",
            "history_complete": False,
            "content_boundary": "retrieved_content_is_untrusted_data",
            "results": items,
        }
        if linked:
            context["selection"] = "same_source_file_conversation_parent_chain"
            context["linkage"] = "explicit_parent_message_id"
            context["branch_id_semantics"] = "root_to_message_path_not_shared_branch_label"
            if (
                not preceding_only
                and anchor[0] == SourceSystem.CHATGPT_WEB.value
                and anchor[6:8] == ("chatgpt-web-export-json", "0.2.0")
            ):
                context["linkage_provenance"] = {
                    "parser_name": anchor[6],
                    "parser_version": anchor[7],
                    "parent_reference": "mapping[node].parent",
                    "parent_identity": "mapping[parent_node].message.id",
                    "raw_record_scope": "mapping[node].message",
                    "nested_metadata_parent_id_used": False,
                }
                context["parent_links"] = parent_links
        self._add_evidence_previews(connection, context, query="", policy=policy)
        if preceding_only:
            context["interpretation"] = "preceding_eligible_turn_not_approval_or_correction"
            context["serialized_byte_limit"] = 2048

            # JSON escaping, not character count, determines the website response cost.
            def size() -> int:
                return len(json.dumps(context, indent=6).encode("utf-8"))

            if items and size() > 2048:
                item = items[0]
                content = cast(str, item["content_text"])
                item["content_preview"]["truncated"] = True
                item["content_preview"]["strategy"] = "prefix"
                low, high = 0, len(content)
                while low < high:
                    middle = (low + high + 1) // 2
                    item["content_text"] = content[:middle]
                    if size() <= 2048:
                        low = middle
                    else:
                        high = middle - 1
                item["content_text"] = content[:low]
                if size() > 2048:
                    context["results"] = []
                    context["omitted_reason"] = "context_metadata_exceeds_preview_budget"
        return context

    def _linked_evidence_context_rows(
        self,
        connection: sqlite3.Connection,
        anchor: sqlite3.Row,
        policy: _WorksetPolicy,
        anchor_event_id: str,
        *,
        preceding_only: bool = False,
    ) -> list[tuple[sqlite3.Row, str, str]]:
        # Web branch hashes describe root-to-message paths, not shared branch labels.
        # Follow only admitted direct links; never infer order across gaps or forks.
        file_id, conversation_id, record_id, message_id, parent_id = anchor[1:6]

        def records(column: str, value: str | None) -> list[sqlite3.Row]:
            if not value:
                return []
            return connection.execute(
                f"SELECT source_record_id, message_id, parent_message_id FROM source_records "
                f"WHERE source_file_id = ? AND {column} = ? LIMIT 2",
                (file_id, value),
            ).fetchall()

        if len(records("message_id", message_id)) != 1:
            return []
        result: list[tuple[sqlite3.Row, str, str]] = []
        seen = {record_id}
        for position in ("preceding",) if preceding_only else ("preceding", "following"):
            current_message, current_parent = message_id, parent_id
            current_event_id = anchor_event_id
            neighbors: list[tuple[sqlite3.Row, str, str]] = []
            for _ in range(1 if preceding_only else 2):
                candidates = records(
                    "message_id" if position == "preceding" else "parent_message_id",
                    current_parent if position == "preceding" else current_message,
                )
                # Count identities before access filtering so a hidden sibling cannot
                # make an ambiguous fork look like a single continuation.
                if len(candidates) != 1:
                    break
                candidate = candidates[0]
                if candidate[0] in seen:
                    return []
                if len(records("message_id", candidate[1])) != 1:
                    break
                row = connection.execute(
                    f"""
                    SELECT {_WORKSET_SELECT_COLUMNS}, 0.0 AS score,
                           e.correction_id, e.corrected_at
                    {_WORKSET_JOINS}
                    WHERE sr.source_record_id = ? AND e.conversation_id = ?
                      AND {" AND ".join(policy.predicates)}
                    """,
                    (candidate[0], conversation_id, *policy.parameters),
                ).fetchone()
                if row is None:
                    break
                seen.add(candidate[0])
                neighbors.append((row, position, current_event_id))
                current_event_id = cast(str, row[0])
                current_message, current_parent = candidate[1], candidate[2]
            result.extend(reversed(neighbors) if position == "preceding" else neighbors)
        return result

    def _evidence_read_state(
        self,
        connection: sqlite3.Connection,
        event_id: str,
        allowed_accesses: Sequence[Access] | None,
    ) -> _EvidenceReadState:
        try:
            policy = self._event_policy_in_connection(connection, event_id)
        except KeyError as error:
            raise KeyError(f"included evidence event not found: {event_id}") from error
        if (
            allowed_accesses is not None
            and Access(cast(str, policy["access"])) not in allowed_accesses
        ):
            raise KeyError(f"included evidence event not found: {event_id}")
        row = connection.execute(
            """
            SELECT
              e.event_id, e.content_text, e.actor_kind, e.assistant,
              e.authority, e.occurred_at, e.conversation_id, e.branch_id,
              sf.source_system, sf.source_path_hash, sf.parser_name,
              sf.parser_version, sr.object_id, sr.record_ordinal,
              sr.byte_start, sr.byte_end, o.object_path, o.byte_length,
              e.parser_version, e.correction_id, e.correction_reason,
              e.correction_authorized_by, e.correction_authorization_scope,
              original.event_type, original.actor_kind, original.assistant,
              original.authority, original.scope, original.project_id,
              original.privacy, original.content_digest, original.content_text,
              original.parser_version, e.event_type, e.scope, e.project_id,
              e.privacy, e.content_digest,
              (
                SELECT batch.source_account_id
                FROM upload_batches batch
                WHERE batch.source_file_id = sf.source_file_id
                ORDER BY batch.created_at, batch.batch_id
                LIMIT 1
              ) AS source_account_id,
              (
                SELECT batch.device_id
                FROM upload_batches batch
                WHERE batch.source_file_id = sf.source_file_id
                ORDER BY batch.created_at, batch.batch_id
                LIMIT 1
              ) AS source_device_id,
              sf.source_file_id, o.storage_kind, e.source_record_id,
              sf.source_account, sf.status, sf.file_digest, sf.file_size,
              sr.message_id, sr.parent_message_id, account.installation_id,
              account.device_id, account.source_system, account.legacy_account_key,
              account.status, device.status, installation.owner_id,
              account_policy.scope, account_policy.project_id
            FROM events_current e
            JOIN events original ON original.event_id = e.event_id
            JOIN source_records sr ON sr.source_record_id = e.source_record_id
            JOIN source_files sf ON sf.source_file_id = sr.source_file_id
            JOIN objects o ON o.object_id = sr.object_id
            LEFT JOIN source_accounts account ON account.source_account_id = sf.source_account
            LEFT JOIN devices device ON device.device_id = account.device_id
            LEFT JOIN installations installation
              ON installation.installation_id = account.installation_id
            LEFT JOIN source_account_policies account_policy
              ON account_policy.source_account_id = account.source_account_id
            WHERE e.event_id = ? AND e.privacy = 'included'
            """,
            (event_id,),
        ).fetchone()
        web_export = None
        web_export_attachment_rows: list[tuple[object, ...]] = []
        web_export_supplemental_member_count = 0
        web_export_linked_member_count = 0
        web_export_event_attachment_count = 0
        web_export_event_attachment_reference_count = 0
        if row is not None:
            web_export = connection.execute(
                """
                SELECT observation.observation_id, observation.batch_id,
                       observation.source_object_id, observation.source_locator,
                       observation.conversation_index, observation.source_byte_start,
                       observation.source_byte_end, observation.conversation_sha256,
                       batch.source_account_id, account.device_id, batch.manifest_sha256,
                       batch.code_revision, batch.prepared_at, batch.archive_sha256,
                       batch.archive_byte_length, batch.selected_member_name_sha256,
                       batch.selected_member_sha256, batch.selected_member_byte_length,
                       source.object_id, source.plaintext_sha256, source.byte_length,
                       source.media_type,
                       (
                         SELECT archive.source_object_id
                         FROM web_export_source_objects archive
                         WHERE archive.batch_id = batch.batch_id
                           AND archive.object_kind = 'official_export_archive'
                       ),
                       (
                         SELECT member.source_object_id
                         FROM web_export_source_objects member
                         WHERE member.batch_id = batch.batch_id
                           AND member.object_kind = 'selected_export_member'
                       ),
                       authorization.source_client,
                       authorization.source_client_version,
                       authorization.capture_capability,
                       authorization.adapter_name,
                       authorization.adapter_version,
                       authorization.schema_fingerprint,
                       authorization.parser_versions_json
                FROM web_export_conversation_observations observation
                JOIN web_export_batches batch ON batch.batch_id = observation.batch_id
                JOIN source_accounts account
                  ON account.source_account_id = batch.source_account_id
                JOIN web_export_source_objects source
                  ON source.source_object_id = observation.source_object_id
                JOIN source_schema_authorizations authorization
                  ON authorization.authorization_id = batch.authorization_id
                WHERE observation.source_file_id = ?
                ORDER BY observation.created_at, observation.observation_id
                LIMIT 1
                """,
                (cast(str, row[40]),),
            ).fetchone()
            if web_export is not None:
                count_row = connection.execute(
                    """
                    SELECT
                      (SELECT COUNT(*)
                       FROM web_export_archive_members
                       WHERE batch_id = ?),
                      (SELECT COUNT(DISTINCT archive_member_id)
                       FROM web_export_attachment_links
                       WHERE batch_id = ?),
                      (SELECT COUNT(DISTINCT archive_member_id)
                       FROM web_export_attachment_links
                       WHERE batch_id = ? AND conversation_index = ?
                         AND source_record_ordinal = ?),
                      (SELECT COUNT(*)
                       FROM web_export_attachment_links
                       WHERE batch_id = ? AND conversation_index = ?
                         AND source_record_ordinal = ?)
                    """,
                    (
                        cast(str, web_export[1]),
                        cast(str, web_export[1]),
                        cast(str, web_export[1]),
                        cast(int, web_export[4]),
                        cast(int, row[13]),
                        cast(str, web_export[1]),
                        cast(int, web_export[4]),
                        cast(int, row[13]),
                    ),
                ).fetchone()
                web_export_supplemental_member_count = cast(int, count_row[0])
                web_export_linked_member_count = cast(int, count_row[1])
                web_export_event_attachment_count = cast(int, count_row[2])
                web_export_event_attachment_reference_count = cast(int, count_row[3])
                web_export_attachment_rows = [
                    tuple(item)
                    for item in connection.execute(
                        """
                        WITH selected_members AS (
                          SELECT DISTINCT archive_member_id
                          FROM web_export_attachment_links
                          WHERE batch_id = ? AND conversation_index = ?
                            AND source_record_ordinal = ?
                          ORDER BY archive_member_id
                          LIMIT ?
                        )
                        SELECT member.archive_member_id, member.archive_member_index,
                               member.locator, member.name_sha256,
                               member.content_sha256, member.compressed_bytes,
                               member.byte_length, member.compression_method,
                               member.media_type_hint, link.attachment_link_id,
                               link.source_record_ordinal, link.reference_ordinal,
                               link.reference_sha256,
                               object.attachment_source_object_id, object.object_id,
                               object.plaintext_sha256, object.byte_length,
                               object.media_type
                        FROM selected_members selected
                        JOIN web_export_archive_members member
                          ON member.archive_member_id = selected.archive_member_id
                        JOIN web_export_attachment_links link
                          ON link.archive_member_id = member.archive_member_id
                         AND link.conversation_index = ?
                         AND link.source_record_ordinal = ?
                        LEFT JOIN web_export_attachment_objects object
                          ON object.archive_member_id = member.archive_member_id
                        ORDER BY member.archive_member_index,
                                 link.source_record_ordinal,
                                 link.reference_ordinal,
                                 link.reference_sha256
                        LIMIT ?
                        """,
                        (
                            cast(str, web_export[1]),
                            cast(int, web_export[4]),
                            cast(int, row[13]),
                            MAX_EVIDENCE_ATTACHMENT_MANIFESTS,
                            cast(int, web_export[4]),
                            cast(int, row[13]),
                            MAX_EVIDENCE_ATTACHMENT_REFERENCES,
                        ),
                    )
                ]
        if row is None:
            raise KeyError(f"included evidence event not found: {event_id}")
        object_id = cast(str, row[12])
        if (
            connection.execute(
                "SELECT 1 FROM deletion_object_work "
                "WHERE object_id = ? AND status = 'pending' LIMIT 1",
                (object_id,),
            ).fetchone()
            is not None
        ):
            raise RuntimeError("evidence object has a pending deletion")
        return _EvidenceReadState(
            row=tuple(row),
            policy=policy,
            web_export=tuple(web_export) if web_export is not None else None,
            attachment_rows=tuple(web_export_attachment_rows),
            attachment_counts=(
                web_export_supplemental_member_count,
                web_export_linked_member_count,
                web_export_event_attachment_count,
                web_export_event_attachment_reference_count,
            ),
            location=read_location(connection, object_id),
        )

    def propose_memory(
        self,
        *,
        statement: str,
        memory_type: MemoryType,
        scope: Scope,
        evidence_event_ids: Sequence[str],
        project_id: str | None,
        created_by: str,
        pending_web_evidence: PendingWebEvidenceClaim | None = None,
        allowed_accesses: Sequence[Access] | None = None,
        proposer_principal: str | None = None,
        proposer_kind: ClientKind | None = None,
    ) -> dict[str, Any]:
        self._require_writable()
        if (proposer_principal is None) is not (proposer_kind is None):
            raise ValueError("proposal authorization is incomplete")
        if proposer_principal is not None and proposer_principal != created_by:
            raise PermissionError("proposal creator must match its authenticated principal")
        if not statement.strip() or len(statement.encode()) > MAX_PROPOSAL_STATEMENT_BYTES:
            raise ValueError("statement is required")
        if scope is Scope.PROJECT and not project_id:
            raise ValueError("project_id is required for project-scoped memory")
        if scope is not Scope.PROJECT and project_id is not None:
            raise ValueError("only project-scoped memory may carry project_id")
        if len(evidence_event_ids) > MAX_PROPOSAL_EVIDENCE_EVENTS:
            raise ValueError("proposal evidence count exceeds its limit")
        if len(evidence_event_ids) != len(set(evidence_event_ids)):
            raise ValueError("proposal evidence ids contain duplicates")
        decision = classify_record(
            source_system=SourceSystem.CODEX,
            content_text=statement,
            raw_record=statement.encode(),
            max_record_bytes=64 * 1024,
        )
        if not decision.accepted:
            raise ValueError(f"memory proposal rejected by admission policy: {decision.reason}")
        unique_ids = tuple(sorted(evidence_event_ids))
        normalized_claim = (
            _normalized_pending_web_evidence_claim(pending_web_evidence)
            if pending_web_evidence is not None
            else None
        )
        if not unique_ids and normalized_claim is None:
            raise ValueError(
                "at least one evidence event or pending web evidence claim is required"
            )

        with closing(self._connect()) as connection, connection:
            rows: list[sqlite3.Row | tuple[Any, ...]] = []
            if unique_ids:
                placeholders = ",".join("?" for _ in unique_ids)
                rows = connection.execute(
                    f"""
                    SELECT event_id, authority, scope, project_id
                    FROM events_current
                    WHERE event_id IN ({placeholders}) AND privacy = 'included'
                    """,
                    unique_ids,
                ).fetchall()
                if len(rows) != len(unique_ids):
                    raise ValueError("one or more evidence events are missing or excluded")
            authorities = [Authority(cast(str, row[1])) for row in rows]
            evidence_scopes = [Scope(cast(str, row[2])) for row in rows]
            evidence_projects = [cast(str | None, row[3]) for row in rows]
            if rows:
                _validate_proposal_scope(scope, project_id, evidence_scopes, evidence_projects)
            authority = _authority_floor(authorities) if authorities else Authority.ASSISTANT_OUTPUT
            memory_id = str(uuid.uuid4())
            created_at = _now()
            creation_digest = _memory_candidate_creation_digest(
                memory_id=memory_id,
                memory_type=memory_type,
                statement_digest=_sha256_text(statement.strip()),
                authority=authority,
                scope=scope,
                project_id=project_id,
                evidence_event_ids=unique_ids,
                created_by=created_by,
                pending_web_evidence=normalized_claim,
            )
            installation_id = _ensure_installation(connection, created_at)
            if normalized_claim is not None:
                _require_registered_source_account_for_candidate(
                    connection,
                    installation_id=installation_id,
                    source_account_id=normalized_claim.source_account_id,
                    source_system=normalized_claim.source_system,
                    scope=scope,
                    project_id=project_id,
                    allowed_accesses=allowed_accesses,
                )
                if _record_is_erased(
                    connection,
                    source_system=normalized_claim.source_system,
                    source_account=normalized_claim.source_account_id,
                    conversation_id=normalized_claim.conversation_id,
                    raw_digest=None,
                    message_id=normalized_claim.message_id,
                    message_id_kind="provider_message_id",
                ):
                    raise PermissionError("pending evidence belongs to an erased record")
            connection.execute(
                """
                INSERT INTO memory_candidates(
                  memory_id, memory_type, statement, statement_digest, authority,
                  lifecycle, scope, project_id, temporal_status,
                  evidence_event_ids_json, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, 'candidate', ?, ?, 'current', ?, ?, ?)
                """,
                (
                    memory_id,
                    memory_type.value,
                    statement.strip(),
                    _sha256_text(statement.strip()),
                    authority.value,
                    scope.value,
                    project_id,
                    json.dumps(unique_ids),
                    created_by,
                    created_at,
                ),
            )
            _sync_legacy_access(
                connection,
                table="memory_candidate_access",
                id_column="memory_id",
                entity_id=memory_id,
                scope=scope.value,
                now=created_at,
            )
            _sync_legacy_context(
                connection,
                table="memory_candidate_contexts",
                id_column="memory_id",
                entity_id=memory_id,
                installation_id=installation_id,
                project_id=project_id,
                now=created_at,
            )
            claim_id: str | None = None
            linked_event_id: str | None = None
            if normalized_claim is not None:
                claim_id = _stable_id(
                    "pending_web_evidence_claim",
                    memory_id,
                    normalized_claim.family_key,
                    normalized_claim.parent_message_id or "",
                    normalized_claim.branch_id or "",
                    normalized_claim.content_digest,
                )
                connection.execute(
                    """
                    INSERT INTO memory_candidate_evidence_claims(
                      claim_id, memory_id, source_account_id, source_system, family_key,
                      conversation_id, message_id, message_id_kind, parent_message_id,
                      branch_id, content_digest, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'provider_message_id', ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_id,
                        memory_id,
                        normalized_claim.source_account_id,
                        normalized_claim.source_system.value,
                        normalized_claim.family_key,
                        normalized_claim.conversation_id,
                        normalized_claim.message_id,
                        normalized_claim.parent_message_id,
                        normalized_claim.branch_id,
                        normalized_claim.content_digest,
                        created_by,
                        created_at,
                    ),
                )
                linked = _reconcile_pending_memory_claim_from_existing_event(
                    connection,
                    claim_id=claim_id,
                    memory_id=memory_id,
                    claim=normalized_claim,
                    candidate_scope=scope,
                    candidate_project_id=project_id,
                    created_at=created_at,
                )
                if linked is not None:
                    linked_event_id = linked[0]
                    candidate = connection.execute(
                        """
                        SELECT authority, evidence_event_ids_json
                        FROM memory_candidates
                        WHERE memory_id = ?
                        """,
                        (memory_id,),
                    ).fetchone()
                    if candidate is None:
                        raise RuntimeError("reconciled memory candidate is missing")
                    authority = Authority(cast(str, candidate[0]))
                    unique_ids = tuple(json.loads(cast(str, candidate[1])))
            proposal_id: str | None = None
            if proposer_principal is not None and proposer_kind is not None:
                proposal_id = _memory_candidate_proposal_id(
                    memory_id=memory_id,
                    candidate_creation_digest=creation_digest,
                    proposed_by=proposer_principal,
                    proposer_kind=proposer_kind,
                    authorization_scope=Capability.MEMORY_PROPOSE_WRITE.value,
                    policy_version=CANDIDATE_CREATION_POLICY_VERSION,
                    created_at=created_at,
                )
                connection.execute(
                    """
                    INSERT INTO memory_candidate_proposal_receipts(
                      proposal_id, memory_id, candidate_creation_digest, proposed_by,
                      proposer_kind, authorization_scope, policy_version, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'memory:propose-write', ?, ?)
                    """,
                    (
                        proposal_id,
                        memory_id,
                        creation_digest,
                        proposer_principal,
                        proposer_kind.value,
                        CANDIDATE_CREATION_POLICY_VERSION,
                        created_at,
                    ),
                )
        return {
            "memory_id": memory_id,
            "memory_type": memory_type.value,
            "statement": statement.strip(),
            "authority": authority.value,
            "lifecycle": "candidate",
            "scope": scope.value,
            "project_id": project_id,
            "evidence_event_ids": list(unique_ids),
            "created_by": created_by,
            "created_at": created_at,
            "proposal_receipt_id": proposal_id,
            "pending_web_evidence": (
                {
                    "claim_id": claim_id,
                    "status": "reconciled" if linked_event_id is not None else "pending",
                    "event_id": linked_event_id,
                }
                if claim_id is not None
                else None
            ),
        }

    def candidate_review_state(self, memory_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                return _candidate_review_state(connection, memory_id)
            finally:
                connection.rollback()

    def review_memory_candidate(
        self,
        memory_id: str,
        *,
        operation: CandidateReviewOperation,
        expected_basis_digest: str,
        reason_code: CandidateReviewReason,
        authorized_by: str,
        authorization_scope: str,
    ) -> dict[str, Any]:
        self._require_writable()
        memory_id = _bounded_text_value(memory_id, "memory candidate id", max_bytes=256)
        _validate_sha256(expected_basis_digest, "expected candidate basis")
        authorized_by = _bounded_text_value(
            authorized_by,
            "candidate reviewer",
            max_bytes=1024,
        )
        if authorization_scope != "memory:curate":
            raise PermissionError("candidate review requires memory:curate authorization")
        _validate_candidate_review_reason(operation, reason_code)

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                previous_generation = _ledger_generation_digest(connection)
                state = _candidate_review_state(connection, memory_id)
                if not hmac.compare_digest(
                    cast(str, state["review_basis_digest"]),
                    expected_basis_digest,
                ):
                    raise RuntimeError("memory candidate changed after review state was read")
                previous_lifecycle = MemoryLifecycle(cast(str, state["lifecycle"]))
                new_lifecycle = _candidate_review_transition(operation, previous_lifecycle)
                blockers = cast(list[str], state["qualification_blockers"])
                if operation in {
                    CandidateReviewOperation.QUALIFY,
                    CandidateReviewOperation.APPROVE,
                }:
                    if blockers:
                        raise ValueError(
                            "candidate qualification is blocked: " + ",".join(blockers)
                        )
                    for event_id in cast(list[str], state["evidence_event_ids"]):
                        self._read_event_object(connection, event_id)

                created_at = _now()
                transition_id = _candidate_review_transition_id(
                    memory_id=memory_id,
                    operation=operation,
                    previous_lifecycle=previous_lifecycle,
                    new_lifecycle=new_lifecycle,
                    candidate_basis_digest=expected_basis_digest,
                    previous_transition_id=cast(str | None, state["last_transition_id"]),
                    authorized_by=authorized_by,
                    authorization_scope=authorization_scope,
                    reason_code=reason_code,
                    created_at=created_at,
                )
                connection.execute(
                    """
                    INSERT INTO memory_candidate_review_transitions(
                      transition_id, memory_id, operation, previous_lifecycle,
                      new_lifecycle, candidate_basis_digest, previous_transition_id,
                      review_policy_version, authorized_by, authorization_scope,
                      reason_code, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'memory:curate', ?, ?)
                    """,
                    (
                        transition_id,
                        memory_id,
                        operation.value,
                        previous_lifecycle.value,
                        new_lifecycle.value,
                        expected_basis_digest,
                        state["last_transition_id"],
                        CANDIDATE_REVIEW_POLICY_VERSION,
                        authorized_by,
                        reason_code.value,
                        created_at,
                    ),
                )
                new_generation = _ledger_generation_digest(connection)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return {
            "status": "reviewed",
            "memory_id": memory_id,
            "transition_id": transition_id,
            "operation": operation.value,
            "previous_lifecycle": previous_lifecycle.value,
            "lifecycle": new_lifecycle.value,
            "candidate_basis_digest": expected_basis_digest,
            "review_policy_version": CANDIDATE_REVIEW_POLICY_VERSION,
            "reason_code": reason_code.value,
            "authorized_by": authorized_by,
            "authorization_scope": authorization_scope,
            "previous_generation_digest": previous_generation,
            "new_generation_digest": new_generation,
            "created_at": created_at,
        }

    def status(
        self, *, source_freshness_accesses: Sequence[Access] | None = None
    ) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            status = self._status_in_transaction(connection)
            if source_freshness_accesses is not None:
                rows = self._source_account_observations_in_transaction(
                    connection, allowed_accesses=source_freshness_accesses
                )
                files_cte, file_parameters = self._source_freshness_files_cte(
                    source_freshness_accesses
                )
                source_rows = connection.execute(
                    f"""
                    {files_cte}
                    SELECT source_system, COUNT(*), MAX(ingested_at)
                    FROM status_files
                    GROUP BY source_system
                    """,
                    file_parameters,
                ).fetchall()
                sources = {row[0]: row for row in source_rows}
                status["source_freshness"] = {
                    "basis": "node_receipts_not_live_provider_state",
                    "access_filtered": True,
                    "freshness_guaranteed": False,
                    "collector_liveness": "not_observed_by_node",
                    "sources": [
                        {
                            "source_system": source.value,
                            "source_files": sources.get(source.value, (None, 0, None))[1],
                            "latest_ingested_at": sources.get(source.value, (None, 0, None))[2],
                        }
                        for source in SourceSystem
                    ],
                    "accounts": [
                        {
                            "source_account_id": row[0],
                            "device_id": row[1],
                            "source_system": row[2],
                            "account_status": row[4],
                            "registered": row[6] is not None,
                            "device_status": row[9],
                            "latest_native_admission_at": row[10],
                            "latest_web_observation_at": row[11],
                            "latest_ingested_at": row[12],
                        }
                        for row in rows[:MAX_ADMIN_ROWS]
                    ],
                    "accounts_truncated": len(rows) > MAX_ADMIN_ROWS,
                }
            connection.rollback()
        return status

    def operations_snapshot(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            status = self._status_in_transaction(connection)
            sources = self._source_health_in_transaction(connection)
            publication = self._evidence_publication_status_in_transaction(connection)
            publication["registered_unverified_objects"] = cast(
                int,
                connection.execute(
                    "SELECT COUNT(*) FROM encrypted_object_locations l "
                    "JOIN objects o USING(object_id) WHERE o.storage_kind = 'local'"
                ).fetchone()[0],
            )
            object_count = connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
            local_copies = self._local_copy_observation(connection, object_count)
            connection.rollback()
        return {
            "status": status,
            "sources": sources,
            "publication": publication,
            "local_copies": local_copies,
        }

    def administration_snapshot(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            snapshot = self._administration_snapshot_in_transaction(connection)
            connection.rollback()
        return snapshot

    def audit_attachments(
        self, *, max_objects: int = 1000, max_total_bytes: int = 64 * 1024 * 1024
    ) -> AttachmentAudit:
        if type(max_objects) is not int or not 1 <= max_objects <= 10000:
            raise ValueError("attachment audit object limit must be between 1 and 10000")
        if type(max_total_bytes) is not int or not 0 <= max_total_bytes <= 256 * 1024 * 1024:
            raise ValueError("attachment audit read budget must be between 0 and 256 MiB")
        items: list[AttachmentAuditItem] = []
        reserved = 0
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            generation = _ledger_generation_digest(connection)
            total = cast(
                int,
                connection.execute("SELECT COUNT(*) FROM web_export_attachment_objects").fetchone()[
                    0
                ],
            )
            rows = connection.execute(
                "SELECT a.attachment_source_object_id,a.object_id,a.byte_length,a.media_type,"
                "o.object_path,o.storage_kind,o.byte_length,a.plaintext_sha256 "
                "FROM web_export_attachment_objects a JOIN objects o USING(object_id) "
                "ORDER BY a.attachment_source_object_id LIMIT ?",
                (max_objects,),
            ).fetchall()
            for (
                identity,
                object_id,
                size,
                media_type,
                relative,
                storage_kind,
                object_size,
                digest,
            ) in rows:
                item: AttachmentAuditItem = {
                    "attachment_id_sha256": _sha256_text(identity),
                    "byte_length": size,
                    "finding": "integrity_unverified",
                    "hash_verified": False,
                }
                items.append(item)
                if (
                    SHA256_HEX.fullmatch(digest) is None
                    or object_id != f"sha256:{digest}"
                    or relative != f"objects/sha256/{digest[:2]}/{digest}"
                    or size != object_size
                ):
                    continue
                try:
                    reference = _publication_object_target(connection, object_id)
                except (KeyError, RuntimeError):
                    item["finding"] = "reference_unresolved_or_excluded"
                    continue
                # Unsupported inspection is not evidence of a privacy marker or a secret.
                if storage_kind != "local":
                    item["finding"] = "remote_not_read"
                    continue
                if media_type not in TEXT_ATTACHMENT_MEDIA_TYPES:
                    item["finding"] = "inspection_unsupported"
                    continue
                if size > DEFAULT_MAX_RECORD_BYTES:
                    item["finding"] = "size_limit"
                    continue
                if reserved + size + 1 > max_total_bytes:
                    item["finding"] = "read_budget"
                    continue
                reserved += size + 1
                try:
                    descriptor, _ = open_regular_file_no_symlinks(
                        self.settings.data_root / relative, "attachment audit object"
                    )
                    with os.fdopen(descriptor, "rb") as handle:
                        before = os.fstat(handle.fileno())
                        if (
                            before.st_size != size
                            or before.st_uid != os.getuid()
                            or before.st_nlink != 1
                        ):
                            continue
                        raw = handle.read(size + 1)
                        after = os.fstat(handle.fileno())
                    if (
                        _stat_identity(before) != _stat_identity(after)
                        or len(raw) != size
                        or hashlib.sha256(raw).hexdigest() != digest
                    ):
                        continue
                except (OSError, ValueError):
                    continue
                item["hash_verified"] = True
                decision = classify_attachment(
                    SourceSystem(reference[5]),
                    media_type,
                    raw,
                    max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
                )
                if decision.accepted:
                    item["finding"] = "text_admission_passed"
                elif decision.reason in {
                    "attachment_content_not_inspectable",
                    "uninspectable_record",
                }:
                    item["finding"] = "inspection_unsupported"
                else:
                    item["finding"] = decision.reason
            connection.rollback()
        if self.generation_digest() != generation:
            raise RuntimeError("ledger changed during attachment audit; discard and retry")
        return {
            "text_free": True,
            "scope": "registered_local_attachments",
            "generation_digest": generation,
            "registered_attachments": total,
            "unchecked_attachments": total - len(items),
            "read_budget_reserved_bytes": reserved,
            "findings": dict(Counter(item["finding"] for item in items)),
            "items": items,
            "admission_policy_changed": False,
        }

    def _administration_snapshot_in_transaction(
        self,
        connection: sqlite3.Connection,
    ) -> dict[str, Any]:
        contexts = connection.execute(
            """
            SELECT context.context_id, context.kind, context.context_key, context.label,
                   (SELECT COUNT(*) FROM event_contexts link
                    WHERE link.context_id = context.context_id),
                   (SELECT COUNT(*) FROM source_stream_contexts link
                    WHERE link.context_id = context.context_id),
                   (SELECT COUNT(*) FROM memory_candidate_contexts link
                    WHERE link.context_id = context.context_id)
            FROM contexts context
            ORDER BY context.kind, context.label, context.context_id
            LIMIT ?
            """,
            (MAX_ADMIN_ROWS + 1,),
        ).fetchall()
        candidates = connection.execute(
            """
            SELECT candidate.memory_id, candidate.memory_type, candidate.statement,
                   candidate.statement_digest, candidate.authority, candidate.scope,
                   candidate.project_id, candidate.temporal_status,
                   candidate.evidence_event_ids_json, candidate.created_by,
                   candidate.created_at, claim.claim_id,
                   CASE
                     WHEN claim.claim_id IS NULL THEN NULL
                     WHEN link.claim_id IS NULL THEN 'pending'
                     ELSE 'reconciled'
                   END,
                   link.event_id
            FROM memory_candidates candidate
            LEFT JOIN memory_candidate_evidence_claims claim
              ON claim.memory_id = candidate.memory_id
            LEFT JOIN memory_candidate_evidence_links link
              ON link.claim_id = claim.claim_id
            ORDER BY candidate.created_at DESC, candidate.memory_id
            LIMIT ?
            """,
            (MAX_ADMIN_ROWS + 1,),
        ).fetchall()
        corrections = connection.execute(
            """
            SELECT correction_id, event_id, event_type, actor_kind, assistant,
                   authority, scope, project_id, privacy, content_digest,
                   parser_version, previous_state_digest, new_state_digest,
                   reason, authorized_by, authorization_scope, created_at
            FROM event_corrections
            ORDER BY correction_sequence DESC, correction_id
            LIMIT ?
            """,
            (MAX_ADMIN_ROWS + 1,),
        ).fetchall()
        clients = connection.execute(
            """
            SELECT client.client_id, client.label, client.kind, client.status,
                   client.created_at, client.revoked_at,
                   GROUP_CONCAT(capability.capability, ','),
                   (SELECT COUNT(*) FROM client_credentials credential
                    WHERE credential.client_id = client.client_id
                      AND credential.revoked_at IS NULL
                      AND credential.expires_at > ?)
            FROM clients client
            LEFT JOIN client_capabilities capability
              ON capability.client_id = client.client_id
            GROUP BY client.client_id
            ORDER BY client.created_at DESC, client.client_id
            LIMIT ?
            """,
            (_now(), MAX_ADMIN_ROWS + 1),
        ).fetchall()
        credentials = connection.execute(
            """
            SELECT credential_id, client_id, expires_at, created_at, revoked_at
            FROM client_credentials
            ORDER BY created_at DESC, credential_id
            LIMIT ?
            """,
            (MAX_ADMIN_ROWS + 1,),
        ).fetchall()
        source_accounts = self._source_account_observations_in_transaction(connection)
        deletions = connection.execute(
            """
            SELECT operation_id, deletion_kind, source_system, status,
                   target_counts_json, previous_generation_digest,
                   new_generation_digest, reason, authorized_by, created_at,
                   completed_at
            FROM deletion_operations
            ORDER BY created_at DESC, operation_id
            LIMIT ?
            """,
            (MAX_ADMIN_ROWS + 1,),
        ).fetchall()
        object_count, object_bytes = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(byte_length), 0) FROM objects"
        ).fetchone()
        local_copies = self._local_copy_observation(connection, object_count)
        encrypted_object_count = connection.execute(
            "SELECT COUNT(*) FROM objects WHERE storage_kind = 'encrypted'"
        ).fetchone()[0]
        pending_publication_count = connection.execute(
            "SELECT COUNT(*) FROM encrypted_object_locations l JOIN objects o USING(object_id) "
            "WHERE o.storage_kind = 'local'"
        ).fetchone()[0]
        queued_publication_count, queued_publication_bytes = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(o.byte_length), 0) "
            "FROM evidence_publication_work w JOIN objects o USING(object_id)"
        ).fetchone()
        page_count = cast(int, connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = cast(int, connection.execute("PRAGMA page_size").fetchone()[0])
        free_pages = cast(int, connection.execute("PRAGMA freelist_count").fetchone()[0])
        now = datetime.now(UTC)

        def limited(rows: Sequence[sqlite3.Row | tuple[Any, ...]]) -> tuple[list[Any], bool]:
            return list(rows[:MAX_ADMIN_ROWS]), len(rows) > MAX_ADMIN_ROWS

        context_rows, contexts_truncated = limited(contexts)
        candidate_rows, candidates_truncated = limited(candidates)
        correction_rows, corrections_truncated = limited(corrections)
        client_rows, clients_truncated = limited(clients)
        credential_rows, credentials_truncated = limited(credentials)
        source_account_rows, source_accounts_truncated = limited(source_accounts)
        deletion_rows, deletions_truncated = limited(deletions)

        return {
            "contexts": [
                {
                    "context_id": row[0],
                    "kind": row[1],
                    "key": row[2],
                    "label": row[3],
                    "event_count": row[4],
                    "source_stream_count": row[5],
                    "candidate_count": row[6],
                }
                for row in context_rows
            ],
            "candidates": [
                _administration_candidate_record(connection, row) for row in candidate_rows
            ],
            "corrections": [
                {
                    "correction_id": row[0],
                    "event_id": row[1],
                    "event_type": row[2],
                    "actor_kind": row[3],
                    "assistant": row[4],
                    "authority": row[5],
                    "scope": row[6],
                    "project_id": row[7],
                    "privacy": row[8],
                    "content_digest": row[9],
                    "parser_version": row[10],
                    "previous_state_digest": row[11],
                    "new_state_digest": row[12],
                    "reason": row[13],
                    "authorized_by": row[14],
                    "authorization_scope": row[15],
                    "created_at": row[16],
                }
                for row in correction_rows
            ],
            "clients": [
                {
                    "client_id": row[0],
                    "label": row[1],
                    "kind": row[2],
                    "status": row[3],
                    "created_at": row[4],
                    "revoked_at": row[5],
                    "capabilities": sorted(cast(str, row[6]).split(",")) if row[6] else [],
                    "active_credential_count": row[7],
                }
                for row in client_rows
            ],
            "credentials": [
                {
                    "credential_id": row[0],
                    "client_id": row[1],
                    "expires_at": row[2],
                    "created_at": row[3],
                    "revoked_at": row[4],
                    "status": (
                        "revoked"
                        if row[4] is not None
                        else "expired"
                        if _parse_timestamp(cast(str, row[2])) <= now
                        else "active"
                    ),
                }
                for row in credential_rows
            ],
            "source_accounts": [
                {
                    "source_account_id": row[0],
                    "device_id": row[1],
                    "source_system": row[2],
                    "label": row[3],
                    "status": row[4],
                    "created_at": row[5],
                    "scope": row[6],
                    "project_id": row[7],
                    "device_label": row[8],
                    "device_status": row[9],
                    "latest_native_admission_at": row[10],
                    "latest_web_observation_at": row[11],
                    "collector_liveness": "not_observed_by_node",
                    "freshness_guaranteed": False,
                }
                for row in source_account_rows
            ],
            "deletions": [
                {
                    "operation_id": row[0],
                    "kind": row[1],
                    "source_system": row[2],
                    "status": row[3],
                    "target_counts": _validated_count_object(row[4]),
                    "previous_generation_digest": row[5],
                    "new_generation_digest": row[6],
                    "reason": row[7],
                    "authorized_by": row[8],
                    "created_at": row[9],
                    "completed_at": row[10],
                }
                for row in deletion_rows
            ],
            "storage": {
                "backend": "ledger_object_locations"
                if encrypted_object_count
                else "local_filesystem",
                "application_encryption": "mapped_objects_only"
                if encrypted_object_count
                else "none",
                "mapped_encrypted_objects": encrypted_object_count,
                "pending_encrypted_publications": pending_publication_count,
                "queued_publication_objects": queued_publication_count,
                "queued_publication_bytes": queued_publication_bytes,
                "local_copy_residency": "partial"
                if local_copies["uninspected_objects"] or local_copies["uninspectable_objects"]
                else "observed",
                "local_copies": local_copies,
                "object_bytes_basis": "registered_plaintext",
                "object_count": object_count,
                "object_bytes": object_bytes,
                "database_bytes": page_count * page_size,
                "database_free_bytes": free_pages * page_size,
            },
            "recovery": {
                "last_successful_backup": None,
                "last_verified_restore": None,
                "status": "not_recorded_by_node",
            },
            "truncated": {
                "contexts": contexts_truncated,
                "candidates": candidates_truncated,
                "corrections": corrections_truncated,
                "clients": clients_truncated,
                "credentials": credentials_truncated,
                "source_accounts": source_accounts_truncated,
                "deletions": deletions_truncated,
            },
        }

    def _local_copy_observation(
        self, connection: sqlite3.Connection, object_count: int
    ) -> LocalCopyObservation:
        rows = connection.execute(
            "SELECT object_id, plaintext_digest, object_path, storage_kind, byte_length "
            "FROM objects ORDER BY object_id LIMIT ?",
            (MAX_RESIDENCY_OBJECTS,),
        ).fetchall()
        observation: LocalCopyObservation = {
            "scope": "registered_object_paths",
            "inspection_limit": MAX_RESIDENCY_OBJECTS,
            "inspected_objects": len(rows),
            "uninspected_objects": object_count - len(rows),
            "present_objects": 0,
            "logical_file_bytes": 0,
            "encrypted_mapped_present_objects": 0,
            "encrypted_mapped_present_bytes": 0,
            "absent_encrypted_objects": 0,
            "missing_local_objects": 0,
            "uninspectable_objects": 0,
            "size_mismatch_objects": 0,
        }
        # Registry snapshot, best-effort filesystem metadata; no content or provider verification.
        for object_id, digest, relative, storage_kind, registered_bytes in rows:
            if (
                SHA256_HEX.fullmatch(digest) is None
                or object_id != f"sha256:{digest}"
                or relative != f"objects/sha256/{digest[:2]}/{digest}"
            ):
                observation["uninspectable_objects"] += 1
                continue
            try:
                metadata = secure_path_stat(self.settings.data_root / relative, "local evidence")
            except (OSError, ValueError) as error:
                if isinstance(error, FileNotFoundError) or isinstance(
                    error.__cause__, FileNotFoundError
                ):
                    if storage_kind == "encrypted":
                        observation["absent_encrypted_objects"] += 1
                    else:
                        observation["missing_local_objects"] += 1
                else:
                    observation["uninspectable_objects"] += 1
                continue
            observation["present_objects"] += 1
            observation["logical_file_bytes"] += metadata.st_size
            if storage_kind == "encrypted":
                observation["encrypted_mapped_present_objects"] += 1
                observation["encrypted_mapped_present_bytes"] += metadata.st_size
            if metadata.st_size != registered_bytes:
                observation["size_mismatch_objects"] += 1
        return observation

    def completed_deletion_operation(self, operation_id: str) -> dict[str, Any]:
        if DELETION_OPERATION_ID.fullmatch(operation_id) is None:
            raise ValueError("deletion operation id is invalid")
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT plan_sha256, deletion_kind, source_system, target_digest,
                       previous_generation_digest, new_generation_digest,
                       status, target_counts_json
                FROM deletion_operations
                WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"deletion operation not found: {operation_id}")
        plan_sha256 = cast(str, row[0])
        target_digest = cast(str, row[3])
        previous_generation = cast(str, row[4])
        new_generation = cast(str | None, row[5])
        if cast(str, row[6]) != "complete" or new_generation is None:
            raise RuntimeError("deletion operation is not complete")
        _validate_sha256(plan_sha256, "deletion plan")
        if operation_id != f"deletion:{plan_sha256}":
            raise RuntimeError("deletion operation id does not match its plan")
        _validate_sha256(target_digest, "deletion target")
        _validate_sha256(previous_generation, "previous ledger generation")
        _validate_sha256(new_generation, "new ledger generation")
        try:
            raw_counts: object = json.loads(cast(str, row[7]))
        except json.JSONDecodeError as error:
            raise RuntimeError("deletion operation counts are invalid") from error
        if not isinstance(raw_counts, dict):
            raise RuntimeError("deletion operation counts are invalid")
        counts = _validated_deletion_counts(cast(dict[str, int], raw_counts))
        return {
            "operation_id": operation_id,
            "plan_sha256": plan_sha256,
            "kind": DeletionKind(cast(str, row[1])).value,
            "source_system": SourceSystem(cast(str, row[2])).value,
            "target_digest": target_digest,
            "previous_generation_digest": previous_generation,
            "new_generation_digest": new_generation,
            "target_counts": counts,
        }

    def plan_deletion(
        self,
        *,
        kind: DeletionKind,
        source_system: SourceSystem,
        source_account: str,
        conversation_id: str | None,
        retirement_pairs: Sequence[ObservationRetirement] = (),
    ) -> dict[str, Any]:
        normalized_account = _bounded_identity_value(source_account, "source account")
        normalized_conversation = (
            _bounded_identity_value(conversation_id, "conversation id")
            if conversation_id is not None
            else None
        )
        if kind is DeletionKind.CONVERSATION and normalized_conversation is None:
            raise ValueError("conversation deletion requires a conversation id")
        if kind is DeletionKind.SOURCE_ACCOUNT and normalized_conversation is not None:
            raise ValueError("source-account deletion cannot include a conversation id")
        if kind is DeletionKind.WEB_CONTAINERS and normalized_conversation is not None:
            raise ValueError("web-container retirement cannot include a conversation id")
        if kind is DeletionKind.OBSOLETE_OBSERVATIONS:
            if source_system not in {
                SourceSystem.CODEX,
                SourceSystem.CLAUDE_CODE,
                SourceSystem.GROK_BUILD,
            }:
                raise ValueError("observation retirement requires a native source")
            if normalized_conversation is None:
                raise ValueError("observation retirement requires a conversation")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            selector = _build_deletion_selector(
                connection,
                kind=kind,
                source_system=source_system,
                source_account=normalized_account,
                conversation_id=normalized_conversation,
                retirement_pairs=retirement_pairs,
            )
            target = _collect_deletion_target(connection, selector)
            self._verify_retained_replacements(connection, target, source_system)
            encrypted_targets = self._encrypted_deletion_targets(
                connection, target.deletable_object_ids
            )
            generation = _ledger_generation_digest(connection)
            connection.rollback()
        if kind is DeletionKind.CONVERSATION and not (
            target.source_file_ids
            or target.event_ids
            or target.memory_claim_ids
            or target.web_observation_ids
        ):
            raise KeyError("conversation not found for the selected source account")
        if kind is DeletionKind.WEB_CONTAINERS and not target.web_container_retirement_ids:
            raise KeyError("retained web containers not found for the selected source account")
        if (
            kind in {DeletionKind.NO_MEMORY_RECORDS, DeletionKind.OBSOLETE_OBSERVATIONS}
            and not target.event_ids
        ):
            raise KeyError("no-memory records not found for the selected source account")
        return {
            "kind": selector.kind.value,
            "source_system": selector.source_system.value,
            "source_account_digests": list(selector.source_account_digests),
            "conversation_digest": selector.conversation_digest,
            "expected_generation_digest": generation,
            "target_digest": target.digest(selector),
            "target_counts": target.counts(),
            "encrypted_targets": [item.as_dict() for item in encrypted_targets],
        }

    def _verify_retained_replacements(
        self, connection: sqlite3.Connection, target: _DeletionTarget, source_system: SourceSystem
    ) -> None:
        for event_id in sorted(target.retained_replacement_event_ids):
            state = _current_event_state(connection, event_id)
            raw = self._read_event_object(connection, event_id)
            decision = classify_record(
                source_system,
                state["content_text"],
                raw,
                max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
            )
            if not decision.accepted:
                raise RuntimeError("retained replacement fails current admission")

    def _encrypted_deletion_targets(
        self,
        connection: sqlite3.Connection,
        object_ids: frozenset[str],
        expected: Sequence[EncryptedDeletionTarget] | None = None,
    ) -> tuple[EncryptedDeletionTarget, ...]:
        purger = self._encrypted_evidence_purger
        if purger is None:
            _require_local_deletion_objects(connection, object_ids)
            if expected:
                raise RuntimeError("encrypted deletion requires its configured purger")
            return ()
        retained = {item.object_id: item for item in expected or ()}
        if expected is not None and len(retained) != len(expected):
            raise ValueError("encrypted deletion target identities must be unique")
        locations: dict[str, tuple[int, str, EncryptedObjectManifest]] = {}
        for object_id in sorted(object_ids):
            row = connection.execute(
                "SELECT byte_length, storage_kind FROM objects WHERE object_id = ?", (object_id,)
            ).fetchone()
            if row is None:
                raise RuntimeError("deletion object metadata is missing")
            location = read_location(connection, object_id)
            require_mapping_state(cast(str, row[1]), location)
            if location is not None:
                locations[object_id] = (cast(int, row[0]), *location)
        if expected is not None and set(retained) != set(locations):
            raise RuntimeError("encrypted deletion targets differ from current mappings")
        result: list[EncryptedDeletionTarget] = []
        for object_id, (byte_length, identity, manifest) in locations.items():
            if expected is None:
                result.append(
                    purger.plan(
                        data_root=self.settings.data_root,
                        object_id=object_id,
                        byte_length=byte_length,
                        backend_identity_sha256=identity,
                        manifest=manifest,
                    )
                )
            else:
                purger.validate(
                    retained[object_id],
                    data_root=self.settings.data_root,
                    object_id=object_id,
                    byte_length=byte_length,
                    backend_identity_sha256=identity,
                    manifest=manifest,
                )
                result.append(retained[object_id])
        return tuple(result)

    def require_ingest_allowed(
        self,
        *,
        source_system: SourceSystem,
        source_account: str,
        conversation_ids: Sequence[str],
    ) -> None:
        if not conversation_ids:
            raise ValueError("at least one conversation id is required")
        with closing(self._connect()) as connection:
            for conversation_id in conversation_ids:
                _require_not_tombstoned(
                    connection,
                    source_system=source_system,
                    source_account=source_account,
                    conversation_id=conversation_id,
                )

    def apply_deletion(
        self,
        *,
        kind: DeletionKind,
        source_system: SourceSystem,
        source_account_digests: Sequence[str],
        conversation_digest: str | None,
        expected_generation_digest: str,
        expected_target_digest: str,
        expected_target_counts: dict[str, int],
        plan_sha256: str,
        authorized_by: str,
        authorization_scope: str,
        reason: str,
        encrypted_targets: Sequence[EncryptedDeletionTarget] = (),
        retirement_pairs: Sequence[ObservationRetirement] = (),
    ) -> dict[str, Any]:
        self._require_writable()
        token = self._exclusive_writer_token
        if token is None or not token.active:
            raise RuntimeError("deletion requires an exclusive ledger writer")
        selector = _validated_deletion_selector(
            kind=kind,
            source_system=source_system,
            source_account_digests=source_account_digests,
            conversation_digest=conversation_digest,
            retirement_pairs=retirement_pairs,
        )
        _validate_sha256(expected_generation_digest, "expected ledger generation")
        _validate_sha256(expected_target_digest, "expected deletion target")
        _validate_sha256(plan_sha256, "deletion plan")
        normalized_counts = _validated_deletion_counts(expected_target_counts)
        normalized_authorizer = _bounded_identity_value(authorized_by, "deletion authorizer")
        normalized_scope = _bounded_identity_value(
            authorization_scope, "deletion authorization scope"
        )
        normalized_reason = _bounded_identity_value(reason, "deletion reason")
        operation_id = f"deletion:{plan_sha256}"
        encrypted_work = {
            item.object_id: _serialize_encrypted_deletion_target(item) for item in encrypted_targets
        }
        if len(encrypted_work) != len(encrypted_targets):
            raise ValueError("encrypted deletion target identities must be unique")

        with closing(self._connect()) as connection:
            existing = connection.execute(
                """
                SELECT deletion_kind, source_system, target_digest,
                       previous_generation_digest, new_generation_digest,
                       status, target_counts_json, authorized_by,
                       authorization_scope, reason
                FROM deletion_operations
                WHERE operation_id = ? AND plan_sha256 = ?
                """,
                (operation_id, plan_sha256),
            ).fetchone()
        if existing is not None:
            _verify_existing_deletion_operation(
                existing,
                selector=selector,
                target_digest=expected_target_digest,
                target_counts=normalized_counts,
                authorized_by=normalized_authorizer,
                authorization_scope=normalized_scope,
                reason=normalized_reason,
            )
            with closing(self._connect()) as connection:
                retained_work = dict(
                    connection.execute(
                        "SELECT object_id, encrypted_purge_json FROM deletion_object_work "
                        "WHERE operation_id = ? AND encrypted_purge_json IS NOT NULL",
                        (operation_id,),
                    ).fetchall()
                )
            if retained_work != encrypted_work:
                raise RuntimeError("encrypted deletion work conflicts with the supplied plan")
            return self._finish_deletion_operation(operation_id, resumed=True)

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                previous_generation = _ledger_generation_digest(connection)
                if previous_generation != expected_generation_digest:
                    raise RuntimeError(
                        "ledger generation changed after the deletion plan was created"
                    )
                target = _collect_deletion_target(connection, selector)
                self._verify_retained_replacements(connection, target, source_system)
                if self._encrypted_evidence_purger is None:
                    _require_local_deletion_objects(connection, target.deletable_object_ids)
                if (
                    selector.kind is DeletionKind.WEB_CONTAINERS
                    and not target.web_container_retirement_ids
                ):
                    raise RuntimeError("retained web containers are absent; nothing to retire")
                if target.digest(selector) != expected_target_digest:
                    raise RuntimeError("deletion target changed after planning")
                if target.counts() != normalized_counts:
                    raise RuntimeError("deletion target counts changed after planning")
                self._encrypted_deletion_targets(
                    connection, target.deletable_object_ids, encrypted_targets
                )
                object_rows = _deletion_object_rows(connection, target.deletable_object_ids)
                if set(object_rows) != set(target.deletable_object_ids):
                    raise RuntimeError("deletion target object metadata is incomplete")
                for object_id, (object_path, byte_length) in sorted(object_rows.items()):
                    path = _validated_deletion_object_path(self.settings, object_path, object_id)
                    if object_id not in encrypted_work or path.exists() or path.is_symlink():
                        self._verify_deletion_object_file(object_path, object_id, byte_length)

                created_at = _now()
                connection.execute(
                    """
                    INSERT INTO deletion_operations(
                      operation_id, plan_sha256, deletion_kind, source_system,
                      target_digest, previous_generation_digest,
                      new_generation_digest, status, target_counts_json,
                      authorized_by, authorization_scope, reason, created_at,
                      completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL, 'purging', ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        operation_id,
                        plan_sha256,
                        selector.kind.value,
                        selector.source_system.value,
                        expected_target_digest,
                        previous_generation,
                        json.dumps(normalized_counts, separators=(",", ":"), sort_keys=True),
                        normalized_authorizer,
                        normalized_scope,
                        normalized_reason,
                        created_at,
                    ),
                )
                tombstone_accounts = (
                    selector.source_account_digests
                    if selector.kind in {DeletionKind.CONVERSATION, DeletionKind.SOURCE_ACCOUNT}
                    else ()
                )
                for account_digest in tombstone_accounts:
                    tombstone_id = _stable_id(
                        "deletion_tombstone",
                        selector.kind.value,
                        selector.source_system.value,
                        account_digest,
                        selector.conversation_digest or "all",
                    )
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO deletion_tombstones(
                          tombstone_id, deletion_kind, source_system,
                          source_account_digest, conversation_digest,
                          operation_id, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            tombstone_id,
                            selector.kind.value,
                            selector.source_system.value,
                            account_digest,
                            selector.conversation_digest,
                            operation_id,
                            created_at,
                        ),
                    )

                for conversation_hash, match_kind, match_digest in sorted(target.record_tombstones):
                    for account_digest in selector.source_account_digests:
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO record_deletion_tombstones(
                              source_system, source_account_digest, conversation_digest,
                              match_kind, match_digest, operation_id, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                selector.source_system.value,
                                account_digest,
                                conversation_hash,
                                match_kind,
                                match_digest,
                                operation_id,
                                created_at,
                            ),
                        )
                _delete_target_rows(connection, target)
                unreferenced = _unreferenced_deletion_objects(
                    connection, target.object_candidate_ids
                )
                if unreferenced != set(target.deletable_object_ids):
                    raise RuntimeError("object references changed during deletion")
                for object_id in sorted(target.deletable_object_ids):
                    object_path, byte_length = object_rows[object_id]
                    connection.execute(
                        """
                        INSERT INTO deletion_object_work(
                          operation_id, object_id, object_path, byte_length,
                          status, completed_at, encrypted_purge_json
                        ) VALUES (?, ?, ?, ?, 'pending', NULL, ?)
                        """,
                        (
                            operation_id,
                            object_id,
                            object_path,
                            byte_length,
                            encrypted_work.get(object_id),
                        ),
                    )
                _install_deletion_ids(connection, "object_ids", target.deletable_object_ids)
                connection.execute(
                    "DELETE FROM encrypted_object_locations "
                    "WHERE object_id IN (SELECT value FROM temp.cam_delete_object_ids)"
                )
                connection.execute(
                    """
                    DELETE FROM objects
                    WHERE object_id IN (SELECT value FROM temp.cam_delete_object_ids)
                    """
                )
                _replace_events_fts(connection)
                foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
                if foreign_key_errors:
                    raise RuntimeError("database foreign-key check failed after deletion")
                new_generation = _ledger_generation_digest(connection)
                previous_mutation_digest = _latest_mutation_digest(connection)
                mutation_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO mutation_receipts(
                      mutation_id, target_id, operation, previous_version_digest,
                      new_version_digest, authorized_by, authorization_scope,
                      reason, created_at, previous_mutation_digest
                    ) VALUES (?, ?, 'delete_evidence', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mutation_id,
                        expected_target_digest,
                        previous_generation,
                        new_generation,
                        normalized_authorizer,
                        normalized_scope,
                        normalized_reason,
                        created_at,
                        previous_mutation_digest,
                    ),
                )
                connection.execute(
                    """
                    UPDATE deletion_operations
                    SET new_generation_digest = ?
                    WHERE operation_id = ?
                    """,
                    (new_generation, operation_id),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return self._finish_deletion_operation(operation_id, resumed=False)

    def _finish_deletion_operation(self, operation_id: str, *, resumed: bool) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            operation = connection.execute(
                """
                SELECT status, target_counts_json, previous_generation_digest,
                       new_generation_digest
                FROM deletion_operations
                WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if operation is None:
                raise RuntimeError("deletion operation receipt is missing")
            status = cast(str, operation[0])
            counts = cast(dict[str, int], json.loads(cast(str, operation[1])))
            previous_generation = cast(str, operation[2])
            new_generation = cast(str | None, operation[3])
            if new_generation is None:
                raise RuntimeError("deletion operation has no post-mutation generation")
            if status == "complete":
                return _deletion_result(
                    operation_id,
                    counts,
                    previous_generation,
                    new_generation,
                    resumed=True,
                )
            if status != "purging":
                raise RuntimeError("deletion operation has an invalid state")
            rows = connection.execute(
                """
                SELECT object_id, object_path, byte_length, encrypted_purge_json
                FROM deletion_object_work
                WHERE operation_id = ? AND status = 'pending'
                ORDER BY object_id
                """,
                (operation_id,),
            ).fetchall()
            pending_ids = {cast(str, row[0]) for row in rows}
            _require_local_deletion_objects(connection, pending_ids)
            if (
                _rows_matching_ids(
                    connection,
                    "SELECT object_id FROM objects WHERE object_id IN ({placeholders})",
                    pending_ids,
                )
                or _unreferenced_deletion_objects(connection, pending_ids) != pending_ids
            ):
                raise RuntimeError(
                    "pending deletion objects acquired retained references; explicit remediation "
                    "is required before purge can resume"
                )
            if any(row[3] is not None for row in rows) and self._encrypted_evidence_purger is None:
                raise RuntimeError("pending encrypted deletion requires its configured purger")
            for row in rows:
                object_id = cast(str, row[0])
                if row[3] is not None:
                    encrypted_target = _load_encrypted_deletion_target(cast(str, row[3]))
                    if encrypted_target.object_id != object_id:
                        raise RuntimeError("pending encrypted deletion identity is invalid")
                    purger = self._encrypted_evidence_purger
                    if purger is None:
                        raise RuntimeError("encrypted deletion purger is unavailable")
                    purger.purge(encrypted_target, data_root=self.settings.data_root)
                self._delete_object_file_for_operation(
                    cast(str, row[1]), object_id, cast(int, row[2])
                )
                completed_at = _now()
                connection.execute(
                    """
                    UPDATE deletion_object_work
                    SET status = 'deleted', completed_at = ?
                    WHERE operation_id = ? AND object_id = ? AND status = 'pending'
                    """,
                    (completed_at, operation_id, object_id),
                )
                connection.commit()

            pending = cast(
                int,
                connection.execute(
                    """
                    SELECT COUNT(*) FROM deletion_object_work
                    WHERE operation_id = ? AND status != 'deleted'
                    """,
                    (operation_id,),
                ).fetchone()[0],
            )
            if pending:
                raise RuntimeError("deletion object purge is incomplete")
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or cast(int, checkpoint[0]) != 0:
                raise RuntimeError("deletion vacuum is waiting for active ledger readers")
            connection.execute("VACUUM")
            integrity = cast(str, connection.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity != "ok":
                raise RuntimeError(f"database integrity check failed after deletion: {integrity}")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise RuntimeError("database foreign-key check failed after deletion vacuum")
            completed_at = _now()
            connection.execute(
                """
                UPDATE deletion_operations
                SET status = 'complete', completed_at = ?
                WHERE operation_id = ? AND status = 'purging'
                """,
                (completed_at, operation_id),
            )
            connection.commit()
        return _deletion_result(
            operation_id,
            counts,
            previous_generation,
            new_generation,
            resumed=resumed,
        )

    def _verify_deletion_object_file(
        self, relative_path: str, object_id: str, expected_size: int
    ) -> None:
        path = _validated_deletion_object_path(self.settings, relative_path, object_id)
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError(f"deletion object must be a single-link regular file: {object_id}")
        _stream_verify_object(path, object_id, expected_size)

    def _delete_object_file_for_operation(
        self, relative_path: str, object_id: str, expected_size: int
    ) -> None:
        path = _validated_deletion_object_path(self.settings, relative_path, object_id)
        # Flush observed absence on retry too, before the journal marks this object complete.
        parent = (
            path.parent
            if path.parent.exists()
            else self.settings.data_root.resolve() / "objects" / "sha256"
        )
        descriptor = open_directory_no_symlinks(parent, "deletion object directory")
        try:
            if path.exists() or path.is_symlink():
                before = secure_path_stat(path, "deletion object")
                self._verify_deletion_object_file(relative_path, object_id, expected_size)
                if _stat_identity(
                    os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
                ) != _stat_identity(before):
                    raise RuntimeError("deletion object changed before unlink")
                os.unlink(path.name, dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _status_in_transaction(self, connection: sqlite3.Connection) -> dict[str, Any]:
        stream_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM source_streams").fetchone()[0]
        )
        source_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM source_files").fetchone()[0]
        )
        event_count = cast(int, connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        quarantine_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM quarantines").fetchone()[0]
        )
        candidate_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM memory_candidates").fetchone()[0]
        )
        pending_candidate_evidence_count = cast(
            int,
            connection.execute(
                """
                SELECT COUNT(*)
                FROM memory_candidate_evidence_claims claim
                LEFT JOIN memory_candidate_evidence_links link
                  ON link.claim_id = claim.claim_id
                WHERE link.claim_id IS NULL
                """
            ).fetchone()[0],
        )
        reconciled_candidate_evidence_count = cast(
            int,
            connection.execute("SELECT COUNT(*) FROM memory_candidate_evidence_links").fetchone()[
                0
            ],
        )
        correction_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM event_corrections").fetchone()[0]
        )
        device_count = cast(int, connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
        source_account_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM source_accounts").fetchone()[0]
        )
        registered_source_account_count = cast(
            int,
            connection.execute("SELECT COUNT(*) FROM source_account_policies").fetchone()[0],
        )
        upload_batch_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM upload_batches").fetchone()[0]
        )
        active_source_schema_authorization_count = cast(
            int,
            connection.execute(
                "SELECT COUNT(*) FROM source_schema_authorizations WHERE status = 'active'"
            ).fetchone()[0],
        )
        web_export_batch_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM web_export_batches").fetchone()[0]
        )
        web_export_observation_count = cast(
            int,
            connection.execute(
                "SELECT COUNT(*) FROM web_export_conversation_observations"
            ).fetchone()[0],
        )
        context_count = cast(int, connection.execute("SELECT COUNT(*) FROM contexts").fetchone()[0])
        client_count = cast(int, connection.execute("SELECT COUNT(*) FROM clients").fetchone()[0])
        now = _now()
        active_credential_count = cast(
            int,
            connection.execute(
                """
                SELECT COUNT(*)
                FROM client_credentials
                WHERE revoked_at IS NULL AND expires_at > ?
                """,
                (now,),
            ).fetchone()[0],
        )
        pending_enrollment_count = cast(
            int,
            connection.execute(
                """
                SELECT COUNT(*)
                FROM device_enrollments
                WHERE redeemed_at IS NULL AND expires_at > ?
                """,
                (now,),
            ).fetchone()[0],
        )
        deletion_tombstone_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM deletion_tombstones").fetchone()[0]
        )
        record_tombstone_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM record_deletion_tombstones").fetchone()[0]
        )
        pending_deletion_count = cast(
            int,
            connection.execute(
                "SELECT COUNT(*) FROM deletion_operations WHERE status = 'purging'"
            ).fetchone()[0],
        )
        completed_deletion_count = cast(
            int,
            connection.execute(
                "SELECT COUNT(*) FROM deletion_operations WHERE status = 'complete'"
            ).fetchone()[0],
        )
        latest = connection.execute("SELECT MAX(ingested_at) FROM source_files").fetchone()[0]
        generation_digest = _ledger_generation_digest(connection)
        return {
            "schema_version": SCHEMA_VERSION,
            "database_path": str(self.settings.database_path),
            "devices": device_count,
            "source_accounts": source_account_count,
            "registered_source_accounts": registered_source_account_count,
            "upload_batches": upload_batch_count,
            "active_source_schema_authorizations": (active_source_schema_authorization_count),
            "web_export_batches": web_export_batch_count,
            "web_export_conversation_observations": web_export_observation_count,
            "contexts": context_count,
            "clients": client_count,
            "active_client_credentials": active_credential_count,
            "pending_device_enrollments": pending_enrollment_count,
            "deletion_tombstones": deletion_tombstone_count,
            "record_deletion_tombstones": record_tombstone_count,
            "pending_deletions": pending_deletion_count,
            "completed_deletions": completed_deletion_count,
            "source_streams": stream_count,
            "source_files": source_count,
            "events": event_count,
            "quarantined_records": quarantine_count,
            "memory_candidates": candidate_count,
            "pending_memory_evidence_claims": pending_candidate_evidence_count,
            "reconciled_memory_evidence_claims": reconciled_candidate_evidence_count,
            "event_corrections": correction_count,
            "generation_digest": generation_digest,
            "latest_ingested_at": latest,
        }

    @staticmethod
    def _source_freshness_files_cte(
        allowed_accesses: Sequence[Access],
    ) -> tuple[str, tuple[str, ...]]:
        selection = (
            "SELECT source_file_id, source_system, source_account, ingested_at FROM source_files"
        )
        if set(allowed_accesses) == set(Access):
            return f"WITH status_files AS ({selection})", ()
        accesses = tuple(access.value for access in allowed_accesses)
        placeholders = ",".join("?" for _ in accesses)
        # Historical imports can predate stream/cursor tracking; use admitted event access too.
        return (
            f"""
            WITH status_files AS (
              {selection} file
              WHERE EXISTS (
                SELECT 1 FROM source_segments segment
                JOIN source_stream_access access USING(source_stream_id)
                WHERE segment.source_file_id = file.source_file_id
                  AND access.access IN ({placeholders})
              ) OR EXISTS (
                SELECT 1 FROM source_records record
                JOIN events_current event USING(source_record_id)
                JOIN event_access access USING(event_id)
                WHERE record.source_file_id = file.source_file_id
                  AND event.privacy = 'included' AND access.access IN ({placeholders})
              )
            )
            """,
            (*accesses, *accesses),
        )

    def _source_account_observations_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        allowed_accesses: Sequence[Access] = tuple(Access),
    ) -> list[Any]:
        if not allowed_accesses:
            return []
        files_cte, file_parameters = self._source_freshness_files_cte(allowed_accesses)
        scopes = tuple(
            scope.value
            for scope in Scope
            if _access_from_legacy_scope(scope.value) in allowed_accesses
        )
        installation = connection.execute("SELECT installation_id FROM installations").fetchone()
        legacy_device_id = _stable_id("device", installation[0], "legacy-local")
        return connection.execute(
            f"""
            {files_cte}
            SELECT account.source_account_id, account.device_id, account.source_system,
                   account.legacy_account_key, account.status, account.created_at,
                   policy.scope, policy.project_id, device.label, device.status,
                   (SELECT MAX(batch.created_at) FROM upload_batches batch
                    JOIN status_files visible ON visible.source_file_id = batch.source_file_id
                    WHERE batch.source_account_id = account.source_account_id),
                   (SELECT MAX(observation.created_at)
                    FROM web_export_conversation_observations observation
                    JOIN web_export_batches batch USING(batch_id)
                    JOIN status_files visible
                      ON visible.source_file_id = observation.source_file_id
                    WHERE batch.source_account_id = account.source_account_id),
                   (SELECT MAX(file.ingested_at) FROM status_files file
                    WHERE file.source_system = account.source_system
                      AND (file.source_account = account.source_account_id OR (
                        account.device_id = ? AND file.source_account = account.legacy_account_key
                      )))
            FROM source_accounts account
            JOIN devices device ON device.device_id = account.device_id
            LEFT JOIN source_account_policies policy
              ON policy.source_account_id = account.source_account_id
            WHERE ? OR policy.scope IN ({",".join("?" for _ in scopes)}) OR EXISTS (
              SELECT 1 FROM status_files file
              WHERE file.source_system = account.source_system
                AND (file.source_account = account.source_account_id OR (
                  account.device_id = ? AND file.source_account = account.legacy_account_key
                ))
            )
            ORDER BY account.source_system, account.legacy_account_key,
                     account.source_account_id
            LIMIT ?
            """,
            (
                *file_parameters,
                legacy_device_id,
                set(allowed_accesses) == set(Access),
                *scopes,
                legacy_device_id,
                MAX_ADMIN_ROWS + 1,
            ),
        ).fetchall()

    def source_health(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            sources = self._source_health_in_transaction(connection)
            connection.rollback()
        return sources

    def _source_health_in_transaction(
        self,
        connection: sqlite3.Connection,
    ) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        for source_system in SourceSystem:
            file_row = connection.execute(
                """
                SELECT COUNT(*), COUNT(DISTINCT conversation_id), MAX(ingested_at)
                FROM source_files
                WHERE source_system = ?
                """,
                (source_system.value,),
            ).fetchone()
            event_count = cast(
                int,
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM events event
                    JOIN source_records record
                      ON record.source_record_id = event.source_record_id
                    JOIN source_files source
                      ON source.source_file_id = record.source_file_id
                    WHERE source.source_system = ?
                    """,
                    (source_system.value,),
                ).fetchone()[0],
            )
            quarantine_count = cast(
                int,
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM quarantines quarantine
                    JOIN source_files source
                      ON source.source_file_id = quarantine.source_file_id
                    WHERE source.source_system = ?
                    """,
                    (source_system.value,),
                ).fetchone()[0],
            )
            account_count = cast(
                int,
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM source_accounts
                    WHERE source_system = ? AND status = 'active'
                    """,
                    (source_system.value,),
                ).fetchone()[0],
            )
            registered_account_count = cast(
                int,
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM source_accounts account
                    JOIN source_account_policies policy
                      ON policy.source_account_id = account.source_account_id
                    WHERE account.source_system = ? AND account.status = 'active'
                    """,
                    (source_system.value,),
                ).fetchone()[0],
            )
            upload_batch_count = cast(
                int,
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM upload_batches batch
                    JOIN source_accounts account
                      ON account.source_account_id = batch.source_account_id
                    WHERE account.source_system = ?
                    """,
                    (source_system.value,),
                ).fetchone()[0],
            )
            web_export_batch_count = cast(
                int,
                connection.execute(
                    "SELECT COUNT(*) FROM web_export_batches WHERE source_system = ?",
                    (source_system.value,),
                ).fetchone()[0],
            )
            source_file_count = cast(int, file_row[0])
            sources.append(
                {
                    "source_system": source_system.value,
                    "state": (
                        "ready"
                        if source_file_count
                        else "registered"
                        if registered_account_count
                        else "disconnected"
                    ),
                    "active_accounts": account_count,
                    "registered_accounts": registered_account_count,
                    "source_files": source_file_count,
                    "conversations": cast(int, file_row[1]),
                    "events": event_count,
                    "quarantined_records": quarantine_count,
                    "upload_batches": upload_batch_count,
                    "web_export_batches": web_export_batch_count,
                    "latest_ingested_at": cast(str | None, file_row[2]),
                }
            )
        return sources

    def installation_id(self) -> str:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT installation_id FROM installations").fetchone()
        if row is None:
            raise RuntimeError("installation identity is missing")
        return cast(str, row[0])

    def identity_snapshot(self) -> tuple[str, str]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                row = connection.execute("SELECT installation_id FROM installations").fetchone()
                if row is None:
                    raise RuntimeError("installation identity is missing")
                return cast(str, row[0]), _identity_state_digest(connection)
            finally:
                connection.rollback()

    def register_source_account(
        self,
        *,
        device_id: str,
        source_system: SourceSystem,
        account_label: str,
        scope: Scope,
        project_id: str | None,
        created_by: str,
        expected_identity_state_sha256: str | None = None,
        expected_installation_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_writable()
        normalized_device_id = _bounded_identity_value(device_id, "device id")
        normalized_account_label = _bounded_identity_value(account_label, "source account label")
        normalized_creator = _bounded_identity_value(created_by, "source account creator")
        if scope is Scope.PROJECT and not project_id:
            raise ValueError("project_id is required for project-scoped source accounts")
        if scope is not Scope.PROJECT and project_id is not None:
            raise ValueError("only project-scoped source accounts may carry project_id")
        normalized_project_id = (
            _bounded_identity_value(project_id, "project id") if project_id is not None else None
        )
        created_at = _now()
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_identity_digest = _identity_state_digest(connection)
            generation_matches = _identity_precondition_matches(
                connection,
                expected_identity_state_sha256=expected_identity_state_sha256,
                expected_installation_id=expected_installation_id,
            )
            installation_id = _ensure_installation(connection, created_at)
            device = connection.execute(
                """
                SELECT 1
                FROM devices device
                JOIN client_devices binding ON binding.device_id = device.device_id
                JOIN clients client ON client.client_id = binding.client_id
                JOIN client_capabilities capability ON capability.client_id = client.client_id
                WHERE device.device_id = ?
                  AND device.installation_id = ?
                  AND device.status = 'active'
                  AND client.kind = 'collector'
                  AND client.status = 'active'
                  AND client.revoked_at IS NULL
                  AND capability.capability = 'source:upload'
                """,
                (normalized_device_id, installation_id),
            ).fetchone()
            if device is None:
                raise ValueError("active enrolled collector device not found")
            candidate_source_account_id = _stable_id(
                "source_account",
                installation_id,
                normalized_device_id,
                source_system.value,
                normalized_account_label,
            )
            if not generation_matches:
                account = connection.execute(
                    """
                    SELECT status
                    FROM source_accounts
                    WHERE source_account_id = ?
                    """,
                    (candidate_source_account_id,),
                ).fetchone()
                policy = connection.execute(
                    """
                    SELECT scope, project_id, created_by, created_at
                    FROM source_account_policies
                    WHERE source_account_id = ?
                    """,
                    (candidate_source_account_id,),
                ).fetchone()
                if (
                    account is None
                    or cast(str, account[0]) != "active"
                    or policy is None
                    or (cast(str, policy[0]), cast(str | None, policy[1]))
                    != (scope.value, normalized_project_id)
                ):
                    raise RuntimeError("ledger generation changed before source registration")
                return {
                    "source_account_id": candidate_source_account_id,
                    "device_id": normalized_device_id,
                    "source_system": source_system.value,
                    "account_label": normalized_account_label,
                    "scope": scope.value,
                    "project_id": normalized_project_id,
                    "created_by": cast(str, policy[2]),
                    "created_at": cast(str, policy[3]),
                    "replayed": True,
                }
            _require_source_account_registration_allowed(
                connection,
                source_system=source_system,
                aliases=(candidate_source_account_id,),
            )
            source_account_id = _ensure_source_account(
                connection,
                installation_id=installation_id,
                device_id=normalized_device_id,
                source_system=source_system.value,
                legacy_account_key=normalized_account_label,
                now=created_at,
            )
            account = connection.execute(
                """
                SELECT status
                FROM source_accounts
                WHERE source_account_id = ?
                """,
                (source_account_id,),
            ).fetchone()
            if account is None or cast(str, account[0]) != "active":
                raise ValueError("active source account not found")
            existing = connection.execute(
                """
                SELECT scope, project_id, created_by, created_at
                FROM source_account_policies
                WHERE source_account_id = ?
                """,
                (source_account_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO source_account_policies(
                      source_account_id, scope, project_id, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        source_account_id,
                        scope.value,
                        normalized_project_id,
                        normalized_creator,
                        created_at,
                    ),
                )
                policy_creator = normalized_creator
                policy_created_at = created_at
            else:
                if (cast(str, existing[0]), cast(str | None, existing[1])) != (
                    scope.value,
                    normalized_project_id,
                ):
                    raise RuntimeError("source account policy is immutable after registration")
                policy_creator = cast(str, existing[2])
                policy_created_at = cast(str, existing[3])
            _record_identity_mutation(
                connection,
                target_id=source_account_id,
                operation="register_source_account",
                previous_identity_digest=previous_identity_digest,
                authorized_by=normalized_creator,
                authorization_scope=Capability.CLIENT_ADMIN.value,
                reason="source_account_registered",
                created_at=created_at,
            )
        result: dict[str, Any] = {
            "source_account_id": source_account_id,
            "device_id": normalized_device_id,
            "source_system": source_system.value,
            "account_label": normalized_account_label,
            "scope": scope.value,
            "project_id": normalized_project_id,
            "created_by": policy_creator,
            "created_at": policy_created_at,
        }
        if expected_identity_state_sha256 is not None:
            result["replayed"] = existing is not None
        return result

    def verify_source_account_registration(
        self,
        *,
        source_account_id: str,
        source_system: SourceSystem,
        scope: Scope,
        project_id: str | None,
    ) -> dict[str, str | None]:
        with closing(self._connect()) as connection:
            installation = connection.execute(
                "SELECT installation_id FROM installations"
            ).fetchone()
            if installation is None:
                raise RuntimeError("installation identity is missing")
            device_id = _require_registered_source_account(
                connection,
                installation_id=cast(str, installation[0]),
                source_account_id=source_account_id,
                source_system=source_system,
                scope=scope,
                project_id=project_id,
            )
        return {
            "source_account_id": source_account_id,
            "source_system": source_system.value,
            "device_id": device_id,
            "scope": scope.value,
            "project_id": project_id,
        }

    def registered_web_source_accounts(self) -> list[dict[str, str | None]]:
        web_sources = (
            SourceSystem.CHATGPT_WEB.value,
            SourceSystem.CLAUDE_WEB.value,
            SourceSystem.GROK_WEB.value,
        )
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT account.source_account_id, account.source_system, account.device_id,
                       policy.scope, policy.project_id
                FROM source_accounts account
                JOIN source_account_policies policy
                  ON policy.source_account_id = account.source_account_id
                JOIN devices device ON device.device_id = account.device_id
                WHERE account.status = 'active'
                  AND device.status = 'active'
                  AND account.source_system IN (?, ?, ?)
                ORDER BY account.source_system, account.source_account_id
                """,
                web_sources,
            ).fetchall()
        return [
            {
                "source_account_id": cast(str, row[0]),
                "source_system": cast(str, row[1]),
                "device_id": cast(str, row[2]),
                "scope": cast(str, row[3]),
                "project_id": cast(str | None, row[4]),
            }
            for row in rows
        ]

    @contextmanager
    def temporary_web_source_configuration(
        self,
        *,
        source_account_id: str,
        expected_ledger_generation: str,
    ) -> Generator[tuple[Settings, dict[str, Any]], None, None]:
        """Stage only one registration in a fresh ledger, never in an existing target."""
        if not self.read_only:
            raise ValueError("configuration capture requires a read-only ledger")
        _canonical_identity_value(source_account_id, "source account id")
        _validate_sha256(expected_ledger_generation, "expected ledger generation")
        columns = {
            "installations": ("installation_id", "owner_id", "created_at"),
            "source_accounts": (
                "source_account_id",
                "installation_id",
                "device_id",
                "source_system",
                "legacy_account_key",
                "status",
                "created_at",
                "updated_at",
            ),
            "devices": (
                "device_id",
                "installation_id",
                "label",
                "platform",
                "status",
                "created_at",
                "updated_at",
            ),
            "source_account_policies": (
                "source_account_id",
                "scope",
                "project_id",
                "created_by",
                "created_at",
            ),
        }
        rows: dict[str, sqlite3.Row] = {}
        source_identity = secure_path_stat(self.settings.database_path, "configuration source")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            if version is None or version[0] != SCHEMA_VERSION:
                raise RuntimeError("configuration capture requires the current ledger schema")
            validate_current_schema_objects(connection)
            remaining = 64 * 1024
            for table, names in columns.items():
                where = ""
                parameters: tuple[str, ...] = ()
                if table in {"source_accounts", "source_account_policies"}:
                    where, parameters = "WHERE source_account_id = ?", (source_account_id,)
                elif table == "devices":
                    where, parameters = (
                        "WHERE device_id = ?",
                        (rows["source_accounts"]["device_id"],),
                    )
                lengths = " + ".join(f"coalesce(length(cast({name} AS BLOB)), 0)" for name in names)
                sizes = connection.execute(
                    f"SELECT {lengths} FROM {table} {where} LIMIT 2", parameters
                ).fetchall()
                if len(sizes) != 1:
                    raise ValueError(f"configuration requires exactly one selected {table} row")
                remaining -= cast(int, sizes[0][0])
                if remaining < 0:
                    raise ValueError("web source configuration exceeds metadata size limit")
                row = connection.execute(
                    f"SELECT {', '.join(names)} FROM {table} {where} LIMIT 1", parameters
                ).fetchone()
                if row is None or any(
                    value is not None and not isinstance(value, str) for value in row
                ):
                    raise ValueError("web source configuration must contain text metadata")
                rows[table] = row
            installation, account, device, policy = (rows[table] for table in columns)
            source_system = SourceSystem(account["source_system"])
            if source_system not in {
                SourceSystem.CHATGPT_WEB,
                SourceSystem.CLAUDE_WEB,
                SourceSystem.GROK_WEB,
            }:
                raise ValueError("configuration snapshot requires a web source")
            if (
                account["installation_id"] != installation["installation_id"]
                or device["installation_id"] != installation["installation_id"]
            ):
                raise ValueError("web source configuration installation identity mismatch")
            scope = Scope(policy["scope"])
            project_id = cast(str | None, policy["project_id"])
            if scope is Scope.PROJECT:
                _canonical_identity_value(project_id or "", "project id")
            elif project_id is not None:
                raise ValueError("only project-scoped source accounts may carry project_id")
            _require_registered_source_account(
                connection,
                installation_id=installation["installation_id"],
                source_account_id=source_account_id,
                source_system=source_system,
                scope=scope,
                project_id=project_id,
            )
            generation = _ledger_generation_digest(connection)
            if generation != expected_ledger_generation:
                raise RuntimeError("ledger generation changed before configuration capture")

        # All source checks finish before creating any destination artifacts.
        current = secure_path_stat(self.settings.database_path, "configuration source")
        if not os.path.samestat(source_identity, current):
            raise RuntimeError("configuration source database changed during capture")
        if self.require_checkpointed:
            if (
                source_identity.st_size,
                source_identity.st_mtime_ns,
                source_identity.st_ctime_ns,
            ) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns):
                raise RuntimeError("configuration source database changed during capture")
            _reject_read_only_sidecars(self.settings.database_path)
        else:
            _validate_live_read_only_sidecars(self.settings.database_path)
        scratch_parent = Path(tempfile.gettempdir()).resolve()
        if scratch_parent.is_relative_to(self.settings.data_root.resolve()):
            raise ValueError("configuration staging must be outside the source root")
        parent = Path(tempfile.mkdtemp(prefix=".web-source-configuration-", dir=scratch_parent))
        parent_descriptor = open_directory_no_symlinks(parent, "configuration scratch directory")
        staging_name = "registration"
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_descriptor)
        identity = os.stat(staging_name, dir_fd=parent_descriptor, follow_symlinks=False)
        temporary = parent / staging_name
        try:
            settings = Settings(temporary)
            target = Ledger(settings)
            with closing(target._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                # Only schema bootstrap rows may exist before replacing the generated identity.
                for table in connection.execute("PRAGMA table_list").fetchall():
                    name = cast(str, table[1])
                    if (
                        table[2] == "shadow"
                        or name.startswith("sqlite_")
                        or name
                        in {
                            "installations",
                            "schema_migrations",
                        }
                    ):
                        continue
                    quoted = name.replace('"', '""')
                    if connection.execute(f'SELECT 1 FROM "{quoted}" LIMIT 1').fetchone():
                        raise RuntimeError("configuration target is not an empty ledger")
                if connection.execute("SELECT count(*) FROM installations").fetchone()[0] != 1:
                    raise RuntimeError("configuration target has an unexpected installation")
                connection.execute("DELETE FROM installations")
                for table in (
                    "installations",
                    "devices",
                    "source_accounts",
                    "source_account_policies",
                ):
                    names = columns[table]
                    connection.execute(
                        f"INSERT INTO {table} ({', '.join(names)}) "
                        f"VALUES ({', '.join('?' for _ in names)})",
                        tuple(rows[table]),
                    )
                if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise RuntimeError("web source configuration violates foreign keys")
            yield (
                settings,
                {
                    "source_account_id": source_account_id,
                    "source_system": source_system.value,
                    "scope": scope.value,
                    "project_id": project_id,
                    "source_ledger_generation": generation,
                },
            )
        finally:
            try:
                remove_owned_directory_at(parent_descriptor, staging_name, identity)
                if not os.listdir(parent_descriptor):
                    parent.rmdir()
            finally:
                os.close(parent_descriptor)

    def authorize_source_schema(
        self,
        *,
        source_account_id: str,
        source_system: SourceSystem,
        scope: Scope,
        project_id: str | None,
        provenance: SourceSchemaProvenance,
        authorized_by: str,
        expected_ledger_generation: str | None = None,
    ) -> dict[str, Any]:
        self._require_writable()
        normalized_source_account_id = _canonical_identity_value(
            source_account_id,
            "source account id",
        )
        normalized_authorized_by = _canonical_identity_value(
            authorized_by,
            "schema authorizer",
        )
        normalized_provenance = _normalized_source_schema_provenance(provenance)
        parser_versions_json = _source_schema_parser_versions_json(normalized_provenance)
        authorization_id = _source_schema_authorization_id(
            source_account_id=normalized_source_account_id,
            source_system=source_system,
            provenance=normalized_provenance,
        )
        if expected_ledger_generation is not None:
            _validate_sha256(expected_ledger_generation, "expected ledger generation")
        created_at = _now()
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            if (
                expected_ledger_generation is not None
                and _ledger_generation_digest(connection) != expected_ledger_generation
            ):
                raise RuntimeError(
                    "ledger generation does not match the schema-authorization manifest; "
                    "replan required"
                )
            installation_id = _ensure_installation(connection, created_at)
            device_id = _require_registered_source_account(
                connection,
                installation_id=installation_id,
                source_account_id=normalized_source_account_id,
                source_system=source_system,
                scope=scope,
                project_id=project_id,
            )
            existing = connection.execute(
                """
                SELECT status, authorized_by, created_at
                FROM source_schema_authorizations
                WHERE authorization_id = ?
                """,
                (authorization_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO source_schema_authorizations(
                      authorization_id, source_account_id, source_system,
                      schema_fingerprint, source_client, source_client_version,
                      capture_capability, adapter_name, adapter_version,
                      parser_versions_json, status, authorized_by, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                    """,
                    (
                        authorization_id,
                        normalized_source_account_id,
                        source_system.value,
                        normalized_provenance.schema_fingerprint,
                        normalized_provenance.source_client,
                        normalized_provenance.source_client_version,
                        normalized_provenance.capture_capability,
                        normalized_provenance.adapter_name,
                        normalized_provenance.adapter_version,
                        parser_versions_json,
                        normalized_authorized_by,
                        created_at,
                        created_at,
                    ),
                )
                effective_authorizer = normalized_authorized_by
                effective_created_at = created_at
            else:
                if cast(str, existing[0]) != "active":
                    raise PermissionError("source schema authorization is revoked")
                effective_authorizer = cast(str, existing[1])
                effective_created_at = cast(str, existing[2])
        return {
            "authorization_id": authorization_id,
            "source_account_id": normalized_source_account_id,
            "source_system": source_system.value,
            "source_device_id": device_id,
            "schema_fingerprint": normalized_provenance.schema_fingerprint,
            "source_client": normalized_provenance.source_client,
            "source_client_version": normalized_provenance.source_client_version,
            "capture_capability": normalized_provenance.capture_capability,
            "adapter_name": normalized_provenance.adapter_name,
            "adapter_version": normalized_provenance.adapter_version,
            "parser_versions": dict(normalized_provenance.parser_versions),
            "status": "active",
            "authorized_by": effective_authorizer,
            "created_at": effective_created_at,
        }

    def inspect_source_schema_authorization(
        self,
        *,
        source_account_id: str,
        authorization_id: str,
    ) -> dict[str, Any] | None:
        normalized_source_account_id = _canonical_identity_value(
            source_account_id,
            "source account id",
        )
        normalized_authorization_id = _canonical_identity_value(
            authorization_id,
            "source schema authorization id",
        )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                row = connection.execute(
                    """
                    SELECT authorization.source_account_id, authorization.source_system,
                           account.device_id, authorization.status, authorization.authorized_by,
                           authorization.created_at, authorization.updated_at
                    FROM source_schema_authorizations authorization
                    JOIN source_accounts account
                      ON account.source_account_id = authorization.source_account_id
                    WHERE authorization.authorization_id = ?
                    """,
                    (normalized_authorization_id,),
                ).fetchone()
                if row is None:
                    return None
                if cast(str, row[0]) != normalized_source_account_id:
                    raise PermissionError("source schema authorization not found for exact account")
                return {
                    "authorization_id": normalized_authorization_id,
                    "source_account_id": normalized_source_account_id,
                    "source_system": cast(str, row[1]),
                    "source_device_id": cast(str, row[2]),
                    "status": cast(str, row[3]),
                    "authorized_by": cast(str, row[4]),
                    "created_at": cast(str, row[5]),
                    "updated_at": cast(str, row[6]),
                }
            finally:
                connection.rollback()

    def revoke_source_schema_authorization(
        self,
        *,
        source_account_id: str,
        authorization_id: str,
        expected_ledger_generation: str,
    ) -> dict[str, Any]:
        self._require_writable()
        token = self._exclusive_writer_token
        if token is None or not token.active:
            raise RuntimeError("source schema revocation requires an active exclusive writer")
        normalized_source_account_id = _canonical_identity_value(
            source_account_id,
            "source account id",
        )
        normalized_authorization_id = _canonical_identity_value(
            authorization_id,
            "source schema authorization id",
        )
        _validate_sha256(expected_ledger_generation, "expected ledger generation")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT authorization.source_system, account.device_id, authorization.status
                FROM source_schema_authorizations authorization
                JOIN source_accounts account
                  ON account.source_account_id = authorization.source_account_id
                WHERE authorization.authorization_id = ?
                  AND authorization.source_account_id = ?
                """,
                (normalized_authorization_id, normalized_source_account_id),
            ).fetchone()
            if row is None:
                raise PermissionError("source schema authorization not found for exact account")
            previous_generation = _ledger_generation_digest(connection)
            replayed = cast(str, row[2]) == "revoked"
            if not replayed:
                if previous_generation != expected_ledger_generation:
                    raise RuntimeError(
                        "ledger generation does not match the schema-authorization revocation; "
                        "replan required"
                    )
                connection.execute(
                    """
                    UPDATE source_schema_authorizations
                    SET status = 'revoked', updated_at = ?
                    WHERE authorization_id = ? AND source_account_id = ? AND status = 'active'
                    """,
                    (_now(), normalized_authorization_id, normalized_source_account_id),
                )
            result_generation = (
                previous_generation if replayed else _ledger_generation_digest(connection)
            )
        return {
            "authorization_id": normalized_authorization_id,
            "source_account_id": normalized_source_account_id,
            "source_system": cast(str, row[0]),
            "source_device_id": cast(str, row[1]),
            "status": "revoked",
            "replayed": replayed,
            "previous_ledger_generation": previous_generation,
            "result_ledger_generation": result_generation,
        }

    def verify_source_schema_authorization(
        self,
        *,
        source_account_id: str,
        source_system: SourceSystem,
        scope: Scope,
        project_id: str | None,
        provenance: SourceSchemaProvenance,
    ) -> dict[str, Any]:
        normalized_source_account_id = _canonical_identity_value(
            source_account_id,
            "source account id",
        )
        normalized_provenance = _normalized_source_schema_provenance(provenance)
        with closing(self._connect()) as connection:
            installation = connection.execute(
                "SELECT installation_id FROM installations"
            ).fetchone()
            if installation is None:
                raise RuntimeError("installation identity is missing")
            device_id = _require_registered_source_account(
                connection,
                installation_id=cast(str, installation[0]),
                source_account_id=normalized_source_account_id,
                source_system=source_system,
                scope=scope,
                project_id=project_id,
            )
            authorization_id, authorized_by, created_at = (
                _require_active_source_schema_authorization(
                    connection,
                    source_account_id=normalized_source_account_id,
                    source_system=source_system,
                    provenance=normalized_provenance,
                )
            )
        return {
            "authorization_id": authorization_id,
            "source_account_id": normalized_source_account_id,
            "source_system": source_system.value,
            "source_device_id": device_id,
            "schema_fingerprint": normalized_provenance.schema_fingerprint,
            "status": "active",
            "authorized_by": authorized_by,
            "created_at": created_at,
        }

    def register_web_export_batch(
        self,
        *,
        source_account_id: str,
        source_system: SourceSystem,
        scope: Scope,
        project_id: str | None,
        source_provenance: SourceSchemaProvenance,
        batch_provenance: WebExportBatchProvenance,
        archive_path: Path,
        selected_member_path: Path,
        conversation_ids: Sequence[str],
        attachment_paths: Sequence[tuple[int, Path]] = (),
        defer_attachment_objects: bool = False,
        expected_ledger_generation: str | None = None,
    ) -> dict[str, Any]:
        self._require_writable()
        created_at = _now()
        created_object_paths: set[Path] = set()
        with self._object_write_transaction(created_object_paths) as connection:
            if source_system not in {
                SourceSystem.CHATGPT_WEB,
                SourceSystem.CLAUDE_WEB,
                SourceSystem.GROK_WEB,
            }:
                raise ValueError("web export batch requires a web source system")
            normalized_source_account_id = _canonical_identity_value(
                source_account_id,
                "source account id",
            )
            normalized_conversation_ids = tuple(
                _bounded_identity_value(item, "web export conversation id")
                for item in conversation_ids
            )
            if not normalized_conversation_ids:
                raise ValueError("web export batch requires at least one conversation id")
            if len(set(normalized_conversation_ids)) != len(normalized_conversation_ids):
                raise ValueError("web export conversation ids must be unique")
            normalized_source_provenance = _normalized_source_schema_provenance(source_provenance)
            normalized_batch = _normalized_web_export_batch_provenance(batch_provenance)
            attachment_path_by_index: dict[int, Path] = {}
            for archive_member_index, attachment_path in attachment_paths:
                if isinstance(archive_member_index, bool) or archive_member_index < 0:
                    raise ValueError("web export attachment path index must be non-negative")
                if archive_member_index in attachment_path_by_index:
                    raise ValueError("web export attachment path indexes must be unique")
                attachment_path_by_index[archive_member_index] = attachment_path
            if set(attachment_path_by_index) != set(normalized_batch.extracted_attachment_indices):
                raise ValueError("web export attachment paths do not match approved extraction set")
            if expected_ledger_generation is not None:
                _validate_sha256(expected_ledger_generation, "expected ledger generation")
            if not connection.in_transaction:
                connection.execute("BEGIN IMMEDIATE")
            if (
                expected_ledger_generation is not None
                and _ledger_generation_digest(connection) != expected_ledger_generation
            ):
                raise RuntimeError(
                    "ledger generation does not match the web-export batch; replan required"
                )
            installation_id = _ensure_installation(connection, created_at)
            for conversation_id in normalized_conversation_ids:
                _require_not_tombstoned(
                    connection,
                    source_system=source_system,
                    source_account=normalized_source_account_id,
                    conversation_id=conversation_id,
                )
            device_id = _require_registered_source_account(
                connection,
                installation_id=installation_id,
                source_account_id=normalized_source_account_id,
                source_system=source_system,
                scope=scope,
                project_id=project_id,
            )
            authorization_id, _, _ = _require_active_source_schema_authorization(
                connection,
                source_account_id=normalized_source_account_id,
                source_system=source_system,
                provenance=normalized_source_provenance,
            )
            batch_id = _web_export_batch_id(
                source_account_id=normalized_source_account_id,
                source_system=source_system,
                authorization_id=authorization_id,
                provenance=normalized_batch,
            )
            expected_batch = (
                normalized_source_account_id,
                source_system.value,
                authorization_id,
                normalized_batch.manifest_sha256,
                normalized_batch.code_revision,
                normalized_batch.prepared_at,
                normalized_batch.archive_sha256,
                normalized_batch.archive_byte_length,
                normalized_batch.selected_member_name_sha256,
                normalized_batch.selected_member_sha256,
                normalized_batch.selected_member_byte_length,
            )
            existing = connection.execute(
                """
                SELECT source_account_id, source_system, authorization_id,
                       prepared_at, archive_sha256,
                       archive_byte_length, selected_member_name_sha256,
                       selected_member_sha256, selected_member_byte_length
                FROM web_export_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
            inserted = existing is None
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO web_export_batches(
                      batch_id, source_account_id, source_system, authorization_id,
                      manifest_sha256, code_revision, prepared_at, archive_sha256,
                      archive_byte_length, selected_member_name_sha256,
                      selected_member_sha256, selected_member_byte_length, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (batch_id, *expected_batch, created_at),
                )
                batch_prepared_at = normalized_batch.prepared_at
            else:
                # Replanning against a new ledger generation changes plan metadata,
                # not source bytes.
                existing_values = tuple(existing)
                stable_existing = existing_values[:3] + existing_values[4:]
                stable_expected = expected_batch[:3] + expected_batch[6:]
                if stable_existing != stable_expected:
                    raise RuntimeError("web export batch conflicts with an existing receipt")
                batch_prepared_at = cast(str, existing_values[3])

            expected_members: list[tuple[object, ...]] = []
            for member in normalized_batch.archive_members:
                archive_member_id = _stable_id(
                    "web_export_archive_member",
                    batch_id,
                    str(member.archive_member_index),
                    member.name_sha256,
                    member.content_sha256,
                )
                member_values = (
                    archive_member_id,
                    batch_id,
                    member.archive_member_index,
                    member.locator,
                    member.name_sha256,
                    member.content_sha256,
                    member.compressed_bytes,
                    member.byte_length,
                    member.compression_method,
                    member.media_type_hint,
                )
                expected_members.append(member_values)
                if inserted:
                    connection.execute(
                        """
                        INSERT INTO web_export_archive_members(
                          archive_member_id, batch_id, archive_member_index, locator,
                          name_sha256, content_sha256, compressed_bytes, byte_length,
                          compression_method, media_type_hint, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (*member_values, created_at),
                    )
            stored_members = [
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT archive_member_id, batch_id, archive_member_index, locator,
                           name_sha256, content_sha256, compressed_bytes, byte_length,
                           compression_method, media_type_hint
                    FROM web_export_archive_members
                    WHERE batch_id = ?
                    ORDER BY archive_member_index
                    """,
                    (batch_id,),
                )
            ]
            if stored_members != expected_members:
                raise RuntimeError("web export archive-member manifest conflicts with the ledger")
            member_id_by_index = {
                cast(int, values[2]): cast(str, values[0]) for values in expected_members
            }
            member_by_index = {
                member.archive_member_index: member for member in normalized_batch.archive_members
            }
            expected_links: list[tuple[object, ...]] = []
            for reference in normalized_batch.attachment_references:
                archive_member_id = member_id_by_index[reference.archive_member_index]
                attachment_link_id = _stable_id(
                    "web_export_attachment_link",
                    archive_member_id,
                    str(reference.conversation_index),
                    str(reference.source_record_ordinal),
                    str(reference.reference_ordinal),
                    reference.reference_sha256,
                )
                values = (
                    attachment_link_id,
                    archive_member_id,
                    batch_id,
                    reference.conversation_index,
                    reference.source_record_ordinal,
                    reference.reference_ordinal,
                    reference.reference_sha256,
                )
                expected_links.append(values)
                connection.execute(
                    """
                    INSERT OR IGNORE INTO web_export_attachment_links(
                      attachment_link_id, archive_member_id, batch_id,
                      conversation_index, source_record_ordinal, reference_ordinal,
                      reference_sha256,
                      created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*values, created_at),
                )
            stored_links = [
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT attachment_link_id, archive_member_id, batch_id,
                           conversation_index, source_record_ordinal, reference_ordinal,
                           reference_sha256
                    FROM web_export_attachment_links
                    WHERE batch_id = ?
                    ORDER BY archive_member_id, conversation_index,
                             source_record_ordinal, reference_ordinal, reference_sha256
                    """,
                    (batch_id,),
                )
            ]
            expected_links.sort(key=lambda item: item[1:])
            if stored_links != expected_links:
                raise RuntimeError("web export attachment links conflict with the ledger")

            expected_attachment_objects: list[tuple[object, ...]] = []
            has_record_erasures = (
                connection.execute(
                    "SELECT 1 FROM record_deletion_tombstones WHERE source_system = ? "
                    "AND source_account_digest = ? LIMIT 1",
                    (source_system.value, _sha256_text(normalized_source_account_id)),
                ).fetchone()
                is not None
            )
            for archive_member_index in (
                () if defer_attachment_objects else normalized_batch.extracted_attachment_indices
            ):
                member = member_by_index[archive_member_index]
                archive_member_id = member_id_by_index[archive_member_index]
                if (
                    has_record_erasures
                    and connection.execute(
                        """
                    SELECT 1 FROM web_export_attachment_links link
                    JOIN web_export_conversation_observations obs
                      ON obs.batch_id = link.batch_id
                     AND obs.conversation_index = link.conversation_index
                    JOIN source_records r ON r.source_file_id = obs.source_file_id
                     AND r.record_ordinal = link.source_record_ordinal
                    JOIN web_export_event_observations observation
                      ON observation.source_record_id = r.source_record_id
                    JOIN events_current e ON e.event_id = observation.event_id
                    WHERE link.archive_member_id = ? AND e.privacy != 'no_memory'
                    LIMIT 1
                    """,
                        (archive_member_id,),
                    ).fetchone()
                    is None
                ):
                    continue
                _require_object_not_pending_deletion(connection, f"sha256:{member.content_sha256}")
                object_id, object_path = self._store_file_object(
                    attachment_path_by_index[archive_member_index],
                    connection=connection,
                    source_system=source_system,
                    media_type=member.media_type_hint,
                    expected_sha256=member.content_sha256,
                    expected_byte_length=member.byte_length,
                    created_object_paths=created_object_paths,
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO objects(
                      object_id, plaintext_digest, byte_length, media_type,
                      object_path, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        object_id,
                        member.content_sha256,
                        member.byte_length,
                        member.media_type_hint,
                        object_path,
                        created_at,
                    ),
                )
                self._queue_evidence_publication(
                    connection,
                    object_id,
                    newly_created=self.settings.data_root / object_path in created_object_paths,
                )
                attachment_source_object_id = _stable_id(
                    "web_export_attachment_object",
                    batch_id,
                    archive_member_id,
                    object_id,
                )
                values = (
                    attachment_source_object_id,
                    archive_member_id,
                    batch_id,
                    object_id,
                    member.content_sha256,
                    member.byte_length,
                    member.media_type_hint,
                )
                expected_attachment_objects.append(values)
                connection.execute(
                    """
                    INSERT OR IGNORE INTO web_export_attachment_objects(
                      attachment_source_object_id, archive_member_id, batch_id,
                      object_id, plaintext_sha256, byte_length, media_type, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*values, created_at),
                )
            stored_attachment_objects = [
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT attachment_source_object_id, archive_member_id, batch_id,
                           object_id, plaintext_sha256, byte_length, media_type
                    FROM web_export_attachment_objects
                    WHERE batch_id = ?
                    ORDER BY archive_member_id
                    """,
                    (batch_id,),
                )
            ]
            if not defer_attachment_objects and not inserted:
                # A stricter extraction policy does not authorize deleting existing opaque holds.
                # Validate their original identities without admitting or publishing them again.
                expected_member_ids = {values[1] for values in expected_attachment_objects}
                members_by_id = {
                    member_id_by_index[index]: member for index, member in member_by_index.items()
                }
                for stored in stored_attachment_objects:
                    archive_member_id = cast(str, stored[1])
                    if archive_member_id in expected_member_ids:
                        continue
                    retained = members_by_id.get(archive_member_id)
                    if retained is None or retained.media_type_hint in TEXT_ATTACHMENT_MEDIA_TYPES:
                        raise RuntimeError("web export attachment objects conflict with the ledger")
                    object_id = f"sha256:{retained.content_sha256}"
                    expected = (
                        _stable_id(
                            "web_export_attachment_object", batch_id, archive_member_id, object_id
                        ),
                        archive_member_id,
                        batch_id,
                        object_id,
                        retained.content_sha256,
                        retained.byte_length,
                        retained.media_type_hint,
                    )
                    if stored != expected:
                        raise RuntimeError(
                            "retained attachment identity conflicts with the archive"
                        )
                    target = _publication_object_target(connection, object_id)
                    if (
                        target[1] != retained.byte_length
                        or target[4] != retained.media_type_hint
                        or connection.execute(
                            "SELECT 1 FROM objects WHERE object_id = ? AND plaintext_digest = ?",
                            (object_id, retained.content_sha256),
                        ).fetchone()
                        is None
                    ):
                        raise RuntimeError("retained attachment object metadata changed")
                    location = read_location(connection, object_id)
                    require_mapping_state(cast(str, target[2]), location)
                    if location is not None:
                        reader = self._encrypted_evidence_reader
                        if reader is None:
                            raise RuntimeError("encrypted evidence reader is not configured")
                        reader.validate_location(
                            location[1],
                            object_id=object_id,
                            expected_size=retained.byte_length,
                            backend_identity_sha256=location[0],
                            allowed_states=(ObjectState.PENDING, ObjectState.VERIFIED),
                        )
                    if target[2] != "encrypted":
                        details = secure_path_stat(
                            self.settings.data_root / cast(str, target[3]), "retained attachment"
                        )
                        if (
                            details.st_uid != os.geteuid()
                            or details.st_nlink != 1
                            or stat.S_IMODE(details.st_mode) not in {0o400, 0o600}
                        ):
                            raise RuntimeError(
                                "retained attachment ownership or permissions changed"
                            )
                        self._verify_deletion_object_file(
                            cast(str, target[3]), object_id, retained.byte_length
                        )
                    expected_attachment_objects.append(expected)
            expected_attachment_objects.sort(key=lambda item: cast(str, item[1]))
            if (
                not defer_attachment_objects
                and stored_attachment_objects != expected_attachment_objects
            ):
                raise RuntimeError("web export attachment objects conflict with the ledger")
            archive_source_object_id = self._register_web_export_source_object(
                connection,
                batch_id=batch_id,
                object_kind="official_export_archive",
                conversation_index=None,
                source_path=archive_path,
                expected_sha256=normalized_batch.archive_sha256,
                expected_byte_length=normalized_batch.archive_byte_length,
                media_type="application/zip",
                conversation_id=None,
                branch_id=None,
                captured_at=batch_prepared_at,
                parser_name="web-export-archive",
                parser_version=normalized_source_provenance.adapter_version,
                schema_fingerprint=normalized_source_provenance.schema_fingerprint,
                created_at=created_at,
            )
            member_source_object_id = self._register_web_export_source_object(
                connection,
                batch_id=batch_id,
                object_kind="selected_export_member",
                conversation_index=None,
                source_path=selected_member_path,
                expected_sha256=normalized_batch.selected_member_sha256,
                expected_byte_length=normalized_batch.selected_member_byte_length,
                media_type="application/json",
                conversation_id=None,
                branch_id=None,
                captured_at=batch_prepared_at,
                parser_name="web-export-container",
                parser_version=normalized_source_provenance.adapter_version,
                schema_fingerprint=normalized_source_provenance.schema_fingerprint,
                created_at=created_at,
            )
        return {
            "batch_id": batch_id,
            "inserted": inserted,
            "source_account_id": normalized_source_account_id,
            "source_system": source_system.value,
            "source_device_id": device_id,
            "authorization_id": authorization_id,
            "archive_sha256": normalized_batch.archive_sha256,
            "archive_source_object_id": archive_source_object_id,
            "selected_member_source_object_id": member_source_object_id,
            "supplemental_member_count": len(normalized_batch.archive_members),
            "attachment_link_count": len(normalized_batch.attachment_references),
            "attachment_object_count": len(normalized_batch.extracted_attachment_indices),
        }

    def ingest_upload_batch(
        self,
        parsed: ParseResult,
        *,
        batch_id: str,
        request_digest: str,
        source_account_id: str,
        client_id: str,
        device_id: str,
        source_path_hash: str,
        provenance: CollectorProvenance,
        exclusion_receipts: Sequence[ExclusionReceipt],
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
        max_publication_objects: int | None = None,
    ) -> dict[str, Any]:
        if max_publication_objects is not None and (
            type(max_publication_objects) is not int or max_publication_objects < 1
        ):
            raise ValueError("upload publication limit must be a positive integer")
        scope = self._native_upload_write_scope(
            parsed,
            identity=(batch_id, request_digest, source_account_id, client_id, device_id),
            source_path_hash=source_path_hash,
            provenance=provenance,
            max_record_bytes=max_record_bytes,
        )
        with self._publication_writer(force_exclusive=True, object_write_scope=scope) as ledger:
            admitted_result: dict[str, Any] | None = None

            def admit() -> dict[str, Any]:
                nonlocal admitted_result
                with ledger._upload_transaction():
                    result = ledger._ingest_upload_batch(
                        parsed,
                        batch_id=batch_id,
                        request_digest=request_digest,
                        source_account_id=source_account_id,
                        client_id=client_id,
                        device_id=device_id,
                        source_path_hash=source_path_hash,
                        provenance=provenance,
                        exclusion_receipts=exclusion_receipts,
                        max_record_bytes=max_record_bytes,
                    )
                ledger._finish_native_upload_write_attempt(batch_id)
                admitted_result = result
                return result

            try:
                return ledger._admit_and_publish(
                    admit, max_publication_objects=max_publication_objects
                )
            except EvidencePublicationYielded:
                # Only a committed, fully published batch may finish ahead of unrelated work.
                if admitted_result is None or not ledger._source_publication_complete(
                    cast(str, admitted_result["source_file_id"])
                ):
                    raise
                return admitted_result

    def _native_upload_write_scope(
        self,
        parsed: ParseResult,
        *,
        identity: tuple[str, str, str, str, str],
        source_path_hash: str,
        provenance: CollectorProvenance,
        max_record_bytes: int,
    ) -> ObjectWriteScope:
        return self._native_object_write_scope(
            parsed,
            operation=(
                "native-upload-v1",
                identity,
                source_path_hash,
                parsed.parser_name,
                parsed.parser_version,
                asdict(provenance),
            ),
            max_record_bytes=max_record_bytes,
        )

    def _native_object_write_scope(
        self,
        parsed: ParseResult,
        *,
        operation: tuple[Any, ...],
        max_record_bytes: int,
    ) -> ObjectWriteScope:
        reader = self._encrypted_evidence_reader
        policy = self._evidence_publication_policy
        binding = {
            "reader": None
            if reader is None
            else {
                "backend_identity_sha256": reader.backend.identity_sha256,
                "root_key_sha256": publication_key_sha256(reader),
            },
            "publication": None if policy is None else asdict(policy),
            "max_record_bytes": max_record_bytes,
        }
        objects = max(1, len(parsed.records))
        byte_count = max(1, sum(len(record.raw_record) for record in parsed.records))
        return ObjectWriteScope(
            operation_sha256=_sha256_text(json.dumps(operation, sort_keys=True)),
            binding_sha256=_sha256_text(json.dumps(binding, sort_keys=True)),
            max_objects=min(objects, policy.max_pending_objects) if policy else objects,
            max_bytes=min(byte_count, policy.max_pending_bytes) if policy else byte_count,
        )

    def _finish_native_upload_write_attempt(self, batch_id: str) -> None:
        scope = self._object_write_scope
        if scope is None:
            raise RuntimeError("native upload completion requires its exact write scope")
        with closing(self._connect()) as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM upload_batches JOIN source_capture_metadata USING(batch_id) "
                    "WHERE batch_id = ?",
                    (batch_id,),
                ).fetchone()
                is None
            ):
                raise RuntimeError("object writes have no committed upload receipt and provenance")
            with closing(ObjectWriteJournal(self.settings.data_root, scope)) as journal:
                journal.finish(self._registered_object_check(connection))

    def _ingest_upload_batch(
        self,
        parsed: ParseResult,
        *,
        batch_id: str,
        request_digest: str,
        source_account_id: str,
        client_id: str,
        device_id: str,
        source_path_hash: str,
        provenance: CollectorProvenance,
        exclusion_receipts: Sequence[ExclusionReceipt],
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
    ) -> dict[str, Any]:
        self._require_writable()
        if UPLOAD_BATCH_ID.fullmatch(batch_id) is None:
            raise ValueError("upload batch id is invalid")
        _validate_sha256(request_digest, "upload request digest")
        _validate_sha256(source_path_hash, "source path hash")
        normalized_source_account_id = _bounded_identity_value(
            source_account_id, "source account id"
        )
        normalized_client_id = _bounded_identity_value(client_id, "client id")
        normalized_device_id = _bounded_identity_value(device_id, "device id")
        _validate_sha256(provenance.schema_fingerprint, "collector schema fingerprint")
        provenance_values = (
            _bounded_identity_value(provenance.source_client, "source client"),
            _bounded_identity_value(provenance.source_client_version, "source client version"),
            _bounded_identity_value(provenance.capture_capability, "capture capability"),
            _bounded_identity_value(provenance.adapter_name, "adapter name"),
            _bounded_identity_value(provenance.adapter_version, "adapter version"),
            provenance.schema_fingerprint,
        )

        with self._object_write_transaction(set()) as connection:
            policy = connection.execute(
                """
                SELECT account.installation_id, account.source_system,
                       policy.scope, policy.project_id
                FROM source_accounts account
                JOIN source_account_policies policy
                  ON policy.source_account_id = account.source_account_id
                WHERE account.source_account_id = ?
                  AND account.status = 'active'
                """,
                (normalized_source_account_id,),
            ).fetchone()
            if policy is None:
                raise PermissionError("registered source account not found")
            source_system = SourceSystem(cast(str, policy[1]))
            scope = Scope(cast(str, policy[2]))
            project_id = cast(str | None, policy[3])
            _require_registered_upload_identity(
                connection,
                installation_id=cast(str, policy[0]),
                client_id=normalized_client_id,
                device_id=normalized_device_id,
                source_account_id=normalized_source_account_id,
                source_system=source_system,
                scope=scope,
                project_id=project_id,
            )
            existing = connection.execute(
                """
                SELECT request_digest, client_id, device_id, source_account_id,
                       source_file_id, conversation_id, event_count,
                       quarantined_records, quarantine_reasons_json, created_at
                FROM upload_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
        if parsed.source_system is not source_system:
            raise PermissionError("source account does not allow this source system")
        expected_identity = (
            request_digest,
            normalized_client_id,
            normalized_device_id,
            normalized_source_account_id,
        )
        if existing is not None:
            if tuple(existing[:4]) != expected_identity:
                raise RuntimeError("upload batch identity conflicts with an existing receipt")
            with self._object_write_transaction(set()) as connection:
                _require_capture_metadata(
                    connection=connection,
                    batch_id=batch_id,
                    parser_name=parsed.parser_name,
                    parser_version=parsed.parser_version,
                    provenance_values=provenance_values,
                )
                self._start_object_write_attempt(connection)
                self._queue_source_evidence_publication(connection, cast(str, existing[4]))
            return _upload_receipt(batch_id, existing, replayed=True)

        synthetic_source_path = (
            f"/collector/{_sha256_text(normalized_source_account_id)}/{source_path_hash}.jsonl"
        )
        with self._object_write_transaction(set()) as connection:
            self._start_object_write_attempt(connection)
        report = self._ingest(
            parsed,
            source_account=normalized_source_account_id,
            scope=scope,
            project_id=project_id,
            source_path=synthetic_source_path,
            max_record_bytes=max_record_bytes,
            exclusion_receipts=exclusion_receipts,
            registered_client_id=normalized_client_id,
            registered_device_id=normalized_device_id,
        )
        event_count = report.inserted_events + report.existing_events
        quarantine_reasons_json = json.dumps(
            report.quarantine_reasons,
            sort_keys=True,
            separators=(",", ":"),
        )
        created_at = _now()
        inserted = (
            request_digest,
            normalized_client_id,
            normalized_device_id,
            normalized_source_account_id,
            report.source_file_id,
            report.conversation_id,
            event_count,
            report.quarantined_records,
            quarantine_reasons_json,
            created_at,
        )
        with self._object_write_transaction(set()) as connection:
            existing = connection.execute(
                """
                SELECT request_digest, client_id, device_id, source_account_id,
                       source_file_id, conversation_id, event_count,
                       quarantined_records, quarantine_reasons_json, created_at
                FROM upload_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO upload_batches(
                      batch_id, request_digest, client_id, device_id,
                      source_account_id, source_file_id, conversation_id,
                      event_count, quarantined_records, quarantine_reasons_json,
                      created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (batch_id, *inserted),
                )
                connection.execute(
                    """
                    INSERT INTO source_capture_metadata(
                      batch_id, source_file_id, source_client, source_client_version,
                      capture_capability, adapter_name, adapter_version, parser_name,
                      parser_version, schema_fingerprint, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        batch_id,
                        report.source_file_id,
                        *provenance_values[:5],
                        parsed.parser_name,
                        parsed.parser_version,
                        provenance_values[5],
                        created_at,
                    ),
                )
                stored = inserted
                replayed = False
            else:
                if tuple(existing) != inserted:
                    if tuple(existing[:4]) != expected_identity:
                        raise RuntimeError(
                            "upload batch identity conflicts with an existing receipt"
                        )
                    if tuple(existing[4:9]) != inserted[4:9]:
                        raise RuntimeError("upload batch result conflicts with an existing receipt")
                capture = connection.execute(
                    """
                    SELECT source_client, source_client_version, capture_capability,
                           adapter_name, adapter_version, parser_name, parser_version,
                           schema_fingerprint
                    FROM source_capture_metadata
                    WHERE batch_id = ?
                    """,
                    (batch_id,),
                ).fetchone()
                expected_capture = (
                    *provenance_values[:5],
                    parsed.parser_name,
                    parsed.parser_version,
                    provenance_values[5],
                )
                if capture is None or tuple(capture) != expected_capture:
                    raise RuntimeError("upload batch provenance conflicts with an existing receipt")
                stored = tuple(existing)
                replayed = True
        return _upload_receipt(batch_id, stored, replayed=replayed)

    def register_client(
        self,
        *,
        label: str,
        kind: ClientKind,
        capabilities: Sequence[Capability],
        intent_key: str | None = None,
        expected_identity_state_sha256: str | None = None,
        expected_installation_id: str | None = None,
        authorized_by: str = "local:ledger",
    ) -> dict[str, Any]:
        self._require_writable()
        created_at = _now()
        normalized_authorizer = _bounded_identity_value(authorized_by, "client authorizer")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_identity_digest = _identity_state_digest(connection)
            allow_create = _identity_precondition_matches(
                connection,
                expected_identity_state_sha256=expected_identity_state_sha256,
                expected_installation_id=expected_installation_id,
            )
            installation_id = _ensure_installation(connection, created_at)
            result = _insert_client(
                connection,
                installation_id=installation_id,
                label=label,
                kind=kind,
                capabilities=capabilities,
                created_at=created_at,
                intent_key=intent_key,
                allow_create=allow_create,
            )
            _record_identity_mutation(
                connection,
                target_id=cast(str, result["client_id"]),
                operation="register_client",
                previous_identity_digest=previous_identity_digest,
                authorized_by=normalized_authorizer,
                authorization_scope=Capability.CLIENT_ADMIN.value,
                reason="client_registered",
                created_at=created_at,
            )
            return result

    def issue_client_credential(
        self,
        client_id: str,
        *,
        expires_at: datetime,
        token: str | None = None,
        expected_identity_state_sha256: str | None = None,
        expected_installation_id: str | None = None,
        require_existing: bool = False,
        authorized_by: str = "local:ledger",
    ) -> dict[str, Any]:
        self._require_writable()
        now = datetime.now(UTC)
        normalized_authorizer = _bounded_identity_value(authorized_by, "credential authorizer")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_identity_digest = _identity_state_digest(connection)
            allow_create = (
                _identity_precondition_matches(
                    connection,
                    expected_identity_state_sha256=expected_identity_state_sha256,
                    expected_installation_id=expected_installation_id,
                )
                and not require_existing
            )
            result = _insert_client_credential(
                connection,
                client_id,
                expires_at=expires_at,
                now=now,
                token=token,
                allow_create=allow_create,
                require_existing=require_existing,
            )
            _record_identity_mutation(
                connection,
                target_id=cast(str, result["credential_id"]),
                operation="issue_client_credential",
                previous_identity_digest=previous_identity_digest,
                authorized_by=normalized_authorizer,
                authorization_scope=Capability.CLIENT_ADMIN.value,
                reason="client_credential_issued",
                created_at=now.isoformat(),
            )
            return result

    def create_device_enrollment(
        self,
        *,
        label: str,
        platform: str,
        expires_at: datetime,
        credential_expires_at: datetime,
        created_by: str,
        code: str | None = None,
        expected_identity_state_sha256: str | None = None,
        expected_installation_id: str | None = None,
        require_existing: bool = False,
    ) -> dict[str, Any]:
        self._require_writable()
        normalized_label = _bounded_identity_value(label, "device label")
        normalized_platform = _bounded_identity_value(platform, "device platform")
        normalized_creator = _bounded_identity_value(created_by, "enrollment creator")
        now = datetime.now(UTC)
        expiry = _normalized_timestamp(expires_at)
        credential_expiry = _normalized_timestamp(credential_expires_at)
        enrollment_lifetime = (expiry - now).total_seconds()
        credential_lifetime = (credential_expiry - now).total_seconds()
        if credential_expiry <= expiry:
            raise ValueError("device credential must outlive the enrollment code")

        enrollment_code = code or generate_device_enrollment_code()
        enrollment_id, code_digest = _parse_enrollment_code(enrollment_code)
        created_at = now.isoformat()
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_identity_digest = _identity_state_digest(connection)
            allow_create = (
                _identity_precondition_matches(
                    connection,
                    expected_identity_state_sha256=expected_identity_state_sha256,
                    expected_installation_id=expected_installation_id,
                )
                and not require_existing
            )
            installation_id = _ensure_installation(connection, created_at)
            existing = connection.execute(
                """
                SELECT installation_id, code_digest, device_label, device_platform,
                       created_by, created_at, expires_at, credential_expires_at,
                       redeemed_at
                FROM device_enrollments
                WHERE enrollment_id = ?
                """,
                (enrollment_id,),
            ).fetchone()
            if existing is not None:
                if (
                    code is None
                    or cast(str, existing[0]) != installation_id
                    or not hmac.compare_digest(cast(str, existing[1]), code_digest)
                    or cast(str, existing[2]) != normalized_label
                    or cast(str, existing[3]) != normalized_platform
                    or cast(str, existing[4]) != normalized_creator
                    or _parse_timestamp(cast(str, existing[6])) != expiry
                    or _parse_timestamp(cast(str, existing[7])) != credential_expiry
                ):
                    raise RuntimeError(
                        "device enrollment intent conflicts with an existing enrollment"
                    )
                if existing[8] is None and (
                    enrollment_lifetime <= 0 or enrollment_lifetime > MAX_ENROLLMENT_LIFETIME
                ):
                    raise ValueError("unredeemed device enrollment is no longer usable")
                if credential_lifetime <= 0:
                    raise ValueError("device enrollment credential lifetime has ended")
                return {
                    "enrollment_id": enrollment_id,
                    "code": enrollment_code,
                    "device_label": normalized_label,
                    "device_platform": normalized_platform,
                    "expires_at": cast(str, existing[6]),
                    "credential_expires_at": cast(str, existing[7]),
                    "created_at": cast(str, existing[5]),
                    "replayed": True,
                }
            if enrollment_lifetime <= 0 or enrollment_lifetime > MAX_ENROLLMENT_LIFETIME:
                raise ValueError("device enrollment must expire within 60 minutes")
            if credential_lifetime <= 0 or credential_lifetime > MAX_DEVICE_CREDENTIAL_LIFETIME:
                raise ValueError("device credential must expire within 365 days")
            if require_existing:
                raise RuntimeError("published device enrollment code has no matching ledger row")
            if not allow_create:
                raise RuntimeError("ledger generation changed before device enrollment creation")
            connection.execute(
                """
                INSERT INTO device_enrollments(
                  enrollment_id, installation_id, code_digest,
                  device_label, device_platform, created_by, created_at,
                  expires_at, credential_expires_at,
                  redeemed_at, redeemed_device_id, redeemed_client_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (
                    enrollment_id,
                    installation_id,
                    code_digest,
                    normalized_label,
                    normalized_platform,
                    normalized_creator,
                    created_at,
                    expiry.isoformat(),
                    credential_expiry.isoformat(),
                ),
            )
            _record_identity_mutation(
                connection,
                target_id=enrollment_id,
                operation="create_device_enrollment",
                previous_identity_digest=previous_identity_digest,
                authorized_by=normalized_creator,
                authorization_scope=Capability.CLIENT_ADMIN.value,
                reason="device_enrollment_created",
                created_at=created_at,
            )
        result: dict[str, Any] = {
            "enrollment_id": enrollment_id,
            "code": enrollment_code,
            "device_label": normalized_label,
            "device_platform": normalized_platform,
            "expires_at": expiry.isoformat(),
            "credential_expires_at": credential_expiry.isoformat(),
        }
        if code is not None:
            result["created_at"] = created_at
            result["replayed"] = False
        return result

    def redeem_device_enrollment(
        self,
        code: str,
        credential_token: str | None = None,
    ) -> dict[str, Any]:
        self._require_writable()
        enrollment_id, candidate_digest = _parse_enrollment_code(code)
        return_token = credential_token is None
        if credential_token is None:
            credential_token = generate_client_credential_token()
        credential_id, normalized_token = parse_client_credential_token(credential_token)
        credential_digest = hashlib.sha256(normalized_token.encode()).hexdigest()
        now = datetime.now(UTC)
        redeemed_at = now.isoformat()
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_identity_digest = _identity_state_digest(connection)
            row = connection.execute(
                """
                SELECT installation_id, code_digest, device_label, device_platform,
                       expires_at, credential_expires_at, redeemed_at,
                       redeemed_device_id, redeemed_client_id
                FROM device_enrollments
                WHERE enrollment_id = ?
                """,
                (enrollment_id,),
            ).fetchone()
            if row is None or not hmac.compare_digest(cast(str, row[1]), candidate_digest):
                raise ValueError("valid device enrollment not found")
            expiry = _parse_timestamp(cast(str, row[4]))
            credential_expiry = _parse_timestamp(cast(str, row[5]))
            if credential_expiry <= now:
                raise ValueError("device enrollment expired")

            if row[6] is not None:
                replay = connection.execute(
                    """
                    SELECT device.device_id, device.label, device.platform, device.status,
                           client.client_id, client.label, client.kind, client.status,
                           client.created_at, credential.token_digest,
                           credential.expires_at, credential.revoked_at
                    FROM devices device
                    JOIN clients client ON client.client_id = ?
                    JOIN client_devices binding
                      ON binding.client_id = client.client_id
                     AND binding.device_id = device.device_id
                    JOIN client_credentials credential
                      ON credential.client_id = client.client_id
                     AND credential.credential_id = ?
                    WHERE device.device_id = ?
                    """,
                    (cast(str, row[8]), credential_id, cast(str, row[7])),
                ).fetchone()
                if (
                    replay is None
                    or replay[3] != "active"
                    or replay[6] != ClientKind.COLLECTOR.value
                    or replay[7] != "active"
                    or replay[11] is not None
                    or _parse_timestamp(cast(str, replay[10])) != credential_expiry
                    or not hmac.compare_digest(cast(str, replay[9]), credential_digest)
                ):
                    raise ValueError("device enrollment already redeemed")
                return _device_enrollment_result(
                    enrollment_id=enrollment_id,
                    device_id=cast(str, replay[0]),
                    device_label=cast(str, replay[1]),
                    device_platform=cast(str, replay[2]),
                    device_status=cast(str, replay[3]),
                    client_id=cast(str, replay[4]),
                    client_label=cast(str, replay[5]),
                    client_kind=cast(str, replay[6]),
                    client_status=cast(str, replay[7]),
                    client_created_at=cast(str, replay[8]),
                    credential_id=credential_id,
                    credential_expires_at=cast(str, replay[10]),
                    replayed=True,
                )
            if expiry <= now:
                raise ValueError("device enrollment expired")

            installation_id = cast(str, row[0])
            device_label = cast(str, row[2])
            device_platform = cast(str, row[3])
            device_id = f"device_{uuid.uuid4()}"
            connection.execute(
                """
                INSERT INTO devices(
                  device_id, installation_id, label, platform, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    device_id,
                    installation_id,
                    device_label,
                    device_platform,
                    redeemed_at,
                    redeemed_at,
                ),
            )
            client = _insert_client(
                connection,
                installation_id=installation_id,
                label=f"{device_label} collector",
                kind=ClientKind.COLLECTOR,
                capabilities=(Capability.SOURCE_UPLOAD, Capability.MEMORY_STATUS),
                created_at=redeemed_at,
            )
            client_id = cast(str, client["client_id"])
            connection.execute(
                """
                INSERT INTO client_devices(client_id, device_id, created_at)
                VALUES (?, ?, ?)
                """,
                (client_id, device_id, redeemed_at),
            )
            credential = _insert_client_credential(
                connection,
                client_id,
                expires_at=credential_expiry,
                now=now,
                token=normalized_token,
            )
            cursor = connection.execute(
                """
                UPDATE device_enrollments
                SET redeemed_at = ?, redeemed_device_id = ?, redeemed_client_id = ?
                WHERE enrollment_id = ? AND redeemed_at IS NULL
                """,
                (redeemed_at, device_id, client_id, enrollment_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("device enrollment redemption lost its single-use claim")
            _record_identity_mutation(
                connection,
                target_id=enrollment_id,
                operation="redeem_device_enrollment",
                previous_identity_digest=previous_identity_digest,
                authorized_by=f"enrollment:{enrollment_id}",
                authorization_scope="device:enroll",
                reason="device_enrollment_redeemed",
                created_at=redeemed_at,
            )
        return _device_enrollment_result(
            enrollment_id=enrollment_id,
            device_id=device_id,
            device_label=device_label,
            device_platform=device_platform,
            device_status="active",
            client_id=client_id,
            client_label=cast(str, client["label"]),
            client_kind=cast(str, client["kind"]),
            client_status=cast(str, client["status"]),
            client_created_at=cast(str, client["created_at"]),
            credential_id=cast(str, credential["credential_id"]),
            credential_expires_at=cast(str, credential["expires_at"]),
            replayed=False,
            credential_token=normalized_token if return_token else None,
        )

    def revoke_client_credential(
        self,
        credential_id: str,
        *,
        authorized_by: str = "local:ledger",
    ) -> dict[str, Any]:
        self._require_writable()
        revoked_at = _now()
        normalized_authorizer = _bounded_identity_value(authorized_by, "credential authorizer")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_identity_digest = _identity_state_digest(connection)
            cursor = connection.execute(
                """
                UPDATE client_credentials
                SET revoked_at = ?
                WHERE credential_id = ? AND revoked_at IS NULL
                """,
                (revoked_at, credential_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("active client credential not found")
            _record_identity_mutation(
                connection,
                target_id=credential_id,
                operation="revoke_client_credential",
                previous_identity_digest=previous_identity_digest,
                authorized_by=normalized_authorizer,
                authorization_scope=Capability.CLIENT_ADMIN.value,
                reason="client_credential_revoked",
                created_at=revoked_at,
            )
        return {
            "credential_id": credential_id,
            "status": "revoked",
            "revoked_at": revoked_at,
        }

    def verify_client_token(self, token: str) -> VerifiedClient | None:
        try:
            credential_id, normalized_token = parse_client_credential_token(token)
        except ValueError:
            return None
        candidate_digest = hashlib.sha256(normalized_token.encode()).hexdigest()
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT credential.token_digest, credential.expires_at,
                       client.client_id, client.kind, binding.device_id
                FROM client_credentials credential
                JOIN clients client ON client.client_id = credential.client_id
                LEFT JOIN client_devices binding ON binding.client_id = client.client_id
                WHERE credential.credential_id = ?
                  AND credential.revoked_at IS NULL
                  AND client.status = 'active'
                  AND client.revoked_at IS NULL
                """,
                (credential_id,),
            ).fetchone()
            if row is None or not hmac.compare_digest(cast(str, row[0]), candidate_digest):
                return None
            expires_at = _parse_timestamp(cast(str, row[1]))
            if expires_at <= datetime.now(UTC):
                return None
            capability_rows = connection.execute(
                """
                SELECT capability
                FROM client_capabilities
                WHERE client_id = ?
                ORDER BY capability
                """,
                (cast(str, row[2]),),
            ).fetchall()
        try:
            capabilities = tuple(Capability(cast(str, item[0])) for item in capability_rows)
            kind = ClientKind(cast(str, row[3]))
        except ValueError:
            return None
        if not capabilities or set(capabilities) - CLIENT_KIND_CAPABILITIES[kind]:
            return None
        return VerifiedClient(
            client_id=cast(str, row[2]),
            kind=kind,
            capabilities=capabilities,
            expires_at_epoch=int(expires_at.timestamp()),
            device_id=cast(str | None, row[4]),
        )

    def event_policy(self, event_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            return self._event_policy_in_connection(connection, event_id)

    def _event_policy_in_connection(
        self, connection: sqlite3.Connection, event_id: str
    ) -> dict[str, Any]:
        access_row = connection.execute(
            """
                SELECT access, derived_from_legacy_scope
                FROM event_access
                WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
        if access_row is None:
            exists = connection.execute(
                "SELECT 1 FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(f"event not found: {event_id}")
            raise RuntimeError(f"event access projection is missing: {event_id}")
        context_rows = connection.execute(
            """
                SELECT context.context_id, context.kind, context.context_key,
                       context.label, link.assignment_kind
                FROM event_contexts link
                JOIN contexts context ON context.context_id = link.context_id
                WHERE link.event_id = ?
                ORDER BY context.kind, context.context_key, context.context_id
            """,
            (event_id,),
        ).fetchall()
        return {
            "event_id": event_id,
            "access": cast(str, access_row[0]),
            "derived_from_legacy_scope": bool(access_row[1]),
            "contexts": [
                {
                    "context_id": cast(str, row[0]),
                    "kind": cast(str, row[1]),
                    "key": cast(str, row[2]),
                    "label": cast(str, row[3]),
                    "assignment_kind": cast(str, row[4]),
                }
                for row in context_rows
            ],
        }

    def source_cursor(
        self,
        source_system: SourceSystem,
        *,
        source_account: str,
        source_path: str,
    ) -> SourceCursor | None:
        if not Path(source_path).is_absolute():
            raise ValueError("source_path must be absolute")
        source_stream_id = _stable_id(
            "source_stream",
            source_system.value,
            source_account,
            _sha256_text(source_path),
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT stream.conversation_id, stream.source_kind,
                       cursor.next_record_ordinal, cursor.next_byte_offset,
                       cursor.prefix_digest
                FROM source_streams stream
                JOIN source_cursors cursor
                  ON cursor.source_stream_id = stream.source_stream_id
                WHERE stream.source_stream_id = ?
                """,
                (source_stream_id,),
            ).fetchone()
        if row is None:
            return None
        return SourceCursor(
            source_stream_id=source_stream_id,
            conversation_id=cast(str, row[0]),
            source_kind=SourceKind(cast(str, row[1])),
            next_record_ordinal=cast(int, row[2]),
            next_byte_offset=cast(int, row[3]),
            prefix_digest=cast(str, row[4]),
        )

    def source_file(self, source_file_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT source_file_id, source_system, source_account, source_path,
                       file_digest, conversation_id, parser_name, parser_version
                FROM source_files
                WHERE source_file_id = ?
                """,
                (source_file_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"source file not found: {source_file_id}")
        return {
            "source_file_id": cast(str, row[0]),
            "source_system": cast(str, row[1]),
            "source_account": cast(str, row[2]),
            "source_path": cast(str, row[3]),
            "file_digest": cast(str, row[4]),
            "conversation_id": cast(str, row[5]),
            "parser_name": cast(str, row[6]),
            "parser_version": cast(str, row[7]),
        }

    def source_event_states(self, source_file_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT e.event_id, sr.record_ordinal, sr.object_id,
                       e.event_type, e.actor_kind, e.assistant, e.authority,
                       e.scope, e.project_id, e.privacy, e.content_text,
                       e.parser_version, e.correction_id
                FROM events_current e
                JOIN source_records sr ON sr.source_record_id = e.source_record_id
                WHERE sr.source_file_id = ?
                ORDER BY sr.record_ordinal
                """,
                (source_file_id,),
            ).fetchall()
        return [_event_state_row(row) for row in rows]

    def event_state(self, event_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            return _current_event_state(connection, event_id)

    def event_state_with_generation(self, event_id: str) -> tuple[dict[str, Any], str]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            state = _current_event_state(connection, event_id)
            generation = _ledger_generation_digest(connection)
            connection.rollback()
        return state, generation

    def generation_digest(self, *, schema_version: int = SCHEMA_VERSION) -> str:
        if schema_version not in SUPPORTED_GENERATION_SCHEMA_VERSIONS:
            supported = ", ".join(
                str(item) for item in sorted(SUPPORTED_GENERATION_SCHEMA_VERSIONS)
            )
            raise ValueError(
                f"generation digest schema must be one of {supported}; found {schema_version}"
            )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                return _ledger_generation_digest(connection, schema_version=schema_version)
            finally:
                connection.rollback()

    def identity_state_digest(self) -> str:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                return _identity_state_digest(connection)
            finally:
                connection.rollback()

    def rebuild_search_index(self, *, expected_generation_digest: str) -> dict[str, Any]:
        self._require_writable()
        _validate_sha256(expected_generation_digest, "expected ledger generation")
        with closing(self._connect()) as connection, connection:
            previous_generation = _ledger_generation_digest(connection)
            if previous_generation != expected_generation_digest:
                raise RuntimeError("ledger generation changed before search-index rebuild")
            _replace_events_fts(connection)
            indexed_events = cast(
                int, connection.execute("SELECT COUNT(*) FROM events_fts").fetchone()[0]
            )
            expected_events = cast(
                int,
                connection.execute(
                    "SELECT COUNT(*) FROM events_current WHERE privacy = 'included'"
                ).fetchone()[0],
            )
            if indexed_events != expected_events:
                raise RuntimeError("rebuilt search index does not cover included events")
            new_generation = _ledger_generation_digest(connection)
            if new_generation != previous_generation:
                raise RuntimeError("search-index rebuild changed the ledger generation")
        return {
            "status": "rebuilt",
            "generation_digest": new_generation,
            "indexed_events": indexed_events,
        }

    def apply_event_corrections(
        self,
        corrections: Sequence[EventCorrection],
        *,
        expected_generation_digest: str,
        authorized_by: str,
        authorization_scope: str,
        reason: str,
    ) -> dict[str, Any]:
        self._require_writable()
        if not corrections:
            raise ValueError("at least one event correction is required")
        if not authorized_by or not authorization_scope or not reason:
            raise ValueError("correction authorization and reason are required")
        event_ids = [item.event_id for item in corrections]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("a correction plan cannot contain duplicate event ids")

        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_generation = _ledger_generation_digest(connection)
            if previous_generation != expected_generation_digest:
                raise RuntimeError(
                    "ledger generation changed after the correction plan was created"
                )
            created_at = _now()
            installation_id = _ensure_installation(connection, created_at)
            previous_mutation_digest = _latest_mutation_digest(connection)
            for correction in corrections:
                current = _current_event_state(connection, correction.event_id)
                if current["state_digest"] != correction.expected_state_digest:
                    raise RuntimeError(f"event changed after planning: {correction.event_id}")
                if correction.scope is Scope.PROJECT and not correction.project_id:
                    raise ValueError("project-scoped corrections require project_id")
                if correction.scope is not Scope.PROJECT and correction.project_id is not None:
                    raise ValueError("only project-scoped corrections may carry project_id")
                content_changed = correction.content_text != current["content_text"]
                if correction.privacy is Privacy.INCLUDED and content_changed:
                    raw = self._read_event_object(connection, correction.event_id)
                    if not _content_present_in_raw_record(raw, correction.content_text):
                        raise RuntimeError(
                            "corrected content is not present in source evidence: "
                            f"{correction.event_id}"
                        )
                content_text = (
                    "" if correction.privacy is Privacy.NO_MEMORY else correction.content_text
                )
                target = {
                    "event_type": correction.event_type,
                    "actor_kind": correction.actor_kind,
                    "assistant": correction.assistant,
                    "authority": correction.authority.value,
                    "scope": correction.scope.value,
                    "project_id": correction.project_id,
                    "privacy": correction.privacy.value,
                    "content_digest": _sha256_text(content_text),
                    "content_text": content_text,
                    "parser_version": correction.parser_version,
                }
                new_state_digest = event_state_digest(target)
                if new_state_digest == correction.expected_state_digest:
                    raise ValueError(
                        f"correction does not change event state: {correction.event_id}"
                    )
                correction_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO event_corrections(
                      correction_id, event_id, event_type, actor_kind, assistant,
                      authority, scope, project_id, privacy, content_digest,
                      content_text, parser_version, previous_state_digest,
                      new_state_digest, reason, authorized_by, authorization_scope,
                      created_at, previous_correction_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        correction_id,
                        correction.event_id,
                        correction.event_type,
                        correction.actor_kind,
                        correction.assistant,
                        correction.authority.value,
                        correction.scope.value,
                        correction.project_id,
                        correction.privacy.value,
                        target["content_digest"],
                        content_text,
                        correction.parser_version,
                        correction.expected_state_digest,
                        new_state_digest,
                        correction.reason,
                        authorized_by,
                        authorization_scope,
                        created_at,
                        current["correction_id"],
                    ),
                )
                _sync_legacy_access(
                    connection,
                    table="event_access",
                    id_column="event_id",
                    entity_id=correction.event_id,
                    scope=correction.scope.value,
                    now=created_at,
                )
                _sync_legacy_context(
                    connection,
                    table="event_contexts",
                    id_column="event_id",
                    entity_id=correction.event_id,
                    installation_id=installation_id,
                    project_id=correction.project_id,
                    now=created_at,
                )

            _rebuild_events_fts(connection)
            new_generation = _ledger_generation_digest(connection)
            mutation_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO mutation_receipts(
                  mutation_id, target_id, operation, previous_version_digest,
                  new_version_digest, authorized_by, authorization_scope,
                  reason, created_at, previous_mutation_digest
                ) VALUES (?, 'ledger_generation', 'apply_event_corrections', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mutation_id,
                    previous_generation,
                    new_generation,
                    authorized_by,
                    authorization_scope,
                    reason,
                    created_at,
                    previous_mutation_digest,
                ),
            )
        return {
            "status": "corrected",
            "mutation_id": mutation_id,
            "correction_count": len(corrections),
            "previous_generation_digest": previous_generation,
            "new_generation_digest": new_generation,
            "authorized_by": authorized_by,
            "authorization_scope": authorization_scope,
        }

    def projection_documents(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT e.event_id, e.content_text, e.content_digest, e.event_type,
                       e.actor_kind, e.assistant, e.authority, e.scope, e.project_id,
                       e.conversation_id, e.branch_id, e.occurred_at, e.correction_id,
                       ea.access, sf.source_system
                FROM events_current e
                JOIN event_access ea ON ea.event_id = e.event_id
                JOIN source_records sr ON sr.source_record_id = e.source_record_id
                JOIN source_files sf ON sf.source_file_id = sr.source_file_id
                WHERE e.privacy = 'included'
                ORDER BY e.event_id
                """
            ).fetchall()
            context_rows = connection.execute(
                """
                SELECT link.event_id, context.kind, context.context_key
                FROM event_contexts link
                JOIN contexts context ON context.context_id = link.context_id
                JOIN events_current event ON event.event_id = link.event_id
                WHERE event.privacy = 'included'
                ORDER BY link.event_id, context.kind, context.context_key
                """
            ).fetchall()
        contexts_by_event: dict[str, list[dict[str, str]]] = {}
        for row in context_rows:
            contexts_by_event.setdefault(cast(str, row[0]), []).append(
                {"kind": cast(str, row[1]), "key": cast(str, row[2])}
            )
        return [
            {
                "event_id": cast(str, row[0]),
                "content_text": cast(str, row[1]),
                "content_digest": cast(str, row[2]),
                "event_type": cast(str, row[3]),
                "actor_kind": cast(str, row[4]),
                "assistant": cast(str | None, row[5]),
                "authority": cast(str, row[6]),
                "scope": cast(str, row[7]),
                "project_id": cast(str | None, row[8]),
                "conversation_id": cast(str, row[9]),
                "branch_id": cast(str | None, row[10]),
                "occurred_at": cast(str | None, row[11]),
                "correction_id": cast(str | None, row[12]),
                "access": cast(str, row[13]),
                "source_system": cast(str, row[14]),
                "contexts": contexts_by_event.get(cast(str, row[0]), []),
            }
            for row in rows
        ]

    def validate_projection_event(
        self,
        event_id: str,
        *,
        content_digest: str,
        scopes: Sequence[Scope],
        project_id: str | None,
        authorities: Sequence[Authority],
        accesses: Sequence[Access] | None = None,
        contexts: Sequence[ContextFilter] = (),
    ) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT e.event_id, e.content_text, e.content_digest, e.event_type,
                       e.actor_kind, e.assistant, e.authority, e.scope, e.project_id,
                       e.conversation_id, e.branch_id, e.occurred_at, ea.access
                FROM events_current e
                JOIN event_access ea ON ea.event_id = e.event_id
                WHERE e.event_id = ? AND e.privacy = 'included'
                """,
                (event_id,),
            ).fetchone()
        if row is None or cast(str, row[2]) != content_digest:
            raise RuntimeError(f"projection evidence is stale or missing: {event_id}")
        scope = Scope(cast(str, row[7]))
        authority = Authority(cast(str, row[6]))
        if scope not in scopes:
            raise RuntimeError(f"projection result crossed a scope boundary: {event_id}")
        if (
            project_id is not None
            and scope is Scope.PROJECT
            and cast(str | None, row[8]) != project_id
        ):
            raise RuntimeError(f"projection result crossed a project boundary: {event_id}")
        if authorities and authority not in authorities:
            raise RuntimeError(f"projection result crossed an authority boundary: {event_id}")
        access = Access(cast(str, row[12]))
        if accesses is not None and access not in accesses:
            raise RuntimeError(f"projection result crossed an access boundary: {event_id}")
        required_contexts = effective_context_filters(contexts, project_id)
        if required_contexts:
            policy_contexts = {
                (ContextKind(item["kind"]), cast(str, item["key"]))
                for item in self.event_policy(event_id)["contexts"]
            }
            if any((item.kind, item.key) not in policy_contexts for item in required_contexts):
                raise RuntimeError(f"projection result crossed a context boundary: {event_id}")
        evidence = self.get_evidence(event_id, allowed_accesses=accesses)
        raw = cast(str, evidence.pop("raw_record")).encode()
        evidence["raw_record_sha256"] = hashlib.sha256(raw).hexdigest()
        return evidence

    def _read_event_object(self, connection: sqlite3.Connection, event_id: str) -> bytes:
        row = connection.execute(
            """
            SELECT o.object_path, sr.object_id, o.byte_length
            FROM events event
            JOIN source_records sr ON sr.source_record_id = event.source_record_id
            JOIN objects o ON o.object_id = sr.object_id
            WHERE event.event_id = ?
            """,
            (event_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"event not found: {event_id}")
        return self._read_object(
            cast(str, row[0]), cast(str, row[1]), cast(int, row[2]), connection=connection
        )

    def _validate_read_only(self) -> None:
        root = self.settings.data_root
        database = self.settings.database_path
        if root.is_symlink() or not root.is_dir():
            raise ValueError(f"read-only data root must be an existing directory: {root}")
        if database.is_symlink() or not database.is_file():
            raise ValueError(f"read-only ledger must be an existing regular file: {database}")
        if self.require_checkpointed:
            _reject_read_only_sidecars(database)
        with closing(self._connect()) as connection:
            try:
                row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            except sqlite3.Error as error:
                raise RuntimeError("read-only ledger schema is unavailable") from error
            current_version = cast(int | None, row[0] if row is not None else None)
            if current_version != SCHEMA_VERSION:
                observed = "uninitialized" if current_version is None else str(current_version)
                raise RuntimeError(
                    f"read-only ledger requires schema {SCHEMA_VERSION}; found {observed}; "
                    "run an approved writable migration first"
                )
            validate_current_schema_objects(connection)

    def _require_writable(self) -> None:
        if self.read_only:
            raise RuntimeError("operation is unavailable on a read-only ledger")

    def _record_query_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        mode: QueryMode,
        query: str,
        principal: str,
        filters: dict[str, object],
        results: Sequence[SearchResult],
        omitted_counts: dict[str, object],
        latency_ms: float,
    ) -> None:
        if self.read_only:
            return
        connection.execute(
            """
            INSERT INTO query_receipts(
              query_id, query_mode, query_digest, principal, filters_json,
              result_event_ids_json, omitted_counts_json, latency_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                mode.value,
                _sha256_text(query),
                principal,
                json.dumps(filters, sort_keys=True),
                json.dumps([item.event_id for item in results]),
                json.dumps(omitted_counts, sort_keys=True),
                latency_ms,
                _now(),
            ),
        )
        connection.commit()

    def _connect(self) -> sqlite3.Connection:
        if self._admission_transaction is not None:
            kind = self._admission_transaction.kind.replace("_", " ")
            raise RuntimeError(f"use the active {kind} transaction for batch reads and writes")
        if self.settings.database_path.is_symlink():
            raise ValueError("ledger database must not be a symlink")
        if self.read_only:
            database = self.settings.database_path
            if not database.is_file():
                raise ValueError(f"read-only ledger must be an existing regular file: {database}")
            if self.require_checkpointed:
                _reject_read_only_sidecars(database)
                uri = f"{database.resolve(strict=True).as_uri()}?mode=ro&immutable=1"
            else:
                _validate_live_read_only_sidecars(database)
                uri = f"{database.resolve(strict=True).as_uri()}?mode=ro"
            connection = sqlite3.connect(uri, timeout=15, uri=True, factory=_WriterLockedConnection)
        else:
            lock_descriptor: int | None = None
            token = self._exclusive_writer_token
            if token is not None:
                if not token.active or token.database_path != self.settings.database_path.resolve():
                    raise RuntimeError("exclusive ledger writer token is inactive or mismatched")
                if (
                    token.database_identity is not None
                    and _regular_path_identity(self.settings.database_path)
                    != token.database_identity
                ):
                    raise RuntimeError("ledger database identity changed under the writer lock")
            else:
                lock_descriptor = _open_writer_lock(self.settings)
            try:
                if lock_descriptor is not None:
                    _acquire_writer_lock(
                        lock_descriptor, fcntl.LOCK_SH, wait=not self._fail_fast_on_maintenance
                    )
                check_object_write_access(self.settings.data_root, self._object_write_scope)
                connection = sqlite3.connect(
                    self.settings.database_path,
                    timeout=15,
                    factory=_WriterLockedConnection,
                )
            except BaseException:
                if lock_descriptor is not None:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                    os.close(lock_descriptor)
                raise
            if token is not None:
                connected_identity = _regular_path_identity(self.settings.database_path)
                if token.database_identity is None:
                    token.database_identity = connected_identity
                elif connected_identity != token.database_identity:
                    connection.close()
                    raise RuntimeError("ledger database identity changed while it was opened")
            connection.writer_lock_descriptor = lock_descriptor
        try:
            if not self._rotation_maintenance:
                require_rotation_access(connection, self.settings, self._encrypted_evidence_reader)
                if self._encrypted_evidence_reader is not None:
                    self._encrypted_evidence_reader.require_current_runtime()
                if self.read_only:
                    connection.rotation_close_guard = lambda: check_rotation_access(
                        self.settings,
                        self._encrypted_evidence_reader,
                        require_checkpointed=self.require_checkpointed,
                    )
        except BaseException:
            connection.close()
            raise
        if not self.read_only:
            self.settings.database_path.chmod(0o600)
        connection.row_factory = sqlite3.Row
        connection.create_function("cam_lexical_score", 2, lexical_score, deterministic=True)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 15000")
        if self.read_only:
            connection.execute("PRAGMA query_only = ON")
        else:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA secure_delete = ON")
        return connection

    @contextmanager
    def _upload_transaction(self) -> Generator[None, None, None]:
        self._require_writable()
        if self._admission_transaction is not None:
            raise RuntimeError("an admission transaction is already active")
        token = self._exclusive_writer_token
        if token is None or not token.active:
            raise RuntimeError("upload transactions require an active exclusive writer")
        created_object_paths: set[Path] = set()
        try:
            with self._object_write_transaction(created_object_paths) as connection:
                connection.execute("BEGIN IMMEDIATE")
                transaction = _AdmissionTransaction(
                    connection, token, created_object_paths, kind="native_upload"
                )
                self._admission_transaction = transaction
                try:
                    yield
                    transaction.require_active()
                finally:
                    self._admission_transaction = None
        finally:
            if self._object_write_journal is not None:
                self._object_write_journal.close()
                self._object_write_journal = None

    def _start_object_write_attempt(self, connection: sqlite3.Connection) -> None:
        if self._object_write_scope is None:
            return
        journal = ObjectWriteJournal(self.settings.data_root, self._object_write_scope)
        self._object_write_journal = journal
        if journal.rollback_pending:
            if journal.abort(self._registered_object_check(connection)):
                journal.close()
                self._object_write_journal = None
                self._object_write_journal = ObjectWriteJournal(
                    self.settings.data_root, self._object_write_scope
                )
            elif journal.aborting:
                raise RuntimeError("object write rollback requires the unchanged retained attempt")

    @contextmanager
    def web_export_transaction(self, *, expected_generation: str) -> Generator[None, None, None]:
        """Group guarded web admissions without publishing provider objects before commit."""
        self._require_writable()
        if self._admission_transaction is not None:
            raise RuntimeError("a web export transaction is already active")
        token = self._exclusive_writer_token
        if token is None or not token.active:
            raise RuntimeError("web export transactions require an active exclusive writer")
        _validate_sha256(expected_generation, "expected ledger generation")
        created_object_paths: set[Path] = set()
        try:
            with self._object_write_transaction(created_object_paths) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if _ledger_generation_digest(connection) != expected_generation:
                    raise RuntimeError("ledger generation changed before web export transaction")
                self._start_object_write_attempt(connection)
                transaction = _AdmissionTransaction(
                    connection, token, created_object_paths, expected_generation
                )
                self._admission_transaction = transaction
                try:
                    yield
                    transaction.require_active()
                finally:
                    self._admission_transaction = None
        finally:
            if self._object_write_journal is not None:
                self._object_write_journal.close()
                self._object_write_journal = None

    @staticmethod
    def _registered_object_check(connection: sqlite3.Connection) -> Callable[[str, int], bool]:
        def registered(digest: str, size: int) -> bool:
            row = connection.execute(
                "SELECT plaintext_digest, byte_length FROM objects WHERE object_id = ?",
                (f"sha256:{digest}",),
            ).fetchone()
            if row is not None and tuple(row) != (digest, size):
                raise RuntimeError("registered object differs from its write attempt")
            return row is not None

        return registered

    def finish_object_write_attempt(self) -> None:
        scope = self._object_write_scope
        if scope is None:
            raise ValueError("object write completion requires its exact scope")
        path = self.settings.data_root / JOURNAL_NAME
        if not path.exists() and not path.is_symlink():
            return
        with closing(self._connect()) as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM web_export_import_receipts WHERE batch_sha256 = ?",
                    (scope.operation_sha256,),
                ).fetchone()
                is None
            ):
                raise RuntimeError("object writes have no committed import receipt")
            with closing(ObjectWriteJournal(self.settings.data_root, scope)) as journal:
                journal.finish(self._registered_object_check(connection))

    def web_export_status(self) -> dict[str, Any]:
        """Inspect this writer's uncommitted batch without opening another connection."""
        transaction = self._admission_transaction
        if transaction is None or transaction.kind != "web_export":
            raise RuntimeError("web export transaction is inactive")
        transaction.require_active()
        return self._status_in_transaction(transaction.connection)

    def record_web_export_receipt(self, *, batch_sha256: str, receipt_json: str) -> None:
        """Commit an immutable retry outcome in the same transaction as its web admissions."""
        self._require_writable()
        transaction = self._admission_transaction
        if transaction is None or transaction.kind != "web_export":
            raise RuntimeError("web export receipt requires an active web export transaction")
        with self._object_write_transaction(set()) as connection:
            _validate_sha256(batch_sha256, "web export batch SHA-256")
            if len(receipt_json.encode()) > MAX_WEB_EXPORT_RECEIPT_BYTES:
                raise ValueError("web export receipt exceeds its size limit")
            receipt: object = json.loads(receipt_json)
            if not isinstance(receipt, dict):
                raise ValueError("web export receipt must contain an object")
            payload = cast(dict[str, Any], receipt)
            if (
                payload.get("batch_approval_sha256") != batch_sha256
                or payload.get("expected_ledger_generation") != transaction.expected_generation
                or payload.get("result_ledger_generation") != _ledger_generation_digest(connection)
            ):
                raise RuntimeError("web export receipt does not bind this transaction")
            connection.execute(
                "INSERT INTO web_export_import_receipts VALUES (?, ?)",
                (batch_sha256, receipt_json),
            )

    def committed_web_export_receipt(self, batch_sha256: str) -> str | None:
        _validate_sha256(batch_sha256, "web export batch SHA-256")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT receipt_json FROM web_export_import_receipts WHERE batch_sha256 = ?",
                (batch_sha256,),
            ).fetchone()
        return cast(str, row[0]) if row is not None else None

    @contextmanager
    def _object_write_transaction(
        self,
        created_object_paths: set[Path],
    ) -> Generator[sqlite3.Connection, None, None]:
        transaction = self._admission_transaction
        if transaction is not None:
            transaction.require_active()
            try:
                yield transaction.connection
            except BaseException:
                transaction.failed = True
                raise
            finally:
                transaction.created_object_paths.update(created_object_paths)
            return
        with closing(self._connect()) as connection:
            try:
                with connection:
                    yield connection
            except BaseException:
                connection.execute("BEGIN IMMEDIATE")
                if self._object_write_journal is not None:
                    self._object_write_journal.abort(self._registered_object_check(connection))
                else:
                    self._remove_unregistered_object_paths(connection, created_object_paths)
                connection.commit()
                raise

    def _remove_unregistered_object_paths(
        self,
        connection: sqlite3.Connection,
        created_object_paths: set[Path],
    ) -> None:
        for path in sorted(created_object_paths):
            if not path.is_relative_to(self.settings.object_root):
                raise RuntimeError("created object path escaped the object root")
            relative = path.relative_to(self.settings.data_root).as_posix()
            registered = connection.execute(
                "SELECT 1 FROM objects WHERE object_path = ?",
                (relative,),
            ).fetchone()
            if registered is None:
                path.unlink(missing_ok=True)

    def bind_encrypted_evidence(
        self,
        event_id: str,
        manifest: EncryptedObjectManifest,
        *,
        expected_generation_digest: str,
        authorized_by: str,
        authorization_scope: str,
        reason: str,
    ) -> dict[str, str]:
        """Bind an already verified copy; do not upload or remove local evidence."""
        self._require_writable()
        with closing(self._connect()) as connection:
            object_id = cast(str, _publication_target(connection, event_id)[0])
        return self._bind_encrypted_object(
            object_id,
            manifest,
            expected_generation_digest=expected_generation_digest,
            authorized_by=authorized_by,
            authorization_scope=authorization_scope,
            reason=reason,
        )

    def _bind_encrypted_object(
        self,
        object_id: str,
        manifest: EncryptedObjectManifest,
        *,
        expected_generation_digest: str,
        authorized_by: str,
        authorization_scope: str,
        reason: str,
    ) -> dict[str, str]:
        self._require_writable()
        token = self._exclusive_writer_token
        if token is None or not token.active:
            raise RuntimeError("encrypted evidence binding requires an exclusive ledger writer")
        reader = self._encrypted_evidence_reader
        if reader is None:
            raise RuntimeError("encrypted evidence reader is not configured")
        _validate_sha256(expected_generation_digest, "expected ledger generation")
        authorizer = _bounded_identity_value(authorized_by, "binding authorizer")
        scope = _bounded_identity_value(authorization_scope, "binding authorization scope")
        explanation = _bounded_identity_value(reason, "binding reason")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_generation = _ledger_generation_digest(connection)
            if previous_generation != expected_generation_digest:
                raise RuntimeError("ledger generation changed before encrypted evidence binding")
            return self._bind_encrypted_object_in_transaction(
                connection,
                object_id,
                manifest,
                previous_generation=previous_generation,
                authorizer=authorizer,
                scope=scope,
                explanation=explanation,
            )

    def _bind_encrypted_object_in_transaction(
        self,
        connection: sqlite3.Connection,
        object_id: str,
        manifest: EncryptedObjectManifest,
        *,
        previous_generation: str,
        authorizer: str,
        scope: str,
        explanation: str,
    ) -> dict[str, str]:
        if not connection.in_transaction:
            raise RuntimeError("encrypted evidence binding requires an active transaction")
        reader = self._encrypted_evidence_reader
        if reader is None:
            raise RuntimeError("encrypted evidence reader is not configured")
        row = _publication_object_target(connection, object_id)
        object_id, byte_length = cast(str, row[0]), cast(int, row[1])
        _require_object_not_pending_deletion(connection, object_id)
        excluded_reference = connection.execute(
            "SELECT 1 FROM source_records r JOIN events_current e "
            "ON e.source_record_id = r.source_record_id "
            "WHERE r.object_id = ? AND e.privacy != 'included' LIMIT 1",
            (object_id,),
        ).fetchone()
        if excluded_reference:
            raise RuntimeError("encrypted evidence has an excluded reference requiring remediation")
        identity = reader.backend.identity_sha256
        existing = read_location(connection, object_id)
        require_mapping_state(cast(str, row[2]), existing)
        if existing is not None and (
            existing[0] != identity
            or not same_encrypted_object(existing[1], manifest)
            or (existing[1].state != ObjectState.PENDING and existing[1] != manifest)
        ):
            raise RuntimeError("encrypted evidence already has a different location")
        reader.read(
            manifest,
            object_id=object_id,
            expected_size=byte_length,
            backend_identity_sha256=identity,
        )
        if existing is not None and existing[1].state == ObjectState.VERIFIED:
            return {
                "status": "already_bound",
                "object_id": object_id,
                "generation_digest": previous_generation,
            }
        connection.execute(
            "INSERT INTO encrypted_object_locations VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(object_id) DO UPDATE SET manifest_json = excluded.manifest_json",
            (
                object_id,
                manifest.source_object_id,
                manifest.storage_object_id,
                manifest.backend_profile,
                identity,
                json.dumps(manifest.as_dict(), sort_keys=True, separators=(",", ":")),
            ),
        )
        connection.execute(
            "UPDATE objects SET storage_kind = 'encrypted' WHERE object_id = ?", (object_id,)
        )
        new_generation = _ledger_generation_digest(connection)
        connection.execute(
            "INSERT INTO mutation_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                object_id,
                "bind_encrypted_evidence",
                previous_generation,
                new_generation,
                authorizer,
                scope,
                explanation,
                _now(),
                _latest_mutation_digest(connection),
            ),
        )
        return {"status": "bound", "object_id": object_id, "generation_digest": new_generation}

    def publish_encrypted_evidence(
        self,
        event_id: str,
        *,
        expected_generation_digest: str,
        authorized_by: str,
        authorization_scope: str,
        reason: str,
    ) -> dict[str, str]:
        """Publish one admitted record, retaining its local copy and a retryable intent."""
        self._require_writable()
        _validate_sha256(expected_generation_digest, "expected ledger generation")
        with closing(self._connect()) as connection:
            object_id = cast(str, _publication_target(connection, event_id)[0])
        return self._publish_encrypted_object(
            object_id,
            expected_generation_digest=expected_generation_digest,
            authorized_by=authorized_by,
            authorization_scope=authorization_scope,
            reason=reason,
        )

    def _publish_encrypted_object(
        self,
        object_id: str,
        *,
        expected_generation_digest: str | None,
        authorized_by: str,
        authorization_scope: str,
        reason: str,
    ) -> dict[str, str]:
        self._require_writable()
        token = self._exclusive_writer_token
        if token is None or not token.active:
            raise RuntimeError("encrypted evidence publication requires an exclusive ledger writer")
        reader = self._encrypted_evidence_reader
        if reader is None:
            raise RuntimeError("encrypted evidence reader is not configured")
        if expected_generation_digest is not None:
            _validate_sha256(expected_generation_digest, "expected ledger generation")
        authorizer = _bounded_identity_value(authorized_by, "publication authorizer")
        scope = _bounded_identity_value(authorization_scope, "publication authorization scope")
        explanation = _bounded_identity_value(reason, "publication reason")
        publication: EvidencePublication | None = None
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = _ledger_generation_digest(connection)
            if expected_generation_digest is not None and previous != expected_generation_digest:
                raise RuntimeError("ledger generation changed before evidence publication")
            pending_generation = previous
            row = _publication_object_target(connection, object_id)
            object_id, byte_length = cast(str, row[0]), cast(int, row[1])
            if byte_length > min(reader.max_plaintext_bytes, DEFAULT_MAX_RECORD_BYTES):
                raise ValueError("evidence publication exceeds the admitted record byte limit")
            other_pending = connection.execute(
                "SELECT 1 FROM encrypted_object_locations l JOIN objects o USING(object_id) "
                "WHERE o.storage_kind = 'local' AND l.object_id != ? LIMIT 1",
                (object_id,),
            ).fetchone()
            if other_pending:
                raise RuntimeError("resume the pending evidence publication before another")
            existing = read_location(connection, object_id)
            require_mapping_state(cast(str, row[2]), existing)
            if existing is not None and existing[0] != reader.backend.identity_sha256:
                raise RuntimeError("pending evidence publication backend identity changed")
            if existing is not None and existing[1].state == ObjectState.VERIFIED:
                manifest = existing[1]
            else:
                raw = self._read_object(
                    cast(str, row[3]), object_id, byte_length, connection=connection
                )
                decision = (
                    classify_attachment(
                        SourceSystem(row[5]),
                        cast(str, row[4]),
                        raw,
                        max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
                    )
                    if row[6] is None
                    else classify_record(
                        SourceSystem(row[5]),
                        cast(str, row[6]),
                        raw,
                        max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
                    )
                )
                if not decision.accepted:
                    raise RuntimeError("evidence publication requires admission remediation")
                publication = EvidencePublication.prepare(
                    self.settings.data_root,
                    reader,
                    self.settings.data_root / cast(str, row[3]),
                    object_id=object_id,
                    byte_length=byte_length,
                    media_type=cast(str, row[4]),
                    pending=existing[1] if existing is not None else None,
                )
                manifest = publication.manifest
                if existing is None:
                    connection.execute(
                        "INSERT INTO encrypted_object_locations VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            object_id,
                            manifest.source_object_id,
                            manifest.storage_object_id,
                            manifest.backend_profile,
                            reader.backend.identity_sha256,
                            json.dumps(manifest.as_dict(), sort_keys=True, separators=(",", ":")),
                        ),
                    )
                    pending_generation = _ledger_generation_digest(connection)
                    connection.execute(
                        "INSERT INTO mutation_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            str(uuid.uuid4()),
                            object_id,
                            "prepare_encrypted_evidence",
                            previous,
                            pending_generation,
                            authorizer,
                            scope,
                            explanation,
                            _now(),
                            _latest_mutation_digest(connection),
                        ),
                    )
        if publication is not None:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                if _ledger_generation_digest(connection) != pending_generation:
                    raise RuntimeError("ledger generation changed before encrypted evidence upload")
                _publication_object_target(connection, object_id)
                committed = read_location(connection, object_id)
                if committed is None or committed[0] != reader.backend.identity_sha256:
                    raise RuntimeError(
                        "evidence publication backend identity changed before upload"
                    )
                manifest = publication.upload()
                # The upload transaction still owns the writer lock and checked generation.
                result = self._bind_encrypted_object_in_transaction(
                    connection,
                    object_id,
                    manifest,
                    previous_generation=pending_generation,
                    authorizer=authorizer,
                    scope=scope,
                    explanation=explanation,
                )
        else:
            result = self._bind_encrypted_object(
                object_id,
                manifest,
                expected_generation_digest=pending_generation,
                authorized_by=authorizer,
                authorization_scope=scope,
                reason=explanation,
            )
        if publication is None:
            EvidencePublication.finish_existing(self.settings.data_root, reader, manifest)
        else:
            publication.finish(manifest)
        return result

    def _queue_source_evidence_publication(
        self, connection: sqlite3.Connection, source_file_id: str
    ) -> None:
        if self._evidence_publication_policy is None:
            return
        for (object_id,) in connection.execute(
            "SELECT DISTINCT object_id FROM source_records WHERE source_file_id = ?",
            (source_file_id,),
        ).fetchall():
            self._queue_evidence_publication(connection, object_id, newly_created=False)

    def _source_publication_complete(self, source_file_id: str) -> bool:
        reader = self._encrypted_evidence_reader
        if reader is None or self._evidence_publication_policy is None:
            raise RuntimeError("publication completion requires explicit remote-primary access")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            if connection.execute(
                "SELECT 1 FROM evidence_publication_work w "
                "JOIN source_records r USING(object_id) WHERE r.source_file_id = ? LIMIT 1",
                (source_file_id,),
            ).fetchone():
                return False
            for object_id, size, storage_kind in connection.execute(
                "SELECT DISTINCT r.object_id, o.byte_length, o.storage_kind "
                "FROM source_records r LEFT JOIN objects o USING(object_id) "
                "WHERE r.source_file_id = ?",
                (source_file_id,),
            ):
                location = read_location(connection, object_id)
                require_mapping_state(storage_kind, location)
                if storage_kind != "encrypted" or location is None:
                    return False
                reader.validate_location(
                    location[1],
                    object_id=object_id,
                    expected_size=size,
                    backend_identity_sha256=location[0],
                )
        return True

    def _queue_evidence_publication(
        self, connection: sqlite3.Connection, object_id: str, *, newly_created: bool
    ) -> None:
        policy = self._evidence_publication_policy
        reader = self._encrypted_evidence_reader
        if policy is not None and reader is not None:
            identity = None
            if newly_created:
                digest = object_id.removeprefix("sha256:")
                path = self.settings.object_root / digest[:2] / digest
                identity = _sha256_text(json.dumps(_stat_identity(path.lstat())))
            enqueue_publication_work(
                connection,
                reader,
                policy,
                object_id=object_id,
                retire_plaintext=newly_created,
                plaintext_identity_sha256=identity,
            )

    def evidence_publication_status(self) -> dict[str, int]:
        with closing(self._connect()) as connection:
            return self._evidence_publication_status_in_transaction(connection)

    @staticmethod
    def _evidence_publication_status_in_transaction(
        connection: sqlite3.Connection,
    ) -> dict[str, int]:
        row = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(o.byte_length), 0), "
            "COALESCE(SUM(o.storage_kind = 'local'), 0) "
            "FROM evidence_publication_work w JOIN objects o USING(object_id)"
        ).fetchone()
        return {
            "pending_objects": cast(int, row[0]),
            "pending_bytes": cast(int, row[1]),
            "awaiting_remote_verification": cast(int, row[2]),
        }

    def drain_evidence_publications(self, *, max_objects: int | None = None) -> dict[str, int]:
        """Resume admitted work; only return success after verification and owned retirement."""
        if self._evidence_publication_policy is None:
            raise ValueError("remote-primary publication is not configured")
        if max_objects is not None and (type(max_objects) is not int or max_objects < 0):
            raise ValueError("publication limit must be a nonnegative integer")
        with self._publication_writer() as ledger:
            return ledger._drain_evidence_publications(max_objects=max_objects)

    def _drain_evidence_publications(self, *, max_objects: int | None = None) -> dict[str, int]:
        check_object_write_access(self.settings.data_root, None)
        reader = self._encrypted_evidence_reader
        if reader is None:
            raise ValueError("remote-primary publication requires explicit evidence access")
        completed = 0
        try:
            while True:
                with closing(self._connect()) as connection:
                    work = connection.execute(
                        "SELECT w.object_id, w.backend_identity_sha256, w.root_key_sha256, "
                        "w.retire_plaintext, w.plaintext_identity_sha256 "
                        "FROM evidence_publication_work w "
                        "JOIN objects o USING(object_id) "
                        "LEFT JOIN encrypted_object_locations l USING(object_id) "
                        "ORDER BY (l.object_id IS NOT NULL AND o.storage_kind = 'local') DESC, "
                        "w.rowid LIMIT 1"
                    ).fetchone()
                if work is None:
                    return {"completed_objects": completed, **self.evidence_publication_status()}
                if max_objects is not None and completed >= max_objects:
                    raise EvidencePublicationYielded(completed)
                if (work[1], work[2]) != (
                    reader.backend.identity_sha256,
                    publication_key_sha256(reader),
                ):
                    raise RuntimeError("publication work belongs to another backend or key")
                object_id = cast(str, work[0])
                self._publish_encrypted_object(
                    object_id,
                    expected_generation_digest=None,
                    authorized_by="runtime:remote-primary",
                    authorization_scope="admitted-source-evidence",
                    reason="complete configured remote-primary admission",
                )
                self._finish_evidence_publication(object_id, tuple(work))
                completed += 1
        except EvidencePublicationYielded:
            raise
        except (OSError, RuntimeError, ValueError, KeyError, sqlite3.Error):
            raise EvidencePublicationPending(
                "evidence publication is pending; retry the same import or resume publication"
            ) from None

    def _finish_evidence_publication(self, object_id: str, expected_work: tuple[Any, ...]) -> None:
        reader = self._encrypted_evidence_reader
        if reader is None:
            raise ValueError("remote-primary publication requires explicit evidence access")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            work = connection.execute(
                "SELECT object_id, backend_identity_sha256, root_key_sha256, retire_plaintext, "
                "plaintext_identity_sha256 "
                "FROM evidence_publication_work WHERE object_id = ?",
                (object_id,),
            ).fetchone()
            if work is None or tuple(work) != expected_work:
                raise RuntimeError("publication work changed before completion")
            row = _publication_object_target(connection, object_id)
            location = read_location(connection, object_id)
            require_mapping_state(cast(str, row[2]), location)
            if row[2] != "encrypted" or location is None:
                raise RuntimeError("plaintext retirement requires verified encrypted evidence")
            reader.validate_location(
                location[1],
                object_id=object_id,
                expected_size=cast(int, row[1]),
                backend_identity_sha256=location[0],
            )
            # This transaction changes only the final publication-work table in the digest.
            generation_prefix = _ledger_generation_prefix(connection)
            previous_generation = _publication_generation_digest(connection, generation_prefix)
            if work[3]:
                path = self.settings.data_root / cast(str, row[3])
                parent_descriptor = open_directory_no_symlinks(path.parent, "evidence parent")
                try:
                    parent_identity = os.fstat(parent_descriptor)
                    if _stat_identity(parent_identity) != _stat_identity(path.parent.lstat()):
                        raise RuntimeError("plaintext parent changed before retirement")
                    try:
                        before = path.lstat()
                    except FileNotFoundError:
                        before = None
                    if before is not None:
                        if _sha256_text(json.dumps(_stat_identity(before))) != work[4]:
                            raise RuntimeError("owned plaintext identity changed before retirement")
                        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                            raise RuntimeError(
                                "owned plaintext retirement requires a single-link file"
                            )
                        self._verify_object(path, object_id, cast(int, row[1]))
                        after = path.lstat()
                        if _stat_identity(before) != _stat_identity(after) or _stat_identity(
                            parent_identity
                        ) != _stat_identity(path.parent.lstat()):
                            raise RuntimeError("owned plaintext changed before retirement")
                        os.unlink(path.name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
                finally:
                    os.close(parent_descriptor)
            connection.execute(
                "DELETE FROM evidence_publication_work WHERE object_id = ?", (object_id,)
            )
            connection.execute(
                "INSERT INTO mutation_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    object_id,
                    "complete_evidence_publication",
                    previous_generation,
                    _publication_generation_digest(connection, generation_prefix),
                    "runtime:remote-primary",
                    "admitted-source-evidence",
                    "retire owned plaintext" if work[3] else "preserve legacy plaintext",
                    _now(),
                    _latest_mutation_digest(connection),
                ),
            )

    def preview_unregistered_publication(self) -> dict[str, Any]:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            generation = _ledger_generation_digest(connection)
            cleanup = self._inspect_unregistered_publication(connection)
        return {
            "status": "preview",
            "operation_scope": "unregistered_local_publication_preparation",
            "generation_digest": generation,
            "preparation_scope_sha256": cleanup.scope_sha256,
            "proposed_files": len(cleanup.artifacts),
            "proposed_bytes": sum(item.byte_length for item in cleanup.artifacts),
            "remote_deletion_performed": False,
            "canonical_evidence_changed": False,
            "text_free": True,
        }

    def _inspect_unregistered_publication(
        self, connection: sqlite3.Connection
    ) -> PreparationCleanup:
        reader = self._encrypted_evidence_reader
        if reader is None:
            raise RuntimeError("encrypted evidence reader is not configured")
        if (
            connection.execute(
                "SELECT 1 FROM encrypted_object_locations l JOIN objects o USING(object_id) "
                "WHERE o.storage_kind = 'local' LIMIT 1"
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM deletion_object_work w "
                "JOIN deletion_operations d USING(operation_id) "
                "WHERE w.encrypted_purge_json IS NOT NULL AND d.status != 'complete' LIMIT 1"
            ).fetchone()
        ):
            raise RuntimeError("registered publication or deletion work requires its own recovery")
        cleanup = inspect_preparation_cleanup(self.settings.data_root, reader)
        for source_id in cleanup.source_object_ids:
            if connection.execute(
                "SELECT 1 FROM encrypted_object_locations WHERE source_object_id = ?",
                (source_id,),
            ).fetchone():
                raise RuntimeError("preparation belongs to registered encrypted evidence")
        for storage_id in cleanup.storage_object_ids:
            if connection.execute(
                "SELECT 1 FROM encrypted_object_locations WHERE storage_object_id = ?",
                (storage_id,),
            ).fetchone():
                raise RuntimeError("preparation belongs to registered encrypted evidence")
        return cleanup

    def discard_unregistered_publication(
        self,
        *,
        expected_generation_digest: str,
        authorized_by: str,
        authorization_scope: str,
        reason: str,
        expected_preparation_scope_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Release only unpublished preparation files; never erase evidence or contact storage."""
        self._require_writable()
        token = self._exclusive_writer_token
        if token is None or not token.active:
            raise RuntimeError(
                "publication preparation cleanup requires an exclusive ledger writer"
            )
        reader = self._encrypted_evidence_reader
        if reader is None:
            raise RuntimeError("encrypted evidence reader is not configured")
        _validate_sha256(expected_generation_digest, "expected ledger generation")
        authorizer = _bounded_identity_value(authorized_by, "preparation cleanup authorizer")
        scope = _bounded_identity_value(authorization_scope, "preparation cleanup scope")
        explanation = _bounded_identity_value(reason, "preparation cleanup reason")
        if expected_preparation_scope_sha256 is not None:
            _validate_sha256(expected_preparation_scope_sha256, "expected preparation scope")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            generation = _ledger_generation_digest(connection)
            if generation != expected_generation_digest:
                raise RuntimeError("ledger generation changed before preparation cleanup")
            cleanup = self._inspect_unregistered_publication(connection)
            if (
                expected_preparation_scope_sha256 is not None
                and cleanup.scope_sha256 != expected_preparation_scope_sha256
            ):
                raise RuntimeError("publication preparation changed after inspection")
            previous_mutation = _latest_mutation_digest(connection)
            cleanup.discard(
                self.settings.data_root, max_ciphertext_bytes=reader.max_ciphertext_bytes
            )
            if cleanup.artifacts:
                connection.execute(
                    "INSERT INTO mutation_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        f"preparation:{cleanup.scope_sha256}",
                        "discard_unregistered_publication",
                        generation,
                        generation,
                        authorizer,
                        scope,
                        explanation,
                        _now(),
                        previous_mutation,
                    ),
                )
        return {
            "status": "discarded" if cleanup.artifacts else "empty",
            "operation_scope": "unregistered_local_publication_preparation",
            "generation_digest": generation,
            "removed_files": len(cleanup.artifacts),
            "removed_bytes": sum(item.byte_length for item in cleanup.artifacts),
            "remote_deletion_performed": False,
            "canonical_evidence_changed": False,
            "text_free": True,
        }

    def _store_object(
        self,
        raw: bytes,
        *,
        connection: sqlite3.Connection,
        created_object_paths: set[Path] | None = None,
    ) -> tuple[str, str]:
        digest = hashlib.sha256(raw).hexdigest()
        object_id = f"sha256:{digest}"
        parent = self.settings.object_root / digest[:2]
        path = parent / digest
        relative = str(path.relative_to(self.settings.data_root))
        registered = connection.execute(
            "SELECT plaintext_digest, byte_length, object_path, storage_kind "
            "FROM objects WHERE object_id = ?",
            (object_id,),
        ).fetchone()
        location = read_location(connection, object_id)
        if registered is None and location is not None:
            raise RuntimeError("encrypted evidence location has no registered object")
        if registered is not None:
            if tuple(registered[:3]) != (digest, len(raw), relative):
                raise RuntimeError("registered evidence object metadata does not match admission")
            require_mapping_state(cast(str, registered[3]), location)
            if location is not None:
                reader = self._encrypted_evidence_reader
                if reader is None:
                    raise RuntimeError("encrypted evidence reader is not configured")
                reader.validate_location(
                    location[1],
                    object_id=object_id,
                    expected_size=len(raw),
                    backend_identity_sha256=location[0],
                    allowed_states=(ObjectState.PENDING, ObjectState.VERIFIED),
                )
                if registered[3] == "encrypted":
                    return object_id, relative
        try:
            parent.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            root_descriptor = open_directory_no_symlinks(self.settings.object_root, "object root")
            try:
                os.fsync(root_descriptor)
            finally:
                os.close(root_descriptor)
        if path.exists() or path.is_symlink():
            self._verify_object(path, object_id, len(raw))
            if (
                self._object_write_journal is not None
                and self._object_write_journal.owns(path)
                and created_object_paths is not None
            ):
                created_object_paths.add(path)
            return object_id, relative
        journal = self._object_write_journal
        if journal is not None:
            pending = path.with_name(f".{digest}.pending")
            if digest not in journal.entries and (pending.exists() or pending.is_symlink()):
                raise RuntimeError("unowned pending evidence requires separate review")
            journal.reserve(digest, len(raw))
        self._publish_object_bytes(
            path,
            raw,
            record_ownership=(lambda metadata: journal.ready(digest, metadata))
            if journal
            else None,
        )
        if created_object_paths is not None:
            created_object_paths.add(path)
        return object_id, relative

    @staticmethod
    def _publish_object_bytes(
        path: Path, raw: bytes, *, record_ownership: Callable[[os.stat_result], None] | None = None
    ) -> None:
        parent_descriptor = open_directory_no_symlinks(path.parent, "evidence parent")
        temporary_name = f".{path.name}.pending"
        descriptor: int | None = None
        created = False
        try:
            parent = os.fstat(parent_descriptor)
            if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
                raise RuntimeError("evidence parent must be an owned private directory")
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            try:
                descriptor = os.open(
                    temporary_name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_descriptor
                )
                created = True
            except FileExistsError:
                descriptor = os.open(temporary_name, flags, dir_fd=parent_descriptor)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size > len(raw)
            ):
                raise RuntimeError("pending evidence file identity or size changed")
            # A stopped writer may have left any prefix, but never accept different bytes.
            prefix = os.pread(descriptor, len(raw) + 1, 0)
            if prefix != raw[: before.st_size] or _stat_identity(before) != _stat_identity(
                os.fstat(descriptor)
            ):
                raise RuntimeError("pending evidence bytes changed")
            with os.fdopen(descriptor, "r+b", closefd=False) as handle:
                handle.seek(before.st_size)
                handle.write(raw[before.st_size :])
                handle.flush()
                os.fsync(handle.fileno())
            if os.pread(descriptor, len(raw) + 1, 0) != raw:
                raise RuntimeError("pending evidence failed byte verification")
            if record_ownership is not None:
                record_ownership(os.fstat(descriptor))
            publish_file_no_replace_at(
                parent_descriptor,
                temporary_name,
                path.name,
                required_mode=0o600,
                label="evidence object",
                expected_source_descriptor=descriptor,
                retain_on_failure=True,
            )
        except BaseException:
            # Only this invocation's still-unpublished inode is disposable on a caught error.
            if created and descriptor is not None:
                try:
                    current = os.stat(
                        temporary_name, dir_fd=parent_descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    pass
                else:
                    opened = os.fstat(descriptor)
                    if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                        os.unlink(temporary_name, dir_fd=parent_descriptor)
                        os.fsync(parent_descriptor)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_descriptor)

    def _store_file_object(
        self,
        source: Path,
        *,
        connection: sqlite3.Connection,
        source_system: SourceSystem,
        media_type: str,
        expected_sha256: str,
        expected_byte_length: int,
        created_object_paths: set[Path] | None = None,
    ) -> tuple[str, str]:
        _validate_sha256(expected_sha256, "source object digest")
        if not 0 <= expected_byte_length <= DEFAULT_MAX_RECORD_BYTES:
            raise ValueError("attachment exceeds admission size policy")
        source = source.expanduser()
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"source object must be a regular file: {source}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as source_handle:
            before = os.fstat(source_handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_byte_length:
                raise RuntimeError("source object no longer matches its approved byte length")
            raw = source_handle.read(expected_byte_length + 1)
            after = os.fstat(source_handle.fileno())
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError("source object changed during attachment admission")
        if len(raw) != expected_byte_length or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise RuntimeError("source object no longer matches its approved digest and size")
        decision = classify_attachment(
            source_system, media_type, raw, max_record_bytes=DEFAULT_MAX_RECORD_BYTES
        )
        if not decision.accepted:
            raise ValueError(f"attachment admission rejected: {decision.reason}")
        return self._store_object(
            raw, connection=connection, created_object_paths=created_object_paths
        )

    def _register_web_export_source_object(
        self,
        connection: sqlite3.Connection,
        *,
        batch_id: str,
        object_kind: str,
        conversation_index: int | None,
        source_path: Path,
        expected_sha256: str,
        expected_byte_length: int,
        media_type: str,
        conversation_id: str | None,
        branch_id: str | None,
        captured_at: str | None,
        parser_name: str,
        parser_version: str,
        schema_fingerprint: str,
        created_at: str,
    ) -> str:
        # Containers can include excluded records and unclassified members. Retain only
        # their verified provenance; admitted record/attachment objects are stored separately.
        _verify_source_container(source_path, expected_sha256, expected_byte_length)
        existing = connection.execute(
            """
            SELECT source_object_id, object_id, plaintext_sha256, byte_length, media_type,
                   conversation_id, branch_id, captured_at, parser_name, parser_version,
                   schema_fingerprint
            FROM web_export_source_objects
            WHERE batch_id = ? AND object_kind = ? AND conversation_index IS ?
            """,
            (batch_id, object_kind, conversation_index),
        ).fetchone()
        expected = (
            None,
            expected_sha256,
            expected_byte_length,
            media_type,
            conversation_id,
            branch_id,
            captured_at,
            parser_name,
            parser_version,
            schema_fingerprint,
        )
        if existing is not None:
            if existing[1] is not None:
                raise RuntimeError("retained legacy web container requires explicit remediation")
            if tuple(existing[1:]) != expected:
                raise RuntimeError("web export source object conflicts with the ledger")
            return cast(str, existing[0])
        source_object_id = f"source_{uuid.uuid4().hex}"
        connection.execute(
            """
            INSERT INTO web_export_source_objects(
              source_object_id, batch_id, object_kind, conversation_index, object_id,
              plaintext_sha256, byte_length, media_type, conversation_id, branch_id,
              captured_at, parser_name, parser_version, schema_fingerprint, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_object_id,
                batch_id,
                object_kind,
                conversation_index,
                *expected,
                created_at,
            ),
        )
        return source_object_id

    def _read_object(
        self,
        relative_path: str,
        object_id: str,
        expected_size: int,
        *,
        connection: sqlite3.Connection,
    ) -> bytes:
        kind = connection.execute(
            "SELECT storage_kind FROM objects WHERE object_id = ?", (object_id,)
        ).fetchone()
        location = read_location(connection, object_id)
        if kind is None:
            raise RuntimeError("evidence object storage mapping is missing or inconsistent")
        require_mapping_state(cast(str, kind[0]), location)
        if kind[0] == "encrypted" and location is not None:
            reader = self._encrypted_evidence_reader
            if reader is None:
                raise RuntimeError("encrypted evidence reader is not configured")
            identity, manifest = location
            return reader.read(
                manifest,
                object_id=object_id,
                expected_size=expected_size,
                backend_identity_sha256=identity,
            )
        path = self.settings.data_root / relative_path
        if path.is_symlink():
            raise RuntimeError(f"evidence object must not be a symlink: {object_id}")
        resolved_root = self.settings.object_root.resolve()
        resolved_path = path.resolve(strict=True)
        if resolved_root not in resolved_path.parents:
            raise RuntimeError(f"evidence object escaped the object root: {object_id}")
        return self._verified_object_bytes(resolved_path, object_id, expected_size)

    @staticmethod
    def _verify_object(path: Path, object_id: str, expected_size: int) -> None:
        Ledger._verified_object_bytes(path, object_id, expected_size)

    @staticmethod
    def _verified_object_bytes(path: Path, object_id: str, expected_size: int) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"evidence object is not a regular file: {path}")
        before = path.stat()
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read(expected_size + 1)
            after = os.fstat(handle.fileno())
        digest = hashlib.sha256(raw).hexdigest()
        if (
            _stat_identity(before) != _stat_identity(after)
            or len(raw) != expected_size
            or object_id != f"sha256:{digest}"
        ):
            raise RuntimeError(f"evidence object failed hash verification: {object_id}")
        return raw


def _workset_policy(
    *,
    mode: QueryMode,
    scopes: Sequence[Scope],
    contexts: Sequence[ContextFilter],
    project_id: str | None,
    authorities: Sequence[Authority] | None,
    accesses: Sequence[Access] | None,
) -> _WorksetPolicy:
    effective_accesses = tuple(dict.fromkeys(tuple(Access) if accesses is None else accesses))
    if not effective_accesses:
        raise ValueError("at least one access classification is required")
    effective_scopes = tuple(dict.fromkeys(scopes))
    if not effective_scopes:
        raise ValueError("at least one scope is required")
    effective_authorities = tuple(dict.fromkeys(authorities or ()))
    if mode in (QueryMode.WHAT_DID_I_SAY, QueryMode.WHAT_DID_I_THINK):
        effective_authorities = (Authority.USER_ASSERTION,)
    context_filters = effective_context_filters(contexts, project_id)
    if len(context_filters) > MAX_WORKSET_CONTEXT_FILTERS:
        raise ValueError(
            f"context filter count exceeds the bounded limit of {MAX_WORKSET_CONTEXT_FILTERS}"
        )

    predicates = ["e.privacy = 'included'"]
    parameters: list[object] = []
    access_placeholders = ",".join("?" for _ in effective_accesses)
    predicates.append(f"ea.access IN ({access_placeholders})")
    parameters.extend(item.value for item in effective_accesses)
    scope_placeholders = ",".join("?" for _ in effective_scopes)
    predicates.append(f"e.scope IN ({scope_placeholders})")
    parameters.extend(item.value for item in effective_scopes)
    if effective_authorities:
        authority_placeholders = ",".join("?" for _ in effective_authorities)
        predicates.append(f"e.authority IN ({authority_placeholders})")
        parameters.extend(item.value for item in effective_authorities)
    for context in context_filters:
        predicates.append(
            """
            EXISTS (
              SELECT 1
              FROM event_contexts context_link
              JOIN contexts context ON context.context_id = context_link.context_id
              WHERE context_link.event_id = e.event_id
                AND context.kind = ?
                AND context.context_key = ?
            )
            """
        )
        parameters.extend((context.kind.value, context.key))
    return _WorksetPolicy(
        accesses=effective_accesses,
        scopes=effective_scopes,
        authorities=effective_authorities,
        contexts=context_filters,
        predicates=tuple(predicates),
        parameters=tuple(parameters),
    )


def _search_result(row: sqlite3.Row) -> SearchResult:
    return SearchResult(
        event_id=cast(str, row[0]),
        content_text=cast(str, row[1]),
        event_type=cast(str, row[2]),
        actor_kind=cast(str, row[3]),
        assistant=cast(str | None, row[4]),
        authority=cast(str, row[5]),
        scope=cast(str, row[6]),
        project_id=cast(str | None, row[7]),
        conversation_id=cast(str, row[8]),
        branch_id=cast(str | None, row[9]),
        occurred_at=cast(str | None, row[10]),
        source_system=cast(str, row[11]),
        source_object_id=cast(str, row[12]),
        record_ordinal=cast(int, row[13]),
        byte_start=cast(int, row[14]),
        byte_end=cast(int, row[15]),
        rank=-float(row[16]),
        correction_id=cast(str | None, row[17]),
        corrected_at=cast(str | None, row[18]),
    )


def _event_state_row(row: sqlite3.Row) -> dict[str, Any]:
    state = {
        "event_type": cast(str, row[3]),
        "actor_kind": cast(str, row[4]),
        "assistant": cast(str | None, row[5]),
        "authority": cast(str, row[6]),
        "scope": cast(str, row[7]),
        "project_id": cast(str | None, row[8]),
        "privacy": cast(str, row[9]),
        "content_digest": _sha256_text(cast(str, row[10])),
        "content_text": cast(str, row[10]),
        "parser_version": cast(str, row[11]),
    }
    return {
        "event_id": cast(str, row[0]),
        "record_ordinal": cast(int, row[1]),
        "source_object_id": cast(str, row[2]),
        **state,
        "correction_id": cast(str | None, row[12]),
        "state_digest": event_state_digest(state),
    }


def _current_event_state(connection: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT e.event_id, sr.record_ordinal, sr.object_id,
               e.event_type, e.actor_kind, e.assistant, e.authority,
               e.scope, e.project_id, e.privacy, e.content_text,
               e.parser_version, e.correction_id
        FROM events_current e
        JOIN source_records sr ON sr.source_record_id = e.source_record_id
        WHERE e.event_id = ?
        """,
        (event_id,),
    ).fetchone()
    if row is None:
        raise KeyError(f"event not found: {event_id}")
    return _event_state_row(row)


def _reconcile_runtime_prompt_authority(
    connection: sqlite3.Connection,
    parsed: ParseResult,
    record: ParsedRecord,
    *,
    event_id: str,
    created_at: str,
) -> None:
    # Retained envelopes keep their old interpretation; reconcile only newly admitted events.
    if (
        parsed.source_kind is not SourceKind.INTERACTIVE
        or record.actor_kind != "user"
        or record.assistant is not None
        or record.authority is not Authority.USER_ASSERTION
    ):
        return
    actor_kind = "automation"
    if (
        parsed.source_system is SourceSystem.CLAUDE_CODE
        and parsed.parser_name == "claude-code-jsonl"
        and parsed.parser_version in {"0.4.0", "0.4.1", "0.4.2"}
    ):
        raw = json.loads(record.raw_record)
        message = raw.get("message")
        if parsed.parser_version in {"0.4.0", "0.4.1"} and raw.get("isMeta") is True:
            parser_version = "0.4.2"
            reason = "Claude Code isMeta=true runtime prompt attribution reconciled on admission"
            authorized_by = "parser:claude-code-jsonl:0.4.2"
        elif (
            raw.get("type") == "user"
            and raw.get("version") in ("2.1.215", "2.1.229", "2.1.234", "2.1.237")
            and isinstance(message, dict)
            and cast(dict[str, object], message).get("role") == "user"
            and isinstance(cast(dict[str, object], message).get("content"), str)
            and raw.get("isCompactSummary") is True
            and raw.get("isVisibleInTranscriptOnly") is True
        ):
            parser_version = parsed.parser_version
            reason = "Claude Code producer-marked compact summary reconciled on admission"
            authorized_by = "admission:claude-compact-summary:1"
        elif (
            raw.get("type") == "user"
            and raw.get("version") in ("2.1.209", "2.1.229")
            and isinstance(message, dict)
            and cast(dict[str, object], message).get("role") == "user"
            and isinstance(cast(dict[str, object], message).get("content"), str)
            and raw.get("origin") == {"kind": "task-notification"}
            and raw.get("promptSource") == "sdk"
        ):
            parser_version = parsed.parser_version
            reason = "Claude Code producer-marked task notification reconciled on admission"
            authorized_by = "admission:claude-task-notification:1"
        elif (
            raw.get("type") == "user"
            and isinstance(message, dict)
            and cast(dict[str, object], message).get("role") == "user"
            and isinstance(cast(dict[str, object], message).get("content"), str)
            and (
                (
                    raw.get("isCompactSummary") is True
                    and raw.get("isVisibleInTranscriptOnly") is True
                )
                or raw.get("origin") == {"kind": "task-notification"}
                or (
                    raw.get("origin") == {"kind": "task-notification", "producer": "session-task"}
                    and raw.get("promptSource") == "system"
                )
            )
        ):
            actor_kind = "source"
            parser_version = parsed.parser_version
            reason = (
                "Claude Code unverified runtime-marked origin reconciled as source observation "
                "on admission; automation not verified"
            )
            authorized_by = "admission:claude-unverified-runtime-origin:1"
        else:
            return
        assistant = "claude_code"
    elif (
        parsed.source_system is SourceSystem.CODEX
        and parsed.parser_name == "codex-jsonl"
        and parsed.parser_version in {"0.2.0", "0.2.1", "0.2.2", "0.2.3"}
    ):
        raw = json.loads(record.raw_record)
        payload = raw.get("payload")
        if raw.get("type") != "response_item" or not isinstance(payload, dict):
            return
        payload = cast(dict[str, object], payload)
        if payload.get("type") != "message" or payload.get("role") != "user":
            return
        metadata = payload.get("internal_chat_message_metadata_passthrough")
        if not isinstance(metadata, dict):
            return
        content = payload.get("content")
        # Producer classifications are positional; an unclassified part stays unmodified.
        if not isinstance(content, list) or len(cast(list[object], content)) != 1:
            return
        kinds = cast(dict[str, object], metadata).get("content_item_kinds")
        if kinds == ["goal.internal_context"]:
            reason = (
                "Codex goal.internal_context runtime prompt attribution reconciled on admission"
            )
            authorized_by = "admission:codex-goal-context:1"
        elif kinds == ["multi_agent.subagent_notification"]:
            reason = "Codex subagent notification runtime attribution reconciled on admission"
            authorized_by = "admission:codex-subagent-notification:1"
        else:
            return
        assistant = "codex"
        parser_version = parsed.parser_version
    else:
        return
    current = _current_event_state(connection, event_id)
    target = {
        **current,
        "actor_kind": actor_kind,
        "assistant": assistant,
        "authority": Authority.TOOL_OBSERVATION.value,
        "parser_version": parser_version,
    }
    connection.execute(
        """
        INSERT INTO event_corrections(
          correction_id, event_id, event_type, actor_kind, assistant,
          authority, scope, project_id, privacy, content_digest,
          content_text, parser_version, previous_state_digest,
          new_state_digest, reason, authorized_by, authorization_scope,
          created_at, previous_correction_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            event_id,
            target["event_type"],
            target["actor_kind"],
            target["assistant"],
            target["authority"],
            target["scope"],
            target["project_id"],
            target["privacy"],
            target["content_digest"],
            target["content_text"],
            target["parser_version"],
            current["state_digest"],
            event_state_digest(target),
            reason,
            authorized_by,
            "memory:ingest",
            created_at,
            current["correction_id"],
        ),
    )


def event_state_digest(state: dict[str, Any]) -> str:
    fields = {
        key: state[key]
        for key in (
            "event_type",
            "actor_kind",
            "assistant",
            "authority",
            "scope",
            "project_id",
            "privacy",
            "content_digest",
            "content_text",
            "parser_version",
        )
    }
    serialized = json.dumps(fields, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return _sha256_text(serialized)


def _identity_state_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    queries = (
        (
            "installations",
            """
            SELECT installation_id, owner_id
            FROM installations ORDER BY installation_id
            """,
        ),
        (
            "devices",
            """
            SELECT device_id, installation_id, label, platform, status
            FROM devices ORDER BY device_id
            """,
        ),
        (
            "clients",
            """
            SELECT client_id, installation_id, label, kind, status, revoked_at
            FROM clients ORDER BY client_id
            """,
        ),
        (
            "client_capabilities",
            """
            SELECT client_id, capability
            FROM client_capabilities ORDER BY client_id, capability
            """,
        ),
        (
            "client_credentials",
            """
            SELECT credential_id, client_id, token_digest, expires_at, revoked_at
            FROM client_credentials ORDER BY credential_id
            """,
        ),
        (
            "client_devices",
            """
            SELECT client_id, device_id
            FROM client_devices ORDER BY client_id
            """,
        ),
        (
            "device_enrollments",
            """
            SELECT enrollment_id, installation_id, code_digest, device_label,
                   device_platform, created_by, expires_at, credential_expires_at,
                   redeemed_at, redeemed_device_id, redeemed_client_id
            FROM device_enrollments ORDER BY enrollment_id
            """,
        ),
        (
            "source_accounts",
            """
            SELECT source_account_id, installation_id, device_id, source_system,
                   legacy_account_key, status
            FROM source_accounts ORDER BY source_account_id
            """,
        ),
        (
            "source_account_policies",
            """
            SELECT source_account_id, scope, project_id, created_by
            FROM source_account_policies ORDER BY source_account_id
            """,
        ),
    )
    for label, sql in queries:
        digest.update(f"table:{label}\n".encode())
        for row in connection.execute(sql):
            digest.update(
                json.dumps(tuple(row), ensure_ascii=False, separators=(",", ":")).encode()
            )
            digest.update(b"\n")
    return digest.hexdigest()


def _identity_precondition_matches(
    connection: sqlite3.Connection,
    *,
    expected_identity_state_sha256: str | None,
    expected_installation_id: str | None,
) -> bool:
    if expected_installation_id is not None:
        normalized_installation_id = _bounded_identity_value(
            expected_installation_id,
            "expected installation id",
        )
        row = connection.execute("SELECT installation_id FROM installations").fetchone()
        if row is None or not hmac.compare_digest(cast(str, row[0]), normalized_installation_id):
            raise RuntimeError("ledger installation changed before identity operation")
    if expected_identity_state_sha256 is None:
        return True
    _validate_sha256(expected_identity_state_sha256, "expected identity state")
    return hmac.compare_digest(
        _identity_state_digest(connection),
        expected_identity_state_sha256,
    )


def _publication_target(connection: sqlite3.Connection, event_id: str) -> tuple[Any, ...]:
    row = connection.execute(
        "SELECT o.object_id, o.byte_length, o.storage_kind, o.object_path, o.media_type, "
        "sf.source_system, e.content_text FROM events_current e "
        "JOIN source_records r ON r.source_record_id = e.source_record_id "
        "JOIN source_files sf ON sf.source_file_id = r.source_file_id "
        "JOIN objects o ON o.object_id = r.object_id "
        "WHERE e.event_id = ? AND e.privacy = 'included'",
        (event_id,),
    ).fetchone()
    if row is None:
        raise KeyError("included evidence event not found")
    _require_object_not_pending_deletion(connection, cast(str, row[0]))
    excluded = connection.execute(
        "SELECT 1 FROM source_records r JOIN events_current e "
        "ON e.source_record_id = r.source_record_id "
        "WHERE r.object_id = ? AND e.privacy != 'included' LIMIT 1",
        (row[0],),
    ).fetchone()
    if excluded:
        raise RuntimeError("encrypted evidence has an excluded reference requiring remediation")
    return tuple(row)


def _publication_object_target(connection: sqlite3.Connection, object_id: str) -> tuple[Any, ...]:
    row = connection.execute(
        "SELECT object_id, byte_length, storage_kind, object_path, media_type "
        "FROM objects WHERE object_id = ?",
        (object_id,),
    ).fetchone()
    if row is None:
        raise KeyError("admitted evidence object not found")
    digest = object_id.removeprefix("sha256:")
    if (
        re.fullmatch(r"sha256:[0-9a-f]{64}", object_id) is None
        or row[3] != f"objects/sha256/{digest[:2]}/{digest}"
    ):
        raise RuntimeError("publication object path is not its canonical evidence location")
    _require_object_not_pending_deletion(connection, object_id)
    # Joining the corrected view here materializes every event. Resolve only matched IDs.
    records = connection.execute(
        "SELECT sf.source_system, "
        "(SELECT content_text FROM events_current WHERE event_id = e.event_id), "
        "(SELECT privacy FROM events_current WHERE event_id = e.event_id) FROM source_records r "
        "JOIN source_files sf USING(source_file_id) "
        "LEFT JOIN web_export_event_observations observation USING(source_record_id) "
        "LEFT JOIN events e ON e.source_record_id = r.source_record_id "
        "OR e.event_id = observation.event_id WHERE r.object_id = ? ORDER BY r.rowid, e.rowid",
        (object_id,),
    ).fetchall()
    attachments = connection.execute(
        "SELECT sf.source_system, e.privacy FROM web_export_attachment_objects a "
        "JOIN web_export_attachment_links link USING(archive_member_id) "
        "LEFT JOIN web_export_conversation_observations obs "
        "ON obs.batch_id = link.batch_id AND obs.conversation_index = link.conversation_index "
        "LEFT JOIN source_files sf ON sf.source_file_id = obs.source_file_id "
        "LEFT JOIN source_records r ON r.source_file_id = obs.source_file_id "
        "AND r.record_ordinal = link.source_record_ordinal "
        "LEFT JOIN web_export_event_observations observation "
        "ON observation.source_record_id = r.source_record_id "
        "LEFT JOIN events_current e ON e.event_id = observation.event_id "
        "WHERE a.object_id = ?",
        (object_id,),
    ).fetchall()
    if not records and not attachments:
        raise KeyError("included evidence reference not found")
    if any(item[2] != "included" for item in records) or any(
        item[1] != "included" for item in attachments
    ):
        raise RuntimeError("encrypted evidence has an excluded reference requiring remediation")
    if records:
        return (*tuple(row), records[0][0], records[0][1])
    return (*tuple(row), attachments[0][0], None)


def _require_local_deletion_objects(
    connection: sqlite3.Connection, object_ids: frozenset[str] | set[str]
) -> None:
    if _rows_matching_ids(
        connection,
        "SELECT object_id FROM objects WHERE storage_kind != 'local' "
        "AND object_id IN ({placeholders})",
        object_ids,
    ) or _rows_matching_ids(
        connection,
        "SELECT object_id FROM encrypted_object_locations WHERE object_id IN ({placeholders})",
        object_ids,
    ):
        raise RuntimeError(
            "encrypted evidence requires version-aware deletion; "
            "this local-only operation is unavailable"
        )


def _encode_digest_row(values: tuple[Any, ...]) -> bytes:
    # Native float formatting and non-SQLite values must retain the historical encoder.
    if all(value is None or type(value) in (str, int) for value in values):
        try:
            return to_json(values, ensure_ascii=False)
        except PydanticSerializationError:
            pass
    return json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()


def _ledger_generation_digest(
    connection: sqlite3.Connection,
    *,
    schema_version: int = SCHEMA_VERSION,
) -> str:
    digest = _ledger_generation_prefix(connection, schema_version=schema_version)
    if schema_version >= 20:
        return _publication_generation_digest(connection, digest)
    return digest.hexdigest()


def _ledger_generation_prefix(
    connection: sqlite3.Connection,
    *,
    schema_version: int = SCHEMA_VERSION,
) -> HASH:
    # Operational rotation, mutation and web-import receipts bind before/after generations;
    # they cannot enter their own canonical digest. Snapshot hashes still bind their database bytes.
    # Canonical object manifests enter the digest below.
    digest = hashlib.sha256()
    digest.update(f"schema:{schema_version}\n".encode())
    queries = [
        (
            "installations",
            """
            SELECT installation_id, owner_id
            FROM installations ORDER BY installation_id
            """,
        ),
        (
            "devices",
            """
            SELECT device_id, installation_id, label, platform, status
            FROM devices ORDER BY device_id
            """,
        ),
        (
            "source_accounts",
            """
            SELECT source_account_id, installation_id, device_id, source_system,
                   legacy_account_key, status
            FROM source_accounts ORDER BY source_account_id
            """,
        ),
        (
            "contexts",
            """
            SELECT context_id, installation_id, kind, context_key, label
            FROM contexts ORDER BY context_id
            """,
        ),
        (
            "source_files",
            """
            SELECT source_file_id, source_system, source_account, source_path,
                   source_path_hash, file_digest, file_size, conversation_id,
                   branch_id, parser_name, parser_version, status
            FROM source_files ORDER BY source_file_id
            """,
        ),
        (
            "source_streams",
            """
            SELECT source_stream_id, source_system, source_account,
                   source_path_hash, conversation_id, branch_id,
                   parent_conversation_id, source_kind, source_label,
                   scope, project_id, initial_record_ordinal,
                   initial_byte_offset, initial_prefix_digest, parser_name
            FROM source_streams ORDER BY source_stream_id
            """,
        ),
        (
            "source_segments",
            """
            SELECT source_file_id, source_stream_id, start_record_ordinal,
                   start_byte_offset, end_record_ordinal, end_byte_offset,
                   start_prefix_digest, end_prefix_digest
            FROM source_segments ORDER BY source_file_id
            """,
        ),
        (
            "source_cursors",
            """
            SELECT source_stream_id, next_record_ordinal, next_byte_offset,
                   prefix_digest, last_source_file_id
            FROM source_cursors ORDER BY source_stream_id
            """,
        ),
        (
            "source_stream_access",
            """
            SELECT source_stream_id, access, derived_from_legacy_scope
            FROM source_stream_access ORDER BY source_stream_id
            """,
        ),
        (
            "source_stream_contexts",
            """
            SELECT source_stream_id, context_id, assignment_kind
            FROM source_stream_contexts ORDER BY source_stream_id, context_id
            """,
        ),
        (
            "source_records",
            """
            SELECT source_record_id, source_file_id, object_id, record_ordinal,
                   byte_start, byte_end, message_id, parent_message_id
            FROM source_records ORDER BY source_record_id
            """,
        ),
        (
            "events_current",
            """
            SELECT event_id, source_record_id, event_type, actor_kind, assistant,
                   authority, conversation_id, branch_id, occurred_at, scope,
                   project_id, privacy, content_digest, content_text, parser_version,
                   correction_id
            FROM events_current ORDER BY event_id
            """,
        ),
        (
            "event_access",
            """
            SELECT event_id, access, derived_from_legacy_scope
            FROM event_access ORDER BY event_id
            """,
        ),
        (
            "event_contexts",
            """
            SELECT event_id, context_id, assignment_kind
            FROM event_contexts ORDER BY event_id, context_id
            """,
        ),
        (
            "quarantines",
            """
            SELECT quarantine_id, source_file_id, record_ordinal, byte_start,
                   byte_end, reason
            FROM quarantines ORDER BY quarantine_id
            """,
        ),
        (
            "memory_candidates",
            """
            SELECT memory_id, memory_type, statement_digest, authority, lifecycle,
                   scope, project_id, temporal_status, evidence_event_ids_json
            FROM memory_candidates ORDER BY memory_id
            """,
        ),
        (
            "memory_candidate_access",
            """
            SELECT memory_id, access, derived_from_legacy_scope
            FROM memory_candidate_access ORDER BY memory_id
            """,
        ),
        (
            "memory_candidate_contexts",
            """
            SELECT memory_id, context_id, assignment_kind
            FROM memory_candidate_contexts ORDER BY memory_id, context_id
            """,
        ),
    ]
    if schema_version >= 7:
        queries.extend(
            [
                (
                    "source_account_policies",
                    """
                    SELECT source_account_id, scope, project_id, created_by
                    FROM source_account_policies ORDER BY source_account_id
                    """,
                ),
                (
                    "upload_batches",
                    """
                    SELECT batch_id, request_digest, client_id, device_id,
                           source_account_id, source_file_id, conversation_id,
                           event_count, quarantined_records, quarantine_reasons_json
                    FROM upload_batches ORDER BY batch_id
                    """,
                ),
            ]
        )
    if schema_version >= 8:
        queries.append(
            (
                "source_capture_metadata",
                """
                SELECT batch_id, source_file_id, source_client, source_client_version,
                       capture_capability, adapter_name, adapter_version, parser_name,
                       parser_version, schema_fingerprint
                FROM source_capture_metadata ORDER BY batch_id
                """,
            )
        )
    if schema_version >= 9:
        queries.append(
            (
                "source_schema_authorizations",
                """
                SELECT authorization_id, source_account_id, source_system,
                       schema_fingerprint, source_client, source_client_version,
                       capture_capability, adapter_name, adapter_version,
                       parser_versions_json, status, authorized_by
                FROM source_schema_authorizations ORDER BY authorization_id
                """,
            )
        )
    if schema_version >= 10:
        queries.extend(
            [
                (
                    "web_export_batches",
                    """
                    SELECT batch_id, source_account_id, source_system, authorization_id,
                           manifest_sha256, code_revision, prepared_at, archive_sha256,
                           archive_byte_length,
                           selected_member_name_sha256, selected_member_sha256,
                           selected_member_byte_length
                    FROM web_export_batches ORDER BY batch_id
                    """,
                ),
                (
                    "web_export_archive_members",
                    """
                    SELECT archive_member_id, batch_id, archive_member_index, locator,
                           name_sha256, content_sha256, compressed_bytes, byte_length,
                           compression_method, media_type_hint
                    FROM web_export_archive_members ORDER BY archive_member_id
                    """,
                ),
                (
                    "web_export_source_objects",
                    """
                    SELECT source_object_id, batch_id, object_kind, conversation_index,
                           object_id, plaintext_sha256, byte_length, media_type,
                           conversation_id, branch_id, captured_at, parser_name,
                           parser_version, schema_fingerprint
                    FROM web_export_source_objects ORDER BY source_object_id
                    """,
                ),
                (
                    "web_export_conversation_observations",
                    """
                    SELECT observation_id, batch_id, source_file_id, source_object_id,
                           conversation_index, source_byte_start, source_byte_end,
                           conversation_sha256, source_locator
                    FROM web_export_conversation_observations ORDER BY observation_id
                    """,
                ),
                (
                    "web_export_reconciled_events",
                    """
                    SELECT reconciliation_key, event_id, family_key, source_account_id,
                           source_system, conversation_id, message_id, message_id_kind,
                           parent_message_id, branch_id, object_id, event_type, actor_kind,
                           assistant, authority, occurred_at, scope, project_id, privacy,
                           content_digest
                    FROM web_export_reconciled_events ORDER BY reconciliation_key
                    """,
                ),
                (
                    "web_export_event_observations",
                    """
                    SELECT source_record_id, event_id, reconciliation_key
                    FROM web_export_event_observations ORDER BY source_record_id
                    """,
                ),
                (
                    "event_relations",
                    """
                    SELECT relation_id, from_event_id, to_event_id, relation_type, basis
                    FROM event_relations ORDER BY relation_id
                    """,
                ),
            ]
        )
    if schema_version >= 11:
        queries.extend(
            [
                (
                    "memory_candidate_evidence_claims",
                    """
                    SELECT claim_id, memory_id, source_account_id, source_system,
                           family_key, conversation_id, message_id, message_id_kind,
                           parent_message_id, branch_id, content_digest, created_by
                    FROM memory_candidate_evidence_claims ORDER BY claim_id
                    """,
                ),
                (
                    "memory_candidate_evidence_links",
                    """
                    SELECT claim_id, event_id, reconciliation_key,
                           previous_evidence_event_ids_json, evidence_event_ids_json,
                           previous_authority, authority
                    FROM memory_candidate_evidence_links ORDER BY claim_id
                    """,
                ),
            ]
        )
    if schema_version >= 12:
        queries.extend(
            [
                (
                    "web_export_attachment_links",
                    """
                    SELECT attachment_link_id, archive_member_id, batch_id,
                           conversation_index, source_record_ordinal, reference_ordinal,
                           reference_sha256
                    FROM web_export_attachment_links ORDER BY attachment_link_id
                    """,
                ),
                (
                    "web_export_attachment_objects",
                    """
                    SELECT attachment_source_object_id, archive_member_id, batch_id,
                           object_id, plaintext_sha256, byte_length, media_type
                    FROM web_export_attachment_objects
                    ORDER BY attachment_source_object_id
                    """,
                ),
            ]
        )
    if schema_version >= 13:
        queries.append(
            (
                "deletion_tombstones",
                """
                SELECT tombstone_id, deletion_kind, source_system,
                       source_account_digest, conversation_digest, operation_id
                FROM deletion_tombstones ORDER BY tombstone_id
                """,
            )
        )
    if schema_version >= 14:
        queries.extend(
            [
                (
                    "memory_candidate_proposal_receipts",
                    """
                    SELECT proposal_sequence, proposal_id, memory_id,
                           candidate_creation_digest, proposed_by, proposer_kind,
                           authorization_scope, policy_version
                    FROM memory_candidate_proposal_receipts
                    ORDER BY proposal_sequence
                    """,
                ),
                (
                    "memory_candidate_review_transitions",
                    """
                    SELECT review_sequence, transition_id, memory_id, operation,
                           previous_lifecycle, new_lifecycle, candidate_basis_digest,
                           previous_transition_id, review_policy_version, authorized_by,
                           authorization_scope, reason_code
                    FROM memory_candidate_review_transitions
                    ORDER BY review_sequence
                    """,
                ),
            ]
        )
    if schema_version >= 17:
        queries.append(
            (
                "record_deletion_tombstones",
                """
            SELECT source_system, source_account_digest, conversation_digest,
                   match_kind, match_digest, operation_id
            FROM record_deletion_tombstones
            ORDER BY source_system, source_account_digest, conversation_digest,
                     match_kind, match_digest
            """,
            )
        )
    if schema_version >= 18:
        queries.extend(
            [
                (
                    "objects",
                    "SELECT object_id, plaintext_digest, byte_length, media_type, "
                    "object_path, storage_kind "
                    "FROM objects ORDER BY object_id",
                ),
                (
                    "encrypted_object_locations",
                    "SELECT object_id, source_object_id, storage_object_id, "
                    "backend_profile, backend_identity_sha256, manifest_json "
                    "FROM encrypted_object_locations ORDER BY object_id",
                ),
            ]
        )
    if schema_version >= 19:
        queries.append(
            (
                "encrypted_deletion_work",
                "SELECT operation_id, object_id, encrypted_purge_json FROM deletion_object_work "
                "WHERE encrypted_purge_json IS NOT NULL ORDER BY operation_id, object_id",
            )
        )
    for label, sql in queries:
        digest.update(f"table:{label}\n".encode())
        for row in connection.execute(sql):
            digest.update(_encode_digest_row(tuple(row)))
            digest.update(b"\n")
    return digest


def _publication_generation_digest(connection: sqlite3.Connection, prefix: HASH) -> str:
    digest = prefix.copy()
    digest.update(b"table:evidence_publication_work\n")
    for row in connection.execute(
        "SELECT object_id, backend_identity_sha256, root_key_sha256, retire_plaintext, "
        "plaintext_identity_sha256 FROM evidence_publication_work ORDER BY object_id"
    ):
        digest.update(_encode_digest_row(tuple(row)))
        digest.update(b"\n")
    return digest.hexdigest()


def _validate_legacy_fork_replay(
    connection: sqlite3.Connection,
    parsed: ParseResult,
    *,
    source_file_id: str,
    source_account: str,
    source_path_hash: str,
) -> None:
    legacy = connection.execute(
        """
        SELECT legacy.file_size, legacy.file_digest, legacy.conversation_id,
               legacy.branch_id, legacy.parser_version
        FROM source_files legacy
        LEFT JOIN source_segments segment
          ON segment.source_file_id = legacy.source_file_id
        WHERE legacy.source_file_id = ?
          AND legacy.source_system = ?
          AND legacy.source_account = ?
          AND legacy.source_path_hash = ?
          AND segment.source_file_id IS NULL
        """,
        (
            source_file_id,
            parsed.source_system.value,
            source_account,
            source_path_hash,
        ),
    ).fetchone()
    if legacy is None:
        raise RuntimeError("legacy fork replay source does not match the requested source stream")

    legacy_size = cast(int, legacy[0])
    legacy_digest = cast(str, legacy[1])
    legacy_conversation_id = cast(str, legacy[2])
    legacy_branch_id = cast(str | None, legacy[3])
    legacy_parser_version = cast(str, legacy[4])
    if (
        parsed.parent_conversation_id is None
        or parsed.conversation_id == parsed.parent_conversation_id
        or legacy_conversation_id != parsed.parent_conversation_id
        or legacy_branch_id not in (None, parsed.parent_conversation_id)
    ):
        raise RuntimeError("legacy fork replay identity does not replace the admitted parent")
    if parsed.segment_start_ordinal == 0 or parsed.segment_start_byte == 0:
        raise RuntimeError("legacy fork replay requires a non-zero replay boundary")
    if parsed.segment_end_byte != legacy_size or parsed.end_prefix_digest != legacy_digest:
        raise RuntimeError("legacy fork replay must end at the exact admitted file digest")
    if _semantic_version(parsed.parser_version) <= _semantic_version(legacy_parser_version):
        raise RuntimeError("legacy fork replay requires a newer parser version")

    event_counts = connection.execute(
        """
        SELECT COUNT(*),
               SUM(CASE WHEN current.privacy = 'no_memory' THEN 1 ELSE 0 END)
        FROM events_current current
        JOIN source_records record
          ON record.source_record_id = current.source_record_id
        WHERE record.source_file_id = ?
        """,
        (source_file_id,),
    ).fetchone()
    event_count = cast(int, event_counts[0])
    excluded_count = cast(int, event_counts[1] or 0)
    if event_count == 0 or excluded_count != event_count:
        raise RuntimeError(
            "legacy fork replay requires every admitted legacy event to be no_memory"
        )


def _semantic_version(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise RuntimeError("legacy fork replay requires semantic parser versions")
    return cast(tuple[int, int, int], tuple(int(part) for part in parts))


def _rebuild_events_fts(connection: sqlite3.Connection) -> None:
    connection.execute("DELETE FROM events_fts")
    connection.execute(
        """
        INSERT INTO events_fts(event_id, content_text)
        SELECT event_id, content_text
        FROM events_current
        WHERE privacy = 'included'
        ORDER BY event_id
        """
    )


def _replace_events_fts(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TABLE events_fts")
    connection.execute(
        """
        CREATE VIRTUAL TABLE events_fts USING fts5(
          event_id UNINDEXED,
          content_text,
          tokenize = 'unicode61 remove_diacritics 2'
        )
        """
    )
    connection.execute(
        """
        INSERT INTO events_fts(event_id, content_text)
        SELECT event_id, content_text
        FROM events_current
        WHERE privacy = 'included'
        ORDER BY event_id
        """
    )


def _build_deletion_selector(
    connection: sqlite3.Connection,
    *,
    kind: DeletionKind,
    source_system: SourceSystem,
    source_account: str,
    conversation_id: str | None,
    retirement_pairs: Sequence[ObservationRetirement] = (),
) -> _DeletionSelector:
    rows = connection.execute(
        """
        SELECT source_account_id, legacy_account_key, installation_id, device_id
        FROM source_accounts
        WHERE source_system = ?
        ORDER BY source_account_id
        """,
        (source_system.value,),
    ).fetchall()
    exact = [row for row in rows if cast(str, row[0]) == source_account]
    labelled = [row for row in rows if cast(str, row[1]) == source_account]
    if exact:
        selected = exact
    elif len(labelled) == 1:
        selected = labelled
    elif labelled:
        raise ValueError("source account label is ambiguous; use the exact source account id")
    else:
        raise KeyError("source account not found")
    aliases = {cast(str, row[0]) for row in selected}
    for row in selected:
        # Only pre-enrollment local imports use a label as their persisted identity.
        if cast(str, row[3]) == _stable_id("device", cast(str, row[2]), "legacy-local"):
            aliases.add(cast(str, row[1]))
    return _validated_deletion_selector(
        kind=kind,
        source_system=source_system,
        source_account_digests=tuple(sorted(_sha256_text(value) for value in aliases)),
        conversation_digest=(
            _sha256_text(conversation_id) if conversation_id is not None else None
        ),
        retirement_pairs=retirement_pairs,
    )


def _validated_deletion_selector(
    *,
    kind: DeletionKind,
    source_system: SourceSystem,
    source_account_digests: Sequence[str],
    conversation_digest: str | None,
    retirement_pairs: Sequence[ObservationRetirement] = (),
) -> _DeletionSelector:
    digests = tuple(sorted(set(source_account_digests)))
    if not digests or len(digests) != len(source_account_digests):
        raise ValueError("deletion source-account digests must be non-empty and unique")
    for digest in digests:
        _validate_sha256(digest, "deletion source account")
    if kind is DeletionKind.WEB_CONTAINERS and source_system not in {
        SourceSystem.CHATGPT_WEB,
        SourceSystem.CLAUDE_WEB,
        SourceSystem.GROK_WEB,
    }:
        raise ValueError("web-container retirement requires a web source system")
    pairs = tuple(sorted(retirement_pairs))
    if kind is DeletionKind.OBSOLETE_OBSERVATIONS:
        if source_system not in {
            SourceSystem.CODEX,
            SourceSystem.CLAUDE_CODE,
            SourceSystem.GROK_BUILD,
        }:
            raise ValueError("observation retirement requires a native source")
        if conversation_digest is None:
            raise ValueError("observation retirement requires a conversation")
        _validate_sha256(conversation_digest, "retirement conversation")
        if not pairs or len(pairs) > MAX_PROPOSAL_EVIDENCE_EVENTS:
            raise ValueError("observation retirement requires bounded nonempty replacement pairs")
        for pair in pairs:
            _bounded_identity_value(pair.event_id, "obsolete event")
            _bounded_identity_value(pair.replacement_event_id, "replacement event")
        obsolete = {pair.event_id for pair in pairs}
        replacements = {pair.replacement_event_id for pair in pairs}
        if len(obsolete) != len(pairs) or obsolete & replacements:
            raise ValueError("retirement pairs contain duplicate or overlapping event identities")
    elif pairs:
        raise ValueError("replacement pairs require observation retirement")
    elif kind is DeletionKind.NO_MEMORY_RECORDS:
        if conversation_digest is not None:
            _validate_sha256(conversation_digest, "deletion conversation")
    elif kind is DeletionKind.CONVERSATION:
        if conversation_digest is None:
            raise ValueError("conversation deletion requires a conversation digest")
        _validate_sha256(conversation_digest, "deletion conversation")
    elif conversation_digest is not None:
        raise ValueError("source-account deletion cannot include a conversation digest")
    return _DeletionSelector(
        kind=kind,
        source_system=source_system,
        source_account_digests=digests,
        conversation_digest=conversation_digest,
        retirement_pairs=pairs,
    )


def _matching_source_accounts(
    connection: sqlite3.Connection,
    selector: _DeletionSelector,
) -> tuple[set[str], set[str]]:
    account_ids: set[str] = set()
    aliases: set[str] = set()
    for row in connection.execute(
        """
        SELECT source_account_id, legacy_account_key, installation_id, device_id
        FROM source_accounts
        WHERE source_system = ?
        """,
        (selector.source_system.value,),
    ):
        source_account_id = cast(str, row[0])
        legacy_account_key = cast(str, row[1])
        row_aliases = {source_account_id}
        if cast(str, row[3]) == _stable_id("device", cast(str, row[2]), "legacy-local"):
            row_aliases.add(legacy_account_key)
        if any(_sha256_text(value) in selector.source_account_digests for value in row_aliases):
            account_ids.add(source_account_id)
            aliases.update(row_aliases)
    return account_ids, aliases


def _record_erasure_keys(
    *,
    source_system: SourceSystem,
    conversation_id: str,
    raw_digest: str | None,
    message_id: str | None,
    message_id_kind: str | None,
) -> set[tuple[str, str, str]]:
    conversation_digest = _sha256_text(conversation_id)
    keys: set[tuple[str, str, str]] = set()
    if raw_digest is not None:
        keys.add((conversation_digest, "raw_record", raw_digest))
    # Native Codex sometimes puts a turn ID in message_id. That is not a record identity.
    if message_id and (
        message_id_kind == "provider_message_id" or source_system is SourceSystem.CLAUDE_CODE
    ):
        keys.add((conversation_digest, "provider_message_id", _sha256_text(message_id)))
    return keys


def _record_is_erased(
    connection: sqlite3.Connection,
    *,
    source_system: SourceSystem,
    source_account: str,
    conversation_id: str,
    raw_digest: str | None,
    message_id: str | None,
    message_id_kind: str | None,
) -> bool:
    keys = _record_erasure_keys(
        source_system=source_system,
        conversation_id=conversation_id,
        raw_digest=raw_digest,
        message_id=message_id,
        message_id_kind=message_id_kind,
    )
    return any(
        connection.execute(
            """
            SELECT 1 FROM record_deletion_tombstones
            WHERE source_system = ? AND source_account_digest = ? AND conversation_digest = ?
              AND match_kind = ? AND match_digest = ?
            """,
            (source_system.value, account_digest, *key),
        ).fetchone()
        is not None
        for account_digest in _ingest_account_digests(connection, source_system, source_account)
        for key in keys
    )


def _collect_no_memory_target(
    connection: sqlite3.Connection,
    selector: _DeletionSelector,
) -> _DeletionTarget:
    rows = connection.execute(
        """
        SELECT e.event_id, r.source_record_id, r.object_id, f.source_account,
               f.conversation_id, r.message_id, w.message_id_kind, e.privacy, w.family_key
        FROM events_current e
        JOIN source_records r ON r.source_record_id = e.source_record_id
        JOIN source_files f ON f.source_file_id = r.source_file_id
        LEFT JOIN web_export_reconciled_events w ON w.event_id = e.event_id
        WHERE f.source_system = ?
        """,
        (selector.source_system.value,),
    ).fetchall()
    rows = [
        row
        for row in rows
        if _sha256_text(cast(str, row[3])) in selector.source_account_digests
        and (
            selector.conversation_digest is None
            or _sha256_text(cast(str, row[4])) == selector.conversation_digest
        )
    ]
    retirement = selector.kind is DeletionKind.OBSOLETE_OBSERVATIONS
    keys_by_event = {
        cast(str, row[0]): _record_erasure_keys(
            source_system=selector.source_system,
            conversation_id=cast(str, row[4]),
            raw_digest=cast(str, row[2]).removeprefix("sha256:"),
            message_id=cast(str | None, row[5]),
            message_id_kind=cast(str | None, row[6]),
        )
        for row in rows
    }
    event_ids = {cast(str, row[0]) for row in rows if row[7] == Privacy.NO_MEMORY.value}
    if retirement:
        selected = {pair.event_id for pair in selector.retirement_pairs}
        if not selected <= event_ids:
            raise RuntimeError(
                "retirement targets must be excluded observations in the exact scope"
            )
        event_ids = selected
        _require_observation_replacements(connection, selector)
    keys: set[tuple[str, str, str]] = set()
    for event_id in () if retirement else event_ids:
        keys.update(keys_by_event[event_id])
    # Include all retained observations/variants of the same erased record, not its neighbors.
    while not retirement:
        expanded = {event_id for event_id, values in keys_by_event.items() if values & keys}
        if expanded == event_ids:
            break
        event_ids = expanded
        keys.update(*(keys_by_event[event_id] for event_id in event_ids))
    if not event_ids:
        return _empty_deletion_target()
    record_ids = {cast(str, row[1]) for row in rows if row[0] in event_ids}
    record_ids.update(
        cast(str, row[0])
        for row in _rows_matching_ids(
            connection,
            "SELECT source_record_id FROM web_export_event_observations "
            "WHERE event_id IN ({placeholders})",
            event_ids,
        )
    )
    record_rows = _rows_matching_ids(
        connection,
        """
        SELECT r.source_record_id, r.object_id, f.source_account, f.conversation_id, r.message_id,
               f.source_file_id
        FROM source_records r JOIN source_files f ON f.source_file_id = r.source_file_id
        WHERE r.source_record_id IN ({placeholders})
        """,
        record_ids,
    )
    object_ids = {cast(str, row[1]) for row in record_rows}
    for row in record_rows:
        if _sha256_text(cast(str, row[2])) not in selector.source_account_digests:
            raise RuntimeError("record erasure crosses a retained source account")
        if not retirement:
            keys.add(
                (
                    _sha256_text(cast(str, row[3])),
                    "raw_record",
                    cast(str, row[1]).removeprefix("sha256:"),
                )
            )
    file_ids = {cast(str, row[5]) for row in record_rows}
    batch_ids = {
        cast(str, row[0])
        for row in _rows_matching_ids(
            connection,
            """
        SELECT batch_id FROM web_export_conversation_observations
        WHERE source_file_id IN ({placeholders})
        """,
            file_ids,
        )
    }
    if _rows_matching_ids(
        connection,
        """
        SELECT source_object_id FROM web_export_source_objects
        WHERE batch_id IN ({placeholders}) AND object_id IS NOT NULL
        """,
        batch_ids,
    ):
        raise RuntimeError("record erasure requires explicit legacy web-container retirement first")

    family_keys = {cast(str, row[8]) for row in rows if row[0] in event_ids and row[8] is not None}
    claim_rows = connection.execute(
        "SELECT claim_id, memory_id, family_key FROM memory_candidate_evidence_claims"
    ).fetchall()
    claim_ids = {cast(str, row[0]) for row in claim_rows if row[2] in family_keys}
    claim_ids.update(
        cast(str, row[0])
        for row in _rows_matching_ids(
            connection,
            """
        SELECT claim_id FROM memory_candidate_evidence_links WHERE event_id IN ({placeholders})
        """,
            event_ids,
        )
    )
    memory_ids = {cast(str, row[1]) for row in claim_rows if row[0] in claim_ids}
    for row in connection.execute(
        "SELECT memory_id, evidence_event_ids_json FROM memory_candidates"
    ):
        evidence: object = json.loads(cast(str, row[1]))
        if not isinstance(evidence, list) or not all(
            isinstance(item, str) for item in cast(list[object], evidence)
        ):
            raise RuntimeError("memory candidate evidence ids are invalid")
        if event_ids.intersection(cast(list[str], evidence)):
            memory_ids.add(cast(str, row[0]))
    claim_ids.update(cast(str, row[0]) for row in claim_rows if row[1] in memory_ids)
    links = _rows_matching_ids(
        connection,
        """
        SELECT link.attachment_link_id, link.archive_member_id
        FROM web_export_attachment_links link
        JOIN web_export_conversation_observations obs
          ON obs.batch_id = link.batch_id AND obs.conversation_index = link.conversation_index
        JOIN source_records r ON r.source_file_id = obs.source_file_id
          AND r.record_ordinal = link.source_record_ordinal
        WHERE r.source_record_id IN ({placeholders})
        """,
        record_ids,
    )
    link_ids = {cast(str, row[0]) for row in links}
    member_ids = {cast(str, row[1]) for row in links}
    attachment_rows = _rows_matching_ids(
        connection,
        """
        SELECT attachment_source_object_id, archive_member_id, object_id
        FROM web_export_attachment_objects WHERE archive_member_id IN ({placeholders})
        """,
        member_ids,
    )
    retained_attachment_links = _rows_matching_ids(
        connection,
        """
        SELECT attachment_link_id FROM web_export_attachment_links
        WHERE archive_member_id IN ({placeholders})
        """,
        {cast(str, row[1]) for row in attachment_rows},
    )
    if any(row[0] not in link_ids for row in retained_attachment_links):
        raise RuntimeError(
            "record erasure has shared attachment evidence; explicit remediation required"
        )
    object_ids.update(cast(str, row[2]) for row in attachment_rows)
    object_ids.update(
        cast(str, row[0])
        for row in _rows_matching_ids(
            connection,
            """
        SELECT object_id FROM web_export_reconciled_events WHERE event_id IN ({placeholders})
        """,
            event_ids,
        )
    )
    target = replace(
        _empty_deletion_target(),
        source_record_ids=frozenset(record_ids),
        event_ids=frozenset(event_ids),
        memory_ids=frozenset(memory_ids),
        memory_claim_ids=frozenset(claim_ids),
        touched_web_batch_ids=frozenset(batch_ids),
        web_attachment_link_ids=frozenset(link_ids),
        web_attachment_object_ids=frozenset(cast(str, row[0]) for row in attachment_rows),
        object_candidate_ids=frozenset(object_ids),
        record_tombstones=frozenset(keys),
        observation_retirement_ids=frozenset(record_ids) if retirement else frozenset(),
        retained_replacement_event_ids=frozenset(
            pair.replacement_event_id for pair in selector.retirement_pairs
        ),
    )
    deletable = frozenset(_deletable_object_ids(connection, target))
    if retirement:
        if deletable or link_ids or attachment_rows or batch_ids:
            raise RuntimeError("observation retirement must preserve all objects and attachments")
    elif deletable != target.object_candidate_ids:
        raise RuntimeError(
            "record erasure has shared object evidence; explicit remediation required"
        )
    return replace(target, deletable_object_ids=deletable)


def _require_observation_replacements(
    connection: sqlite3.Connection, selector: _DeletionSelector
) -> None:
    for pair in selector.retirement_pairs:
        row = connection.execute(
            """
            SELECT old.privacy, replacement.privacy, oldr.object_id, newr.object_id,
                   oldf.source_system, newf.source_system, oldf.source_account, newf.source_account,
                   oldf.conversation_id, newf.conversation_id,
                   original.actor_kind, replacement.actor_kind,
                   original.assistant, replacement.assistant
            FROM events_current old
            JOIN events original ON original.event_id = old.event_id
            JOIN source_records oldr ON oldr.source_record_id = old.source_record_id
            JOIN source_files oldf ON oldf.source_file_id = oldr.source_file_id
            JOIN events_current replacement ON replacement.event_id = ?
            JOIN source_records newr ON newr.source_record_id = replacement.source_record_id
            JOIN source_files newf ON newf.source_file_id = newr.source_file_id
            WHERE old.event_id = ?
            """,
            (pair.replacement_event_id, pair.event_id),
        ).fetchone()
        if row is None or not (
            row[0] == Privacy.NO_MEMORY.value
            and row[1] == Privacy.INCLUDED.value
            and row[2] == row[3]
            and row[4] == row[5] == selector.source_system.value
            and row[6] == row[7]
            and _sha256_text(cast(str, row[6])) in selector.source_account_digests
            and _sha256_text(cast(str, row[8])) == selector.conversation_digest
            and row[8] != row[9]
            and row[10] == row[11]
            and row[12] == row[13]
        ):
            raise RuntimeError(
                "observation retirement requires an included same-account replacement "
                "with matching evidence and speaker"
            )


def _collect_deletion_target(
    connection: sqlite3.Connection,
    selector: _DeletionSelector,
) -> _DeletionTarget:
    matched_account_ids, _aliases = _matching_source_accounts(connection, selector)
    if not matched_account_ids:
        return _empty_deletion_target()
    if selector.kind in {DeletionKind.NO_MEMORY_RECORDS, DeletionKind.OBSOLETE_OBSERVATIONS}:
        return _collect_no_memory_target(connection, selector)
    if selector.kind is DeletionKind.WEB_CONTAINERS:
        rows = _rows_matching_ids(
            connection,
            """
            SELECT source.source_object_id, source.object_id, source.batch_id
            FROM web_export_source_objects source
            JOIN web_export_batches batch ON batch.batch_id = source.batch_id
            WHERE batch.source_account_id IN ({placeholders}) AND source.object_id IS NOT NULL
            """,
            matched_account_ids,
        )
        target = replace(
            _empty_deletion_target(),
            web_container_retirement_ids=frozenset(cast(str, row[0]) for row in rows),
            object_candidate_ids=frozenset(cast(str, row[1]) for row in rows),
            touched_web_batch_ids=frozenset(cast(str, row[2]) for row in rows),
        )
        for table in (
            "source_records",
            "web_export_attachment_objects",
            "web_export_reconciled_events",
        ):
            if _rows_matching_ids(
                connection,
                f"SELECT object_id FROM {table} WHERE object_id IN ({{placeholders}})",
                target.object_candidate_ids,
            ):
                raise RuntimeError(
                    "web containers have retained non-container references; explicit "
                    "record or attachment remediation is required before retirement"
                )
        return replace(
            target, deletable_object_ids=frozenset(_deletable_object_ids(connection, target))
        )

    source_file_ids: set[str] = set()
    for row in connection.execute(
        """
        SELECT source_file_id, source_account, conversation_id
        FROM source_files
        WHERE source_system = ?
        """,
        (selector.source_system.value,),
    ):
        if not _deletion_row_matches(
            selector,
            source_account=cast(str, row[1]),
            conversation_id=cast(str, row[2]),
        ):
            continue
        source_file_ids.add(cast(str, row[0]))

    source_stream_ids: set[str] = set()
    for row in connection.execute(
        """
        SELECT source_stream_id, source_account, conversation_id
        FROM source_streams
        WHERE source_system = ?
        """,
        (selector.source_system.value,),
    ):
        if _deletion_row_matches(
            selector,
            source_account=cast(str, row[1]),
            conversation_id=cast(str, row[2]),
        ):
            source_stream_ids.add(cast(str, row[0]))

    source_record_ids: set[str] = set()
    record_object_ids: set[str] = set()
    for row in _rows_matching_ids(
        connection,
        """
        SELECT source_record_id, object_id
        FROM source_records
        WHERE source_file_id IN ({placeholders})
        """,
        source_file_ids,
    ):
        source_record_ids.add(cast(str, row[0]))
        record_object_ids.add(cast(str, row[1]))

    event_ids: set[str] = {
        cast(str, row[0])
        for row in _rows_matching_ids(
            connection,
            """
            SELECT event_id
            FROM events
            WHERE source_record_id IN ({placeholders})
            """,
            source_record_ids,
        )
    }
    observed_event_ids = {
        cast(str, row[0])
        for row in _rows_matching_ids(
            connection,
            """
            SELECT event_id
            FROM web_export_event_observations
            WHERE source_record_id IN ({placeholders})
            """,
            source_record_ids,
        )
    }
    event_ids.update(observed_event_ids)
    observed_records_for_events = {
        cast(str, row[0])
        for row in _rows_matching_ids(
            connection,
            """
            SELECT source_record_id
            FROM web_export_event_observations
            WHERE event_id IN ({placeholders})
            """,
            event_ids,
        )
    }
    if not observed_records_for_events.issubset(source_record_ids):
        raise RuntimeError("deletion target crosses a retained source observation")

    memory_claim_ids: set[str] = set()
    memory_ids: set[str] = set()
    claim_to_memory: dict[str, str] = {}
    for row in connection.execute(
        """
        SELECT claim_id, memory_id, source_account_id, conversation_id
        FROM memory_candidate_evidence_claims
        WHERE source_system = ?
        """,
        (selector.source_system.value,),
    ):
        claim_id = cast(str, row[0])
        memory_id = cast(str, row[1])
        claim_to_memory[claim_id] = memory_id
        if cast(str, row[2]) not in matched_account_ids:
            continue
        if (
            selector.kind is DeletionKind.CONVERSATION
            and _sha256_text(cast(str, row[3])) != selector.conversation_digest
        ):
            continue
        memory_claim_ids.add(claim_id)
        memory_ids.add(memory_id)
    for row in connection.execute("SELECT claim_id, event_id FROM memory_candidate_evidence_links"):
        if cast(str, row[1]) in event_ids:
            claim_id = cast(str, row[0])
            memory_claim_ids.add(claim_id)
            if claim_id in claim_to_memory:
                memory_ids.add(claim_to_memory[claim_id])
    for row in connection.execute(
        "SELECT memory_id, evidence_event_ids_json FROM memory_candidates"
    ):
        evidence_value: object = json.loads(cast(str, row[1]))
        if not isinstance(evidence_value, list):
            raise RuntimeError("memory candidate evidence ids are invalid")
        evidence_ids = cast(list[object], evidence_value)
        if not all(isinstance(item, str) for item in evidence_ids):
            raise RuntimeError("memory candidate evidence ids are invalid")
        if event_ids.intersection(cast(list[str], evidence_ids)):
            memory_ids.add(cast(str, row[0]))
    for claim_id, memory_id in claim_to_memory.items():
        if memory_id in memory_ids:
            memory_claim_ids.add(claim_id)

    upload_batch_ids = {
        cast(str, row[0])
        for row in connection.execute(
            "SELECT batch_id, source_account_id, source_file_id FROM upload_batches"
        )
        if cast(str, row[2]) in source_file_ids
        or (
            selector.kind is DeletionKind.SOURCE_ACCOUNT
            and cast(str, row[1]) in matched_account_ids
        )
    }

    observation_rows = connection.execute(
        """
        SELECT observation_id, batch_id, source_file_id, source_object_id,
               conversation_index
        FROM web_export_conversation_observations
        """
    ).fetchall()
    web_observation_ids = {
        cast(str, row[0]) for row in observation_rows if cast(str, row[2]) in source_file_ids
    }
    touched_web_batch_ids = {
        cast(str, row[1]) for row in observation_rows if cast(str, row[0]) in web_observation_ids
    }
    if selector.kind is DeletionKind.SOURCE_ACCOUNT:
        touched_web_batch_ids.update(
            cast(str, row[0])
            for row in connection.execute(
                "SELECT batch_id, source_account_id FROM web_export_batches"
            )
            if cast(str, row[1]) in matched_account_ids
        )
        web_observation_ids.update(
            cast(str, row[0])
            for row in observation_rows
            if cast(str, row[1]) in touched_web_batch_ids
        )
    selected_conversation_indexes: dict[str, set[int]] = {}
    selected_split_object_ids: set[str] = set()
    for row in observation_rows:
        if cast(str, row[0]) not in web_observation_ids:
            continue
        batch_id = cast(str, row[1])
        selected_split_object_ids.add(cast(str, row[3]))
        selected_conversation_indexes.setdefault(batch_id, set()).add(cast(int, row[4]))

    deleted_web_batch_ids: set[str] = set()
    for batch_id in touched_web_batch_ids:
        batch_observations = {
            cast(str, row[0]) for row in observation_rows if cast(str, row[1]) == batch_id
        }
        if batch_observations.issubset(web_observation_ids):
            deleted_web_batch_ids.add(batch_id)

    web_source_object_ids: set[str] = set()
    web_source_object_object_ids: set[str] = set()
    for row in connection.execute(
        """
        SELECT source_object_id, batch_id, object_kind, object_id
        FROM web_export_source_objects
        """
    ):
        source_object_id = cast(str, row[0])
        batch_id = cast(str, row[1])
        if batch_id not in touched_web_batch_ids:
            continue
        if (
            batch_id in deleted_web_batch_ids
            or cast(str, row[2]) != "conversation_split"
            or source_object_id in selected_split_object_ids
        ):
            web_source_object_ids.add(source_object_id)
            if row[3] is not None:
                web_source_object_object_ids.add(cast(str, row[3]))

    attachment_rows = connection.execute(
        """
        SELECT attachment_link_id, archive_member_id, batch_id, conversation_index
        FROM web_export_attachment_links
        """
    ).fetchall()
    web_attachment_link_ids: set[str] = set()
    for row in attachment_rows:
        batch_id = cast(str, row[2])
        if batch_id not in touched_web_batch_ids:
            continue
        if batch_id in deleted_web_batch_ids or cast(int, row[3]) in (
            selected_conversation_indexes.get(batch_id, set())
        ):
            web_attachment_link_ids.add(cast(str, row[0]))

    web_attachment_object_ids: set[str] = set()
    attachment_object_object_ids: set[str] = set()
    partial_attachment_member_ids: set[str] = set()
    for row in connection.execute(
        """
        SELECT attachment_source_object_id, archive_member_id, batch_id, object_id
        FROM web_export_attachment_objects
        """
    ):
        attachment_object_id = cast(str, row[0])
        archive_member_id = cast(str, row[1])
        batch_id = cast(str, row[2])
        if batch_id not in touched_web_batch_ids:
            continue
        member_links = {
            cast(str, link[0])
            for link in attachment_rows
            if cast(str, link[1]) == archive_member_id
        }
        if batch_id in deleted_web_batch_ids or member_links.issubset(web_attachment_link_ids):
            web_attachment_object_ids.add(attachment_object_id)
            attachment_object_object_ids.add(cast(str, row[3]))
            partial_attachment_member_ids.add(archive_member_id)

    web_archive_member_ids = {
        cast(str, row[0])
        for row in connection.execute(
            "SELECT archive_member_id, batch_id FROM web_export_archive_members"
        )
        if cast(str, row[1]) in deleted_web_batch_ids
        or cast(str, row[0]) in partial_attachment_member_ids
    }

    reconciled_object_ids = {
        cast(str, row[1])
        for row in _rows_matching_ids(
            connection,
            """
            SELECT event_id, object_id
            FROM web_export_reconciled_events
            WHERE event_id IN ({placeholders})
            """,
            event_ids,
        )
    }
    object_candidate_ids = (
        record_object_ids
        | web_source_object_object_ids
        | attachment_object_object_ids
        | reconciled_object_ids
    )

    provisional = _DeletionTarget(
        source_account_ids=frozenset(
            matched_account_ids if selector.kind is DeletionKind.SOURCE_ACCOUNT else set()
        ),
        source_stream_ids=frozenset(source_stream_ids),
        source_file_ids=frozenset(source_file_ids),
        source_record_ids=frozenset(source_record_ids),
        event_ids=frozenset(event_ids),
        memory_ids=frozenset(memory_ids),
        memory_claim_ids=frozenset(memory_claim_ids),
        upload_batch_ids=frozenset(upload_batch_ids),
        touched_web_batch_ids=frozenset(touched_web_batch_ids),
        deleted_web_batch_ids=frozenset(deleted_web_batch_ids),
        web_observation_ids=frozenset(web_observation_ids),
        web_source_object_ids=frozenset(web_source_object_ids),
        web_attachment_link_ids=frozenset(web_attachment_link_ids),
        web_attachment_object_ids=frozenset(web_attachment_object_ids),
        web_archive_member_ids=frozenset(web_archive_member_ids),
        object_candidate_ids=frozenset(object_candidate_ids),
        deletable_object_ids=frozenset(),
    )
    deletable_object_ids = _deletable_object_ids(connection, provisional)
    return replace(provisional, deletable_object_ids=frozenset(deletable_object_ids))


def _empty_deletion_target() -> _DeletionTarget:
    empty: frozenset[str] = frozenset()
    return _DeletionTarget(
        source_account_ids=empty,
        source_stream_ids=empty,
        source_file_ids=empty,
        source_record_ids=empty,
        event_ids=empty,
        memory_ids=empty,
        memory_claim_ids=empty,
        upload_batch_ids=empty,
        touched_web_batch_ids=empty,
        deleted_web_batch_ids=empty,
        web_observation_ids=empty,
        web_source_object_ids=empty,
        web_attachment_link_ids=empty,
        web_attachment_object_ids=empty,
        web_archive_member_ids=empty,
        object_candidate_ids=empty,
        deletable_object_ids=empty,
    )


def _deletion_row_matches(
    selector: _DeletionSelector,
    *,
    source_account: str,
    conversation_id: str,
) -> bool:
    if _sha256_text(source_account) not in selector.source_account_digests:
        return False
    return (
        selector.kind is DeletionKind.SOURCE_ACCOUNT
        or _sha256_text(conversation_id) == selector.conversation_digest
    )


def _rows_matching_ids(
    connection: sqlite3.Connection,
    sql: str,
    values: Iterable[str],
) -> list[sqlite3.Row]:
    ordered = sorted(set(values))
    rows: list[sqlite3.Row] = []
    for offset in range(0, len(ordered), 500):
        batch = ordered[offset : offset + 500]
        placeholders = ",".join("?" for _ in batch)
        rows.extend(connection.execute(sql.format(placeholders=placeholders), batch).fetchall())
    return rows


def _deletable_object_ids(
    connection: sqlite3.Connection,
    target: _DeletionTarget,
) -> set[str]:
    candidates = set(target.object_candidate_ids)
    retained: set[str] = set()
    for row in _rows_matching_ids(
        connection,
        """
        SELECT source_record_id, object_id
        FROM source_records
        WHERE object_id IN ({placeholders})
        """,
        candidates,
    ):
        if cast(str, row[0]) not in target.source_record_ids:
            retained.add(cast(str, row[1]))
    for row in _rows_matching_ids(
        connection,
        """
        SELECT source_object_id, object_id
        FROM web_export_source_objects
        WHERE object_id IN ({placeholders})
        """,
        candidates,
    ):
        if cast(str, row[0]) not in (
            target.web_source_object_ids | target.web_container_retirement_ids
        ):
            retained.add(cast(str, row[1]))
    for row in _rows_matching_ids(
        connection,
        """
        SELECT attachment_source_object_id, object_id
        FROM web_export_attachment_objects
        WHERE object_id IN ({placeholders})
        """,
        candidates,
    ):
        if cast(str, row[0]) not in target.web_attachment_object_ids:
            retained.add(cast(str, row[1]))
    for row in _rows_matching_ids(
        connection,
        """
        SELECT event_id, object_id
        FROM web_export_reconciled_events
        WHERE object_id IN ({placeholders})
        """,
        candidates,
    ):
        if cast(str, row[0]) not in target.event_ids:
            retained.add(cast(str, row[1]))
    return candidates - retained


def _deletion_object_rows(
    connection: sqlite3.Connection,
    object_ids: Iterable[str],
) -> dict[str, tuple[str, int]]:
    return {
        cast(str, row[0]): (cast(str, row[1]), cast(int, row[2]))
        for row in _rows_matching_ids(
            connection,
            """
            SELECT object_id, object_path, byte_length
            FROM objects
            WHERE object_id IN ({placeholders})
            """,
            object_ids,
        )
    }


def _require_object_not_pending_deletion(connection: sqlite3.Connection, object_id: str) -> None:
    if (
        connection.execute(
            "SELECT 1 FROM deletion_object_work WHERE object_id = ? AND status = 'pending' LIMIT 1",
            (object_id,),
        ).fetchone()
        is not None
    ):
        raise RuntimeError("object has a pending deletion; resume that operation before import")


def _unreferenced_deletion_objects(
    connection: sqlite3.Connection,
    object_ids: Iterable[str],
) -> set[str]:
    candidates = set(object_ids)
    referenced: set[str] = set()
    for table in (
        "source_records",
        "web_export_source_objects",
        "web_export_attachment_objects",
        "web_export_reconciled_events",
    ):
        referenced.update(
            cast(str, row[0])
            for row in _rows_matching_ids(
                connection,
                f"SELECT object_id FROM {table} WHERE object_id IN ({{placeholders}})",
                candidates,
            )
        )
    return candidates - referenced


_DELETION_TEMP_NAMES = frozenset(
    {
        "account_ids",
        "stream_ids",
        "file_ids",
        "record_ids",
        "event_ids",
        "memory_ids",
        "claim_ids",
        "upload_batch_ids",
        "web_batch_ids",
        "web_observation_ids",
        "web_source_object_ids",
        "web_container_retirement_ids",
        "attachment_link_ids",
        "attachment_object_ids",
        "archive_member_ids",
        "object_ids",
        "context_ids",
    }
)


def _install_deletion_ids(
    connection: sqlite3.Connection,
    name: str,
    values: Iterable[str],
) -> None:
    if name not in _DELETION_TEMP_NAMES:
        raise ValueError("invalid deletion temporary table")
    table = f"cam_delete_{name}"
    connection.execute(f"DROP TABLE IF EXISTS temp.{table}")
    connection.execute(f"CREATE TEMP TABLE {table}(value TEXT PRIMARY KEY) WITHOUT ROWID")
    connection.executemany(
        f"INSERT INTO temp.{table}(value) VALUES (?)",
        [(value,) for value in sorted(set(values))],
    )


def _delete_target_rows(connection: sqlite3.Connection, target: _DeletionTarget) -> None:
    values = {
        "account_ids": target.source_account_ids,
        "stream_ids": target.source_stream_ids,
        "file_ids": target.source_file_ids,
        "record_ids": target.source_record_ids,
        "event_ids": target.event_ids,
        "memory_ids": target.memory_ids,
        "claim_ids": target.memory_claim_ids,
        "upload_batch_ids": target.upload_batch_ids,
        "web_batch_ids": target.deleted_web_batch_ids,
        "web_observation_ids": target.web_observation_ids,
        "web_source_object_ids": target.web_source_object_ids,
        "web_container_retirement_ids": target.web_container_retirement_ids,
        "attachment_link_ids": target.web_attachment_link_ids,
        "attachment_object_ids": target.web_attachment_object_ids,
        "archive_member_ids": target.web_archive_member_ids,
    }
    for name, identifiers in values.items():
        _install_deletion_ids(connection, name, identifiers)

    affected_contexts: set[str] = set()
    for table, identity, ids in (
        ("event_contexts", "event_id", target.event_ids),
        ("memory_candidate_contexts", "memory_id", target.memory_ids),
        ("source_stream_contexts", "source_stream_id", target.source_stream_ids),
    ):
        affected_contexts.update(
            cast(str, row[0])
            for row in _rows_matching_ids(
                connection,
                f"SELECT context_id FROM {table} WHERE {identity} IN ({{placeholders}})",
                ids,
            )
        )
    _install_deletion_ids(connection, "context_ids", affected_contexts)

    if target.record_tombstones or target.observation_retirement_ids:
        connection.execute(
            """
            INSERT OR IGNORE INTO quarantines(
              quarantine_id, source_file_id, record_ordinal, byte_start, byte_end,
              reason, created_at
            )
            SELECT ? || source_record_id, source_file_id, record_ordinal,
                   byte_start, byte_end, ?, ?
            FROM source_records
            WHERE source_record_id IN (SELECT value FROM temp.cam_delete_record_ids)
            """,
            (
                "observation-retirement:"
                if target.observation_retirement_ids
                else "record-erasure:",
                "obsolete_observation"
                if target.observation_retirement_ids
                else "no_memory_tombstone",
                _now(),
            ),
        )

    statements = (
        """
        UPDATE web_export_source_objects SET object_id = NULL
        WHERE source_object_id IN (SELECT value FROM temp.cam_delete_web_container_retirement_ids)
        """,
        """
        DELETE FROM memory_candidate_evidence_links
        WHERE claim_id IN (SELECT value FROM temp.cam_delete_claim_ids)
           OR event_id IN (SELECT value FROM temp.cam_delete_event_ids)
        """,
        """
        DELETE FROM memory_candidate_evidence_claims
        WHERE claim_id IN (SELECT value FROM temp.cam_delete_claim_ids)
        """,
        """
        DELETE FROM memory_candidate_contexts
        WHERE memory_id IN (SELECT value FROM temp.cam_delete_memory_ids)
        """,
        """
        DELETE FROM memory_candidate_access
        WHERE memory_id IN (SELECT value FROM temp.cam_delete_memory_ids)
        """,
        """
        DELETE FROM memory_candidates
        WHERE memory_id IN (SELECT value FROM temp.cam_delete_memory_ids)
        """,
        """
        DELETE FROM event_relations
        WHERE from_event_id IN (SELECT value FROM temp.cam_delete_event_ids)
           OR to_event_id IN (SELECT value FROM temp.cam_delete_event_ids)
        """,
        """
        DELETE FROM web_export_event_observations
        WHERE source_record_id IN (SELECT value FROM temp.cam_delete_record_ids)
           OR event_id IN (SELECT value FROM temp.cam_delete_event_ids)
        """,
        """
        DELETE FROM web_export_reconciled_events
        WHERE event_id IN (SELECT value FROM temp.cam_delete_event_ids)
        """,
        """
        DELETE FROM event_corrections
        WHERE event_id IN (SELECT value FROM temp.cam_delete_event_ids)
        """,
        """
        DELETE FROM event_contexts
        WHERE event_id IN (SELECT value FROM temp.cam_delete_event_ids)
        """,
        """
        DELETE FROM event_access
        WHERE event_id IN (SELECT value FROM temp.cam_delete_event_ids)
        """,
        "DELETE FROM events WHERE event_id IN (SELECT value FROM temp.cam_delete_event_ids)",
        """
        DELETE FROM source_capture_metadata
        WHERE batch_id IN (SELECT value FROM temp.cam_delete_upload_batch_ids)
           OR source_file_id IN (SELECT value FROM temp.cam_delete_file_ids)
        """,
        """
        DELETE FROM upload_batches
        WHERE batch_id IN (SELECT value FROM temp.cam_delete_upload_batch_ids)
        """,
        """
        DELETE FROM quarantines
        WHERE source_file_id IN (SELECT value FROM temp.cam_delete_file_ids)
        """,
        """
        DELETE FROM web_export_conversation_observations
        WHERE observation_id IN (SELECT value FROM temp.cam_delete_web_observation_ids)
        """,
        """
        DELETE FROM source_cursors
        WHERE source_stream_id IN (SELECT value FROM temp.cam_delete_stream_ids)
        """,
        """
        DELETE FROM source_segments
        WHERE source_file_id IN (SELECT value FROM temp.cam_delete_file_ids)
        """,
        """
        DELETE FROM source_stream_contexts
        WHERE source_stream_id IN (SELECT value FROM temp.cam_delete_stream_ids)
        """,
        """
        DELETE FROM source_stream_access
        WHERE source_stream_id IN (SELECT value FROM temp.cam_delete_stream_ids)
        """,
        "DELETE FROM source_streams WHERE source_stream_id IN "
        "(SELECT value FROM temp.cam_delete_stream_ids)",
        """
        DELETE FROM source_records
        WHERE source_record_id IN (SELECT value FROM temp.cam_delete_record_ids)
        """,
        "DELETE FROM source_files WHERE source_file_id IN "
        "(SELECT value FROM temp.cam_delete_file_ids)",
        """
        DELETE FROM web_export_attachment_links
        WHERE attachment_link_id IN (SELECT value FROM temp.cam_delete_attachment_link_ids)
        """,
        """
        DELETE FROM web_export_attachment_objects
        WHERE attachment_source_object_id IN (
          SELECT value FROM temp.cam_delete_attachment_object_ids
        )
        """,
        """
        DELETE FROM web_export_source_objects
        WHERE source_object_id IN (SELECT value FROM temp.cam_delete_web_source_object_ids)
        """,
        """
        DELETE FROM web_export_archive_members
        WHERE archive_member_id IN (SELECT value FROM temp.cam_delete_archive_member_ids)
        """,
        "DELETE FROM web_export_batches WHERE batch_id IN "
        "(SELECT value FROM temp.cam_delete_web_batch_ids)",
        """
        DELETE FROM source_schema_authorizations
        WHERE source_account_id IN (SELECT value FROM temp.cam_delete_account_ids)
        """,
        """
        DELETE FROM source_account_policies
        WHERE source_account_id IN (SELECT value FROM temp.cam_delete_account_ids)
        """,
        """
        DELETE FROM source_accounts
        WHERE source_account_id IN (SELECT value FROM temp.cam_delete_account_ids)
        """,
        """
        DELETE FROM contexts
        WHERE context_id IN (SELECT value FROM temp.cam_delete_context_ids)
          AND NOT EXISTS (
          SELECT 1 FROM source_stream_contexts link
          WHERE link.context_id = contexts.context_id
        )
          AND NOT EXISTS (
            SELECT 1 FROM event_contexts link WHERE link.context_id = contexts.context_id
          )
          AND NOT EXISTS (
            SELECT 1 FROM memory_candidate_contexts link
            WHERE link.context_id = contexts.context_id
          )
        """,
    )
    for statement in statements:
        connection.execute(statement)


def _validated_deletion_counts(value: Mapping[str, object]) -> dict[str, int]:
    expected_keys = set(_empty_deletion_target().counts())
    if "web_container_references" in value:
        expected_keys.add("web_container_references")
    if "record_erasure_matches" in value:
        expected_keys.add("record_erasure_matches")
    if "obsolete_observations" in value:
        expected_keys.update({"obsolete_observations", "retained_replacements"})
    if set(value) != expected_keys:
        raise ValueError("deletion target counts have an invalid shape")
    normalized: dict[str, int] = {}
    for key in sorted(expected_keys):
        count = value[key]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("deletion target counts must be non-negative integers")
        normalized[key] = count
    return normalized


def _verify_existing_deletion_operation(
    row: sqlite3.Row,
    *,
    selector: _DeletionSelector,
    target_digest: str,
    target_counts: dict[str, int],
    authorized_by: str,
    authorization_scope: str,
    reason: str,
) -> None:
    expected = (
        selector.kind.value,
        selector.source_system.value,
        target_digest,
        target_counts,
        authorized_by,
        authorization_scope,
        reason,
    )
    try:
        stored_counts = json.loads(cast(str, row[6]))
    except json.JSONDecodeError as error:
        raise RuntimeError("deletion operation counts are invalid") from error
    actual = (
        cast(str, row[0]),
        cast(str, row[1]),
        cast(str, row[2]),
        stored_counts,
        cast(str, row[7]),
        cast(str, row[8]),
        cast(str, row[9]),
    )
    if actual != expected:
        raise RuntimeError("deletion operation conflicts with the supplied plan")


def _deletion_result(
    operation_id: str,
    counts: dict[str, int],
    previous_generation: str,
    new_generation: str,
    *,
    resumed: bool,
) -> dict[str, Any]:
    return {
        "status": "deleted",
        "operation_id": operation_id,
        "target_counts": counts,
        "previous_generation_digest": previous_generation,
        "new_generation_digest": new_generation,
        "resumed": resumed,
        "retained_copy_warning": (
            "Existing source exports, snapshots, recovery packages, unselected remote objects "
            "and versions, and independently copied files remain outside this deletion operation."
        ),
    }


def _serialize_encrypted_deletion_target(target: EncryptedDeletionTarget) -> str:
    raw = json.dumps(target.as_dict(), separators=(",", ":"), sort_keys=True)
    if len(raw) > 1048576 or len(raw.encode()) > 1048576:
        raise ValueError("encrypted deletion target exceeds its byte limit")
    return raw


def _load_encrypted_deletion_target(raw: str) -> EncryptedDeletionTarget:
    if len(raw) > 1048576 or len(raw.encode()) > 1048576:
        raise ValueError("encrypted deletion target exceeds its byte limit")
    value = EncryptedDeletionTarget.from_dict(json.loads(raw))
    if _serialize_encrypted_deletion_target(value) != raw:
        raise RuntimeError("encrypted deletion work is not the retained canonical target")
    return value


def _validated_deletion_object_path(
    settings: Settings,
    relative_path: str,
    object_id: str,
) -> Path:
    digest = object_id.removeprefix("sha256:")
    _validate_sha256(digest, "deletion object id")
    expected = Path("objects") / "sha256" / digest[:2] / digest
    if Path(relative_path) != expected:
        raise RuntimeError(f"deletion object path is invalid: {object_id}")
    path = settings.data_root.resolve(strict=True) / expected
    if settings.object_root.resolve() not in path.parent.resolve().parents and (
        path.parent.resolve() != settings.object_root.resolve()
    ):
        raise RuntimeError(f"deletion object escaped the object root: {object_id}")
    return path


def _stream_verify_object(path: Path, object_id: str, expected_size: int) -> None:
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    byte_length = 0
    with os.fdopen(descriptor, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            byte_length += len(chunk)
            if byte_length > expected_size:
                raise RuntimeError(f"deletion object exceeded its expected size: {object_id}")
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    if (
        _stat_identity(before) != _stat_identity(after)
        or byte_length != expected_size
        or object_id != f"sha256:{digest.hexdigest()}"
    ):
        raise RuntimeError(f"deletion object failed hash verification: {object_id}")


def _ingest_account_digests(
    connection: sqlite3.Connection,
    source_system: SourceSystem,
    source_account: str,
) -> set[str]:
    aliases = {source_account}
    for row in connection.execute(
        """
        SELECT source_account_id, legacy_account_key, installation_id, device_id
        FROM source_accounts
        WHERE source_system = ?
          AND (source_account_id = ? OR legacy_account_key = ?)
        """,
        (source_system.value, source_account, source_account),
    ):
        if cast(str, row[3]) == _stable_id("device", cast(str, row[2]), "legacy-local"):
            aliases.update((cast(str, row[0]), cast(str, row[1])))
    return {_sha256_text(value) for value in aliases}


def _require_not_tombstoned(
    connection: sqlite3.Connection,
    *,
    source_system: SourceSystem,
    source_account: str,
    conversation_id: str,
) -> None:
    account_digests = _ingest_account_digests(connection, source_system, source_account)
    conversation_digest = _sha256_text(conversation_id)
    for row in connection.execute(
        """
        SELECT deletion_kind, source_account_digest, conversation_digest
        FROM deletion_tombstones
        WHERE source_system = ?
        """,
        (source_system.value,),
    ):
        if cast(str, row[1]) not in account_digests:
            continue
        if cast(str, row[0]) == DeletionKind.SOURCE_ACCOUNT.value or (
            cast(str | None, row[2]) == conversation_digest
        ):
            raise PermissionError("deleted evidence is blocked from routine reimport")


def _require_source_account_registration_allowed(
    connection: sqlite3.Connection,
    *,
    source_system: SourceSystem,
    aliases: Sequence[str],
) -> None:
    digests = {_sha256_text(value) for value in aliases}
    blocked = connection.execute(
        """
        SELECT source_account_digest
        FROM deletion_tombstones
        WHERE source_system = ? AND deletion_kind = 'source_account'
        """,
        (source_system.value,),
    ).fetchall()
    if any(cast(str, row[0]) in digests for row in blocked):
        raise PermissionError("deleted source account is blocked from routine re-registration")


def _latest_mutation_digest(connection: sqlite3.Connection) -> str | None:
    rows = connection.execute(
        """
        SELECT mutation_id, target_id, operation, previous_version_digest,
               new_version_digest, authorized_by, authorization_scope,
               reason, created_at, previous_mutation_digest
        FROM mutation_receipts
        """
    ).fetchall()
    if not rows:
        return None
    previous_by_digest: dict[str, str | None] = {}
    referenced_digests: set[str] = set()
    for row in rows:
        digest = hashlib.sha256(_encode_digest_row(tuple(row))).hexdigest()
        if digest in previous_by_digest:
            raise RuntimeError("mutation receipt chain contains a duplicate digest")
        previous = cast(str | None, row[9])
        previous_by_digest[digest] = previous
        if previous is not None:
            referenced_digests.add(previous)
    if any(previous not in previous_by_digest for previous in referenced_digests):
        raise RuntimeError("mutation receipt chain references a missing receipt")
    roots = [digest for digest, previous in previous_by_digest.items() if previous is None]
    tips = set(previous_by_digest) - referenced_digests
    if len(roots) != 1 or len(tips) != 1:
        raise RuntimeError("mutation receipt chain is not one linear chain")
    tip = tips.pop()
    visited: set[str] = set()
    current: str | None = tip
    while current is not None:
        if current in visited:
            raise RuntimeError("mutation receipt chain contains a cycle")
        visited.add(current)
        current = previous_by_digest[current]
    if len(visited) != len(previous_by_digest):
        raise RuntimeError("mutation receipt chain is disconnected")
    return tip


def _record_identity_mutation(
    connection: sqlite3.Connection,
    *,
    target_id: str,
    operation: str,
    previous_identity_digest: str,
    authorized_by: str,
    authorization_scope: str,
    reason: str,
    created_at: str,
) -> None:
    new_identity_digest = _identity_state_digest(connection)
    if hmac.compare_digest(previous_identity_digest, new_identity_digest):
        return
    mutation_id = str(uuid.uuid4())
    connection.execute(
        """
        INSERT INTO mutation_receipts(
          mutation_id, target_id, operation, previous_version_digest,
          new_version_digest, authorized_by, authorization_scope,
          reason, created_at, previous_mutation_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            mutation_id,
            _bounded_identity_value(target_id, "mutation target"),
            _bounded_identity_value(operation, "mutation operation"),
            previous_identity_digest,
            new_identity_digest,
            _bounded_identity_value(authorized_by, "mutation authorizer"),
            _bounded_identity_value(authorization_scope, "mutation authorization scope"),
            _bounded_identity_value(reason, "mutation reason"),
            created_at,
            _latest_mutation_digest(connection),
        ),
    )


def _record_media_type(source_system: SourceSystem) -> str:
    if source_system in {
        SourceSystem.CHATGPT_WEB,
        SourceSystem.CLAUDE_WEB,
        SourceSystem.GROK_WEB,
    }:
        return "application/json"
    return "application/x-ndjson-record"


def _content_present_in_raw_record(raw: bytes, content_text: str) -> bool:
    try:
        value: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("source evidence is not a valid JSON record") from exc
    pending: list[object] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and content_text in item:
            return True
        if isinstance(item, dict):
            pending.extend(cast(dict[object, object], item).values())
        elif isinstance(item, list):
            pending.extend(cast(list[object], item))
    return False


def _fts_query(query: str) -> str:
    tokens = [match.group(0) for match in FTS_TOKEN.finditer(query)][:24]
    return " AND ".join(f'"{token.replace(chr(34), "")}"' for token in tokens)


def _verify_source_container(path: Path, expected_sha256: str, expected_size: int) -> None:
    _validate_sha256(expected_sha256, "source container digest")
    descriptor, normalized = open_regular_file_no_symlinks(path, "source container")
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if before.st_size != expected_size:
            raise RuntimeError("source object no longer matches its approved byte length")
        digest = hashlib.sha256()
        size = 0
        while chunk := handle.read(min(1024 * 1024, expected_size - size + 1)):
            size += len(chunk)
            if size > expected_size:
                raise RuntimeError("source object exceeded its approved byte length")
            digest.update(chunk)
        after = os.fstat(handle.fileno())
        current = secure_path_stat(normalized, "source container")
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    if any(
        (state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns, state.st_ctime_ns)
        != identity
        for state in (after, current)
    ):
        raise RuntimeError("source object changed while it was verified")
    if size != expected_size or digest.hexdigest() != expected_sha256:
        raise RuntimeError("source object no longer matches its approved digest and size")


def _stable_id(kind: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join((kind, *parts)).encode()).hexdigest()
    return f"{kind}:{digest}"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _validate_sha256(value: str, field: str) -> None:
    if SHA256_HEX.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _upload_receipt(
    batch_id: str,
    row: Sequence[object],
    *,
    replayed: bool,
) -> dict[str, Any]:
    reasons_value: object = json.loads(cast(str, row[8]))
    if not isinstance(reasons_value, dict):
        raise RuntimeError("stored upload quarantine reasons are invalid")
    reasons = cast(dict[str, object], reasons_value)
    if any(
        isinstance(count, bool) or not isinstance(count, int) or count < 0
        for count in reasons.values()
    ):
        raise RuntimeError("stored upload quarantine reasons are invalid")
    return UploadReceipt(
        batch_id=batch_id,
        status="already_applied" if replayed else "applied",
        source_file_id=cast(str, row[4]),
        conversation_id=cast(str, row[5]),
        event_count=cast(int, row[6]),
        quarantined_records=cast(int, row[7]),
        quarantine_reasons={key: cast(int, value) for key, value in reasons.items()},
        created_at=cast(str, row[9]),
    ).as_dict()


def _validated_string_array(value: object) -> list[str]:
    if not isinstance(value, str):
        raise RuntimeError("stored string array is invalid")
    try:
        parsed: object = json.loads(value)
    except json.JSONDecodeError as error:
        raise RuntimeError("stored string array is invalid") from error
    if not isinstance(parsed, list):
        raise RuntimeError("stored string array is invalid")
    items = cast(list[object], parsed)
    if any(not isinstance(item, str) for item in items):
        raise RuntimeError("stored string array is invalid")
    return [cast(str, item) for item in items]


def _validated_count_object(value: object) -> dict[str, int]:
    if not isinstance(value, str):
        raise RuntimeError("stored count object is invalid")
    try:
        parsed: object = json.loads(value)
    except json.JSONDecodeError as error:
        raise RuntimeError("stored count object is invalid") from error
    if not isinstance(parsed, dict):
        raise RuntimeError("stored count object is invalid")
    result: dict[str, int] = {}
    for key, count in cast(dict[object, object], parsed).items():
        if (
            not isinstance(key, str)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            raise RuntimeError("stored count object is invalid")
        result[key] = count
    return result


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _reject_read_only_sidecars(database: Path) -> None:
    present = [
        suffix
        for suffix in SQLITE_SIDECAR_SUFFIXES
        if (Path(f"{database}{suffix}").exists() or Path(f"{database}{suffix}").is_symlink())
    ]
    if present:
        raise RuntimeError(
            "read-only ledger requires a checkpointed database with no SQLite sidecars: "
            + ", ".join(present)
        )


def _validate_live_read_only_sidecars(database: Path) -> None:
    for suffix in SQLITE_SIDECAR_SUFFIXES:
        path = Path(f"{database}{suffix}")
        try:
            details = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ValueError("read-only SQLite sidecar must be a single-link regular file")
        if suffix == "-journal":
            raise RuntimeError("read-only ledger requires completed SQLite journal recovery")


def _bounded_identity_value(value: str, field: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} is required")
    if len(normalized.encode()) > 256:
        raise ValueError(f"{field} exceeds its size limit")
    return normalized


def _canonical_identity_value(value: str, field: str) -> str:
    normalized = _bounded_identity_value(value, field)
    if normalized != value:
        raise ValueError(f"{field} must use its exact canonical value")
    return normalized


def _normalized_source_schema_provenance(
    provenance: SourceSchemaProvenance,
) -> SourceSchemaProvenance:
    _validate_sha256(provenance.schema_fingerprint, "source schema fingerprint")
    parser_versions: dict[str, str] = {}
    for parser_name, parser_version in provenance.parser_versions:
        normalized_name = _canonical_identity_value(parser_name, "parser name")
        normalized_version = _canonical_identity_value(parser_version, "parser version")
        existing = parser_versions.setdefault(normalized_name, normalized_version)
        if existing != normalized_version:
            raise ValueError("one parser name cannot carry multiple schema-authorized versions")
    return SourceSchemaProvenance(
        source_client=_canonical_identity_value(provenance.source_client, "source client"),
        source_client_version=_canonical_identity_value(
            provenance.source_client_version,
            "source client version",
        ),
        capture_capability=_canonical_identity_value(
            provenance.capture_capability,
            "capture capability",
        ),
        adapter_name=_canonical_identity_value(provenance.adapter_name, "adapter name"),
        adapter_version=_canonical_identity_value(provenance.adapter_version, "adapter version"),
        schema_fingerprint=provenance.schema_fingerprint,
        parser_versions=tuple(sorted(parser_versions.items())),
    )


def _source_schema_parser_versions_json(provenance: SourceSchemaProvenance) -> str:
    return json.dumps(
        dict(provenance.parser_versions),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _source_schema_authorization_id(
    *,
    source_account_id: str,
    source_system: SourceSystem,
    provenance: SourceSchemaProvenance,
) -> str:
    return _stable_id(
        "source_schema_authorization",
        source_account_id,
        source_system.value,
        provenance.schema_fingerprint,
        provenance.source_client,
        provenance.source_client_version,
        provenance.capture_capability,
        provenance.adapter_name,
        provenance.adapter_version,
        _source_schema_parser_versions_json(provenance),
    )


def _normalized_web_export_batch_provenance(
    provenance: WebExportBatchProvenance,
) -> WebExportBatchProvenance:
    _validate_sha256(provenance.manifest_sha256, "web export manifest digest")
    _validate_sha256(provenance.archive_sha256, "web export archive digest")
    _validate_sha256(
        provenance.selected_member_name_sha256,
        "web export selected member name digest",
    )
    _validate_sha256(
        provenance.selected_member_sha256,
        "web export selected member digest",
    )
    for value, field in (
        (provenance.archive_byte_length, "web export archive byte length"),
        (provenance.selected_member_byte_length, "web export selected member byte length"),
    ):
        if isinstance(value, bool) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
    normalized_members: list[WebExportArchiveMemberProvenance] = []
    seen_indexes: set[int] = set()
    for member in provenance.archive_members:
        if isinstance(member.archive_member_index, bool) or member.archive_member_index < 0:
            raise ValueError("web export archive member index must be non-negative")
        if member.archive_member_index in seen_indexes:
            raise ValueError("web export archive member indexes must be unique")
        seen_indexes.add(member.archive_member_index)
        _validate_sha256(member.name_sha256, "web export archive member name digest")
        _validate_sha256(member.content_sha256, "web export archive member content digest")
        for value, field in (
            (member.compressed_bytes, "web export archive member compressed bytes"),
            (member.byte_length, "web export archive member byte length"),
            (member.compression_method, "web export archive member compression method"),
        ):
            if isinstance(value, bool) or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
        normalized_members.append(
            WebExportArchiveMemberProvenance(
                archive_member_index=member.archive_member_index,
                locator=_bounded_text_value(
                    member.locator,
                    "web export archive member locator",
                    max_bytes=4096,
                ),
                name_sha256=member.name_sha256,
                content_sha256=member.content_sha256,
                compressed_bytes=member.compressed_bytes,
                byte_length=member.byte_length,
                compression_method=member.compression_method,
                media_type_hint=_canonical_identity_value(
                    member.media_type_hint,
                    "web export archive member media type hint",
                ),
            )
        )
    normalized_references: list[WebExportAttachmentReferenceProvenance] = []
    seen_references: set[tuple[int, int, int, int, str]] = set()
    for reference in provenance.attachment_references:
        for value, field in (
            (reference.archive_member_index, "web export attachment member index"),
            (reference.conversation_index, "web export attachment conversation index"),
            (reference.source_record_ordinal, "web export attachment record ordinal"),
            (reference.reference_ordinal, "web export attachment reference ordinal"),
        ):
            if isinstance(value, bool) or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
        if reference.archive_member_index not in seen_indexes:
            raise ValueError("web export attachment reference names an unknown archive member")
        _validate_sha256(reference.reference_sha256, "web export attachment reference digest")
        key = (
            reference.archive_member_index,
            reference.conversation_index,
            reference.source_record_ordinal,
            reference.reference_ordinal,
            reference.reference_sha256,
        )
        if key in seen_references:
            raise ValueError("web export attachment references must be unique")
        seen_references.add(key)
        normalized_references.append(
            WebExportAttachmentReferenceProvenance(
                archive_member_index=reference.archive_member_index,
                conversation_index=reference.conversation_index,
                source_record_ordinal=reference.source_record_ordinal,
                reference_ordinal=reference.reference_ordinal,
                reference_sha256=reference.reference_sha256,
            )
        )
    linked_member_indexes = {reference.archive_member_index for reference in normalized_references}
    normalized_extracted_indexes: list[int] = []
    seen_extracted_indexes: set[int] = set()
    for archive_member_index in provenance.extracted_attachment_indices:
        if isinstance(archive_member_index, bool) or archive_member_index < 0:
            raise ValueError("web export extracted attachment index must be non-negative")
        if archive_member_index in seen_extracted_indexes:
            raise ValueError("web export extracted attachment indexes must be unique")
        if archive_member_index not in linked_member_indexes:
            raise ValueError("web export extracted attachment must have an exact provider link")
        seen_extracted_indexes.add(archive_member_index)
        normalized_extracted_indexes.append(archive_member_index)
    return WebExportBatchProvenance(
        manifest_sha256=provenance.manifest_sha256,
        code_revision=_canonical_identity_value(
            provenance.code_revision,
            "web export code revision",
        ),
        prepared_at=_canonical_identity_value(
            provenance.prepared_at,
            "web export prepared time",
        ),
        archive_sha256=provenance.archive_sha256,
        archive_byte_length=provenance.archive_byte_length,
        selected_member_name_sha256=provenance.selected_member_name_sha256,
        selected_member_sha256=provenance.selected_member_sha256,
        selected_member_byte_length=provenance.selected_member_byte_length,
        archive_members=tuple(
            sorted(normalized_members, key=lambda item: item.archive_member_index)
        ),
        attachment_references=tuple(
            sorted(
                normalized_references,
                key=lambda item: (
                    item.archive_member_index,
                    item.conversation_index,
                    item.source_record_ordinal,
                    item.reference_ordinal,
                    item.reference_sha256,
                ),
            )
        ),
        extracted_attachment_indices=tuple(sorted(normalized_extracted_indexes)),
    )


def _web_export_batch_id(
    *,
    source_account_id: str,
    source_system: SourceSystem,
    authorization_id: str,
    provenance: WebExportBatchProvenance,
) -> str:
    return _stable_id(
        "web_export_batch",
        source_account_id,
        source_system.value,
        authorization_id,
        provenance.archive_sha256,
        provenance.selected_member_name_sha256,
        provenance.selected_member_sha256,
    )


def _normalized_web_export_observation(
    observation: WebExportConversationObservation,
) -> WebExportConversationObservation:
    batch_id = _canonical_identity_value(observation.batch_id, "web export batch id")
    if isinstance(observation.conversation_index, bool) or observation.conversation_index < 0:
        raise ValueError("web export conversation index must be non-negative")
    if (
        isinstance(observation.source_byte_start, bool)
        or isinstance(observation.source_byte_end, bool)
        or observation.source_byte_start < 0
        or observation.source_byte_end <= observation.source_byte_start
    ):
        raise ValueError("web export conversation byte range is invalid")
    _validate_sha256(observation.conversation_sha256, "web export conversation digest")
    return WebExportConversationObservation(
        batch_id=batch_id,
        conversation_index=observation.conversation_index,
        source_byte_start=observation.source_byte_start,
        source_byte_end=observation.source_byte_end,
        conversation_sha256=observation.conversation_sha256,
        source_locator=_bounded_text_value(
            observation.source_locator,
            "web export conversation locator",
            max_bytes=4096,
        ),
    )


def _record_web_export_conversation_observation(
    connection: sqlite3.Connection,
    *,
    source_file_id: str,
    source_object_id: str,
    source_account_id: str,
    source_system: SourceSystem,
    authorization_id: str,
    parsed: ParseResult,
    observation: WebExportConversationObservation,
    created_at: str,
) -> str:
    normalized = _normalized_web_export_observation(observation)
    batch = connection.execute(
        """
        SELECT source_account_id, source_system, authorization_id
        FROM web_export_batches
        WHERE batch_id = ?
        """,
        (normalized.batch_id,),
    ).fetchone()
    if batch is None or tuple(batch) != (
        source_account_id,
        source_system.value,
        authorization_id,
    ):
        raise PermissionError("authorized web export batch not found")
    if (
        normalized.conversation_sha256 != parsed.file_digest
        or normalized.source_byte_end - normalized.source_byte_start != parsed.file_size
    ):
        raise RuntimeError("web export conversation observation does not match parsed bytes")
    observation_id = _stable_id(
        "web_export_conversation_observation",
        normalized.batch_id,
        str(normalized.conversation_index),
        normalized.conversation_sha256,
    )
    expected = (
        observation_id,
        normalized.batch_id,
        source_file_id,
        source_object_id,
        normalized.conversation_index,
        normalized.source_byte_start,
        normalized.source_byte_end,
        normalized.conversation_sha256,
        normalized.source_locator,
    )
    existing = connection.execute(
        """
        SELECT observation_id, batch_id, source_file_id, source_object_id,
               conversation_index, source_byte_start, source_byte_end,
               conversation_sha256, source_locator
        FROM web_export_conversation_observations
        WHERE observation_id = ?
        """,
        (observation_id,),
    ).fetchone()
    if existing is None:
        connection.execute(
            """
            INSERT INTO web_export_conversation_observations(
              observation_id, batch_id, source_file_id, source_object_id,
              conversation_index, source_byte_start, source_byte_end,
              conversation_sha256, source_locator, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (*expected, created_at),
        )
    elif tuple(existing) != expected:
        raise RuntimeError("web export conversation observation conflicts with the ledger")
    return observation_id


def _normalized_pending_web_evidence_claim(
    claim: PendingWebEvidenceClaim,
) -> _NormalizedPendingWebEvidenceClaim:
    if claim.source_system not in {
        SourceSystem.CHATGPT_WEB,
        SourceSystem.CLAUDE_WEB,
        SourceSystem.GROK_WEB,
    }:
        raise ValueError("pending web evidence requires an official web source")
    source_account_id = _canonical_identity_value(claim.source_account_id, "source account id")
    conversation_id = _bounded_text_value(
        claim.conversation_id,
        "pending web evidence conversation id",
        max_bytes=4096,
    )
    message_id = _bounded_text_value(
        claim.message_id,
        "pending web evidence message id",
        max_bytes=4096,
    )

    def optional(value: str | None, field: str) -> str | None:
        return _bounded_text_value(value, field, max_bytes=4096) if value is not None else None

    content_bytes = claim.content_text.encode()
    if len(content_bytes) > MAX_PROPOSAL_STATEMENT_BYTES:
        raise ValueError("pending web evidence content exceeds its size limit")
    decision = classify_record(
        source_system=claim.source_system,
        content_text=claim.content_text,
        raw_record=content_bytes,
        max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
    )
    if not decision.accepted:
        raise ValueError(f"pending web evidence rejected by admission policy: {decision.reason}")
    family_key = _web_export_family_key(
        source_account_id=source_account_id,
        source_system=claim.source_system,
        conversation_id=conversation_id,
        message_id=message_id,
        message_id_kind="provider_message_id",
    )
    return _NormalizedPendingWebEvidenceClaim(
        source_account_id=source_account_id,
        source_system=claim.source_system,
        family_key=family_key,
        conversation_id=conversation_id,
        message_id=message_id,
        parent_message_id=optional(
            claim.parent_message_id,
            "pending web evidence parent message id",
        ),
        branch_id=optional(claim.branch_id, "pending web evidence branch id"),
        content_digest=_sha256_text(claim.content_text),
    )


def _reconcile_pending_memory_claims_for_event(
    connection: sqlite3.Connection,
    *,
    event_id: str,
    reconciliation_key: str,
    source_account_id: str,
    source_system: SourceSystem,
    family_key: str,
    conversation_id: str,
    message_id: str,
    parent_message_id: str | None,
    branch_id: str | None,
    content_digest: str,
    scope: Scope,
    project_id: str | None,
    created_at: str,
) -> int:
    rows = connection.execute(
        """
        SELECT claim.claim_id, claim.memory_id, candidate.scope, candidate.project_id
        FROM memory_candidate_evidence_claims claim
        JOIN memory_candidates candidate ON candidate.memory_id = claim.memory_id
        LEFT JOIN memory_candidate_evidence_links link ON link.claim_id = claim.claim_id
        WHERE link.claim_id IS NULL
          AND claim.family_key = ?
          AND claim.source_account_id = ?
          AND claim.source_system = ?
          AND claim.conversation_id = ?
          AND claim.message_id = ?
          AND claim.message_id_kind = 'provider_message_id'
          AND (claim.parent_message_id IS NULL OR claim.parent_message_id = ?)
          AND (claim.branch_id IS NULL OR claim.branch_id = ?)
          AND claim.content_digest = ?
        ORDER BY claim.claim_id
        """,
        (
            family_key,
            source_account_id,
            source_system.value,
            conversation_id,
            message_id,
            parent_message_id,
            branch_id,
            content_digest,
        ),
    ).fetchall()
    linked = 0
    for claim_id, memory_id, candidate_scope, candidate_project_id in rows:
        try:
            _validate_proposal_scope(
                Scope(cast(str, candidate_scope)),
                cast(str | None, candidate_project_id),
                [scope],
                [project_id],
            )
        except ValueError:
            continue
        _link_pending_memory_claim(
            connection,
            claim_id=cast(str, claim_id),
            memory_id=cast(str, memory_id),
            event_id=event_id,
            reconciliation_key=reconciliation_key,
            created_at=created_at,
        )
        linked += 1
    return linked


def _reconcile_pending_memory_claim_from_existing_event(
    connection: sqlite3.Connection,
    *,
    claim_id: str,
    memory_id: str,
    claim: _NormalizedPendingWebEvidenceClaim,
    candidate_scope: Scope,
    candidate_project_id: str | None,
    created_at: str,
) -> tuple[str, str] | None:
    rows = connection.execute(
        """
        SELECT canonical.event_id, canonical.reconciliation_key,
               current.scope, current.project_id, current.privacy
        FROM web_export_reconciled_events canonical
        JOIN events_current current ON current.event_id = canonical.event_id
        WHERE canonical.family_key = ?
          AND canonical.source_account_id = ?
          AND canonical.source_system = ?
          AND canonical.conversation_id = ?
          AND canonical.message_id = ?
          AND canonical.message_id_kind = 'provider_message_id'
          AND (? IS NULL OR canonical.parent_message_id = ?)
          AND (? IS NULL OR canonical.branch_id = ?)
          AND canonical.content_digest = ?
        ORDER BY canonical.created_at, canonical.reconciliation_key
        """,
        (
            claim.family_key,
            claim.source_account_id,
            claim.source_system.value,
            claim.conversation_id,
            claim.message_id,
            claim.parent_message_id,
            claim.parent_message_id,
            claim.branch_id,
            claim.branch_id,
            claim.content_digest,
        ),
    ).fetchall()
    for event_id, reconciliation_key, event_scope, event_project_id, privacy in rows:
        if privacy != Privacy.INCLUDED.value:
            continue
        try:
            _validate_proposal_scope(
                candidate_scope,
                candidate_project_id,
                [Scope(cast(str, event_scope))],
                [cast(str | None, event_project_id)],
            )
        except ValueError:
            continue
        normalized_event_id = cast(str, event_id)
        normalized_reconciliation_key = cast(str, reconciliation_key)
        _link_pending_memory_claim(
            connection,
            claim_id=claim_id,
            memory_id=memory_id,
            event_id=normalized_event_id,
            reconciliation_key=normalized_reconciliation_key,
            created_at=created_at,
        )
        return normalized_event_id, normalized_reconciliation_key
    return None


def _link_pending_memory_claim(
    connection: sqlite3.Connection,
    *,
    claim_id: str,
    memory_id: str,
    event_id: str,
    reconciliation_key: str,
    created_at: str,
) -> None:
    existing = connection.execute(
        """
        SELECT event_id, reconciliation_key
        FROM memory_candidate_evidence_links
        WHERE claim_id = ?
        """,
        (claim_id,),
    ).fetchone()
    if existing is not None:
        if tuple(existing) != (event_id, reconciliation_key):
            raise RuntimeError("pending web evidence claim conflicts with its canonical link")
        return
    candidate = connection.execute(
        """
        SELECT authority, scope, project_id, evidence_event_ids_json
        FROM memory_candidates
        WHERE memory_id = ?
        """,
        (memory_id,),
    ).fetchone()
    event = connection.execute(
        """
        SELECT authority, scope, project_id, privacy
        FROM events_current
        WHERE event_id = ?
        """,
        (event_id,),
    ).fetchone()
    if candidate is None or event is None:
        raise RuntimeError("pending web evidence reconciliation target is missing")
    if event[3] != Privacy.INCLUDED.value:
        raise RuntimeError("pending web evidence cannot widen scope or include excluded evidence")
    try:
        _validate_proposal_scope(
            Scope(cast(str, candidate[1])),
            cast(str | None, candidate[2]),
            [Scope(cast(str, event[1]))],
            [cast(str | None, event[2])],
        )
    except ValueError as error:
        raise RuntimeError(
            "pending web evidence cannot widen scope or include excluded evidence"
        ) from error
    previous_json = cast(str, candidate[3])
    try:
        parsed_ids: object = json.loads(previous_json)
    except json.JSONDecodeError as error:
        raise RuntimeError("memory candidate evidence is invalid") from error
    if not isinstance(parsed_ids, list):
        raise RuntimeError("memory candidate evidence is invalid")
    raw_ids = cast(list[object], parsed_ids)
    if any(not isinstance(item, str) or not item for item in raw_ids) or len(
        {cast(str, item) for item in raw_ids}
    ) != len(raw_ids):
        raise RuntimeError("memory candidate evidence is invalid")
    evidence_ids = [cast(str, item) for item in raw_ids]
    if event_id not in evidence_ids:
        evidence_ids.append(event_id)
    evidence_ids.sort()
    evidence_json = json.dumps(evidence_ids)
    placeholders = ",".join("?" for _ in evidence_ids)
    authority_rows = connection.execute(
        f"""
        SELECT authority
        FROM events_current
        WHERE event_id IN ({placeholders}) AND privacy = 'included'
        """,
        evidence_ids,
    ).fetchall()
    if len(authority_rows) != len(evidence_ids):
        raise RuntimeError("reconciled candidate evidence is missing or excluded")
    authority = _authority_floor(Authority(cast(str, row[0])) for row in authority_rows)
    previous_authority = cast(str, candidate[0])
    connection.execute(
        """
        UPDATE memory_candidates
        SET authority = ?, evidence_event_ids_json = ?
        WHERE memory_id = ?
          AND authority = ?
          AND evidence_event_ids_json = ?
        """,
        (authority.value, evidence_json, memory_id, previous_authority, previous_json),
    )
    if connection.execute("SELECT changes()").fetchone()[0] != 1:
        raise RuntimeError("memory candidate changed during evidence reconciliation")
    connection.execute(
        """
        INSERT INTO memory_candidate_evidence_links(
          claim_id, event_id, reconciliation_key,
          previous_evidence_event_ids_json, evidence_event_ids_json,
          previous_authority, authority, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            claim_id,
            event_id,
            reconciliation_key,
            previous_json,
            evidence_json,
            previous_authority,
            authority.value,
            created_at,
        ),
    )


def _web_export_family_key(
    *,
    source_account_id: str,
    source_system: SourceSystem,
    conversation_id: str,
    message_id: str | None,
    message_id_kind: str | None,
) -> str:
    if message_id is None or message_id_kind != "provider_message_id":
        raise ValueError("web export reconciliation requires a certified provider message id")
    values = (
        _canonical_identity_value(source_account_id, "source account id"),
        source_system.value,
        _bounded_text_value(conversation_id, "web export conversation id", max_bytes=4096),
        message_id_kind,
        _bounded_text_value(message_id, "web export message id", max_bytes=4096),
    )
    return _sha256_text(
        json.dumps(values, ensure_ascii=True, separators=(",", ":"), sort_keys=False)
    )


def _web_export_reconciliation_key(
    *,
    family_key: str | None,
    source_account_id: str,
    source_system: SourceSystem,
    conversation_id: str,
    message_id: str | None,
    message_id_kind: str | None,
    parent_message_id: str | None,
    branch_id: str | None,
    object_id: str,
    event_type: str,
    actor_kind: str,
    assistant: str | None,
    authority: str,
    occurred_at: str | None,
    scope: str,
    project_id: str | None,
    privacy: str,
    content_digest: str,
) -> str:
    values = _normalized_web_reconciliation_values(
        family_key=family_key,
        source_account_id=source_account_id,
        source_system=source_system,
        conversation_id=conversation_id,
        message_id=message_id,
        message_id_kind=message_id_kind,
        parent_message_id=parent_message_id,
        branch_id=branch_id,
        object_id=object_id,
        event_type=event_type,
        actor_kind=actor_kind,
        assistant=assistant,
        authority=authority,
        occurred_at=occurred_at,
        scope=scope,
        project_id=project_id,
        privacy=privacy,
        content_digest=content_digest,
    )
    return _sha256_text(
        json.dumps(values, ensure_ascii=True, separators=(",", ":"), sort_keys=False)
    )


def _find_matching_web_export_event(
    connection: sqlite3.Connection,
    *,
    reconciliation_key: str,
    family_key: str | None,
    source_account_id: str,
    source_system: SourceSystem,
    conversation_id: str,
    message_id: str | None,
    message_id_kind: str | None,
    parent_message_id: str | None,
    branch_id: str | None,
    object_id: str,
    event_type: str,
    actor_kind: str,
    assistant: str | None,
    authority: str,
    occurred_at: str | None,
    scope: str,
    project_id: str | None,
    privacy: str,
    content_digest: str,
) -> str | None:
    _validate_sha256(reconciliation_key, "web export reconciliation key")
    expected = _normalized_web_reconciliation_values(
        family_key=family_key,
        source_account_id=source_account_id,
        source_system=source_system,
        conversation_id=conversation_id,
        message_id=message_id,
        message_id_kind=message_id_kind,
        parent_message_id=parent_message_id,
        branch_id=branch_id,
        object_id=object_id,
        event_type=event_type,
        actor_kind=actor_kind,
        assistant=assistant,
        authority=authority,
        occurred_at=occurred_at,
        scope=scope,
        project_id=project_id,
        privacy=privacy,
        content_digest=content_digest,
    )
    row = connection.execute(
        """
        SELECT event_id, family_key, source_account_id, source_system, conversation_id,
               message_id, message_id_kind, parent_message_id, branch_id, object_id,
               event_type, actor_kind, assistant, authority, occurred_at, scope,
               project_id, privacy, content_digest
        FROM web_export_reconciled_events
        WHERE reconciliation_key = ?
        """,
        (reconciliation_key,),
    ).fetchone()
    if row is None:
        return None
    if tuple(row[1:]) != expected:
        raise RuntimeError("web export reconciliation key conflicts with canonical evidence")
    return cast(str, row[0])


def _normalized_web_reconciliation_values(
    *,
    family_key: str | None,
    source_account_id: str,
    source_system: SourceSystem,
    conversation_id: str,
    message_id: str | None,
    message_id_kind: str | None,
    parent_message_id: str | None,
    branch_id: str | None,
    object_id: str,
    event_type: str,
    actor_kind: str,
    assistant: str | None,
    authority: str,
    occurred_at: str | None,
    scope: str,
    project_id: str | None,
    privacy: str,
    content_digest: str,
) -> tuple[str | None, ...]:
    if message_id is None or message_id_kind != "provider_message_id" or family_key is None:
        raise ValueError("web export reconciliation requires a certified provider message id")
    _validate_sha256(family_key, "web export message family key")
    _validate_sha256(content_digest, "web export reconciled content digest")

    def optional(value: str | None, field: str) -> str | None:
        return _bounded_text_value(value, field, max_bytes=4096) if value is not None else None

    return (
        family_key,
        _canonical_identity_value(source_account_id, "source account id"),
        source_system.value,
        _bounded_text_value(conversation_id, "web export conversation id", max_bytes=4096),
        _bounded_text_value(message_id, "web export message id", max_bytes=4096),
        message_id_kind,
        optional(parent_message_id, "web export parent message id"),
        optional(branch_id, "web export branch id"),
        _bounded_text_value(object_id, "web export object id", max_bytes=256),
        _canonical_identity_value(event_type, "web export event type"),
        _canonical_identity_value(actor_kind, "web export actor kind"),
        optional(assistant, "web export assistant"),
        _canonical_identity_value(authority, "web export authority"),
        optional(occurred_at, "web export occurrence time"),
        _canonical_identity_value(scope, "web export scope"),
        optional(project_id, "web export project id"),
        _canonical_identity_value(privacy, "web export privacy"),
        content_digest,
    )


def _bounded_text_value(value: str, field: str, *, max_bytes: int) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{field} must use its exact canonical value")
    if len(value.encode()) > max_bytes:
        raise ValueError(f"{field} exceeds its size limit")
    return value


def _parse_enrollment_code(code: str) -> tuple[str, str]:
    encoded = code.encode()
    if len(encoded) > ENROLLMENT_CODE_MAX_BYTES:
        raise ValueError("valid device enrollment not found")
    parts = code.split(".")
    if len(parts) != 3 or parts[0] != ENROLLMENT_CODE_PREFIX or not parts[1] or not parts[2]:
        raise ValueError("valid device enrollment not found")
    return parts[1], hashlib.sha256(encoded).hexdigest()


def _normalized_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise RuntimeError("stored timestamp is invalid") from error
    return _normalized_timestamp(parsed)


def _candidate_review_state(
    connection: sqlite3.Connection,
    memory_id: str,
) -> dict[str, Any]:
    memory_id = _bounded_text_value(memory_id, "memory candidate id", max_bytes=256)
    candidate = connection.execute(
        """
        SELECT candidate.memory_type, candidate.statement, candidate.statement_digest,
               candidate.authority, candidate.scope, candidate.project_id,
               candidate.temporal_status, candidate.evidence_event_ids_json,
               candidate.created_by, candidate.created_at, access.access
        FROM memory_candidates candidate
        LEFT JOIN memory_candidate_access access ON access.memory_id = candidate.memory_id
        WHERE candidate.memory_id = ?
        """,
        (memory_id,),
    ).fetchone()
    if candidate is None:
        raise KeyError(f"memory candidate not found: {memory_id}")
    evidence_event_ids = _validated_string_array(candidate[7])
    candidate_evidence_order_valid = evidence_event_ids == sorted(evidence_event_ids)
    context_rows = connection.execute(
        """
        SELECT context.context_id, context.kind, context.context_key
        FROM memory_candidate_contexts link
        JOIN contexts context ON context.context_id = link.context_id
        WHERE link.memory_id = ?
        ORDER BY context.kind, context.context_key
        """,
        (memory_id,),
    ).fetchall()
    context_ids = [cast(str, row[0]) for row in context_rows]
    contexts = [{"kind": cast(str, row[1]), "key": cast(str, row[2])} for row in context_rows]
    claim = connection.execute(
        """
        SELECT claim.claim_id, claim.source_account_id, claim.source_system,
               claim.family_key, claim.conversation_id, claim.message_id,
               claim.message_id_kind, claim.parent_message_id, claim.branch_id,
               claim.content_digest, claim.created_by, claim.created_at,
               link.event_id, link.reconciliation_key,
               link.previous_evidence_event_ids_json, link.evidence_event_ids_json,
               link.previous_authority, link.authority, link.created_at,
               canonical.family_key, canonical.source_account_id, canonical.source_system,
               canonical.conversation_id, canonical.message_id, canonical.message_id_kind,
               canonical.parent_message_id, canonical.branch_id, canonical.object_id,
               canonical.event_type, canonical.actor_kind, canonical.assistant,
               canonical.authority, canonical.occurred_at, canonical.scope,
               canonical.project_id, canonical.privacy, canonical.content_digest
        FROM memory_candidate_evidence_claims claim
        LEFT JOIN memory_candidate_evidence_links link ON link.claim_id = claim.claim_id
        LEFT JOIN web_export_reconciled_events canonical
          ON canonical.reconciliation_key = link.reconciliation_key
         AND canonical.event_id = link.event_id
        WHERE claim.memory_id = ?
        """,
        (memory_id,),
    ).fetchone()
    proposal = connection.execute(
        """
        SELECT proposal_id, candidate_creation_digest, proposed_by, proposer_kind,
               authorization_scope, policy_version, created_at
        FROM memory_candidate_proposal_receipts
        WHERE memory_id = ?
        """,
        (memory_id,),
    ).fetchone()
    lifecycle, last_transition_id, review_history = _validated_candidate_review_history(
        connection,
        memory_id,
    )

    blockers: list[str] = []
    if not candidate_evidence_order_valid:
        blockers.append("candidate_evidence_order_invalid")
    candidate_created_at_valid = True
    try:
        _parse_timestamp(cast(str, candidate[9]))
    except (TypeError, ValueError, RuntimeError):
        candidate_created_at_valid = False
        blockers.append("candidate_creation_time_invalid")
    normalized_claim: _NormalizedPendingWebEvidenceClaim | None = None
    creation_evidence_event_ids = evidence_event_ids
    creation_authority = Authority(cast(str, candidate[3]))
    pending_claim_state: dict[str, object] | None = None
    if claim is not None:
        normalized_claim = _NormalizedPendingWebEvidenceClaim(
            source_account_id=cast(str, claim[1]),
            source_system=SourceSystem(cast(str, claim[2])),
            family_key=cast(str, claim[3]),
            conversation_id=cast(str, claim[4]),
            message_id=cast(str, claim[5]),
            parent_message_id=cast(str | None, claim[7]),
            branch_id=cast(str | None, claim[8]),
            content_digest=cast(str, claim[9]),
        )
        claim_identity_valid = True
        try:
            expected_family_key = _web_export_family_key(
                source_account_id=normalized_claim.source_account_id,
                source_system=normalized_claim.source_system,
                conversation_id=normalized_claim.conversation_id,
                message_id=normalized_claim.message_id,
                message_id_kind=cast(str, claim[6]),
            )
            expected_claim_id = _stable_id(
                "pending_web_evidence_claim",
                memory_id,
                normalized_claim.family_key,
                normalized_claim.parent_message_id or "",
                normalized_claim.branch_id or "",
                normalized_claim.content_digest,
            )
            _parse_timestamp(cast(str, claim[11]))
            claim_identity_valid = (
                hmac.compare_digest(cast(str, claim[0]), expected_claim_id)
                and hmac.compare_digest(normalized_claim.family_key, expected_family_key)
                and cast(str, claim[6]) == "provider_message_id"
                and cast(str, claim[10]) == cast(str, candidate[8])
                and cast(str, claim[11]) == cast(str, candidate[9])
            )
        except (TypeError, ValueError, RuntimeError):
            claim_identity_valid = False
        pending_claim_state = {
            "claim_id": cast(str, claim[0]),
            "claim_identity_digest": _sha256_text(
                json.dumps(tuple(claim[1:12]), ensure_ascii=False, separators=(",", ":"))
            ),
            "claim_identity_valid": claim_identity_valid,
            "status": "reconciled" if claim[12] is not None else "pending",
            "event_id": cast(str | None, claim[12]),
        }
        if not claim_identity_valid:
            blockers.append("pending_claim_identity_invalid")
        if claim[12] is None:
            blockers.append("pending_web_evidence_unresolved")
        else:
            try:
                creation_evidence_event_ids = _validated_string_array(claim[14])
                linked_evidence_event_ids = _validated_string_array(claim[15])
                creation_authority = Authority(cast(str, claim[16]))
                linked_authority = Authority(cast(str, claim[17]))
                _parse_timestamp(cast(str, claim[18]))
                canonical_source_system = SourceSystem(cast(str, claim[21]))
                canonical_reconciliation_key = _web_export_reconciliation_key(
                    family_key=cast(str, claim[19]),
                    source_account_id=cast(str, claim[20]),
                    source_system=canonical_source_system,
                    conversation_id=cast(str, claim[22]),
                    message_id=cast(str, claim[23]),
                    message_id_kind=cast(str, claim[24]),
                    parent_message_id=cast(str | None, claim[25]),
                    branch_id=cast(str | None, claim[26]),
                    object_id=cast(str, claim[27]),
                    event_type=cast(str, claim[28]),
                    actor_kind=cast(str, claim[29]),
                    assistant=cast(str | None, claim[30]),
                    authority=cast(str, claim[31]),
                    occurred_at=cast(str | None, claim[32]),
                    scope=cast(str, claim[33]),
                    project_id=cast(str | None, claim[34]),
                    privacy=cast(str, claim[35]),
                    content_digest=cast(str, claim[36]),
                )
                canonical_family_key = _web_export_family_key(
                    source_account_id=cast(str, claim[20]),
                    source_system=canonical_source_system,
                    conversation_id=cast(str, claim[22]),
                    message_id=cast(str, claim[23]),
                    message_id_kind=cast(str, claim[24]),
                )
            except (TypeError, ValueError, RuntimeError) as error:
                raise RuntimeError("pending candidate evidence link is invalid") from error
            pending_claim_state["reconciliation_key"] = cast(str, claim[13])
            pending_claim_state["link_state_digest"] = _sha256_text(
                json.dumps(tuple(claim[13:37]), ensure_ascii=False, separators=(",", ":"))
            )
            link_identity_invalid = (
                linked_evidence_event_ids != evidence_event_ids
                or cast(str, claim[12]) not in linked_evidence_event_ids
                or linked_authority.value != cast(str, candidate[3])
                or not hmac.compare_digest(cast(str, claim[13]), canonical_reconciliation_key)
                or not hmac.compare_digest(cast(str, claim[19]), canonical_family_key)
                or cast(str, claim[19]) != normalized_claim.family_key
                or cast(str, claim[20]) != normalized_claim.source_account_id
                or canonical_source_system != normalized_claim.source_system
                or cast(str, claim[22]) != normalized_claim.conversation_id
                or cast(str, claim[23]) != normalized_claim.message_id
                or cast(str, claim[24]) != "provider_message_id"
                or (
                    normalized_claim.parent_message_id is not None
                    and cast(str | None, claim[25]) != normalized_claim.parent_message_id
                )
                or (
                    normalized_claim.branch_id is not None
                    and cast(str | None, claim[26]) != normalized_claim.branch_id
                )
                or cast(str, claim[35]) != Privacy.INCLUDED.value
                or cast(str, claim[36]) != normalized_claim.content_digest
            )
            if link_identity_invalid:
                blockers.append("pending_candidate_state_invalid")

    proposal_authenticated = False
    proposal_state: dict[str, object] | None = None
    expected_creation_digest = _memory_candidate_creation_digest(
        memory_id=memory_id,
        memory_type=MemoryType(cast(str, candidate[0])),
        statement_digest=cast(str, candidate[2]),
        authority=creation_authority,
        scope=Scope(cast(str, candidate[4])),
        project_id=cast(str | None, candidate[5]),
        evidence_event_ids=creation_evidence_event_ids,
        created_by=cast(str, candidate[8]),
        pending_web_evidence=normalized_claim,
    )
    if proposal is None:
        blockers.append("proposal_authentication_missing")
    else:
        try:
            proposer_kind = ClientKind(cast(str, proposal[3]))
            _parse_timestamp(cast(str, proposal[6]))
            expected_proposal_id = _memory_candidate_proposal_id(
                memory_id=memory_id,
                candidate_creation_digest=expected_creation_digest,
                proposed_by=cast(str, proposal[2]),
                proposer_kind=proposer_kind,
                authorization_scope=cast(str, proposal[4]),
                policy_version=cast(str, proposal[5]),
                created_at=cast(str, proposal[6]),
            )
            proposal_authenticated = (
                cast(str, proposal[0]) == expected_proposal_id
                and hmac.compare_digest(cast(str, proposal[1]), expected_creation_digest)
                and cast(str, proposal[2]) == cast(str, candidate[8])
                and cast(str, proposal[4]) == Capability.MEMORY_PROPOSE_WRITE.value
                and cast(str, proposal[5]) == CANDIDATE_CREATION_POLICY_VERSION
                and cast(str, proposal[6]) == cast(str, candidate[9])
                and candidate_created_at_valid
                and Capability.MEMORY_PROPOSE_WRITE in CLIENT_KIND_CAPABILITIES[proposer_kind]
            )
        except (TypeError, ValueError, RuntimeError):
            proposal_authenticated = False
        if not proposal_authenticated:
            blockers.append("proposal_authentication_invalid")
        proposal_state = {
            "proposal_id": cast(str, proposal[0]),
            "candidate_creation_digest": cast(str, proposal[1]),
            "proposed_by": cast(str, proposal[2]),
            "proposer_kind": cast(str, proposal[3]),
            "authorization_scope": cast(str, proposal[4]),
            "policy_version": cast(str, proposal[5]),
            "created_at": cast(str, proposal[6]),
        }

    if _sha256_text(cast(str, candidate[1])) != cast(str, candidate[2]):
        blockers.append("candidate_statement_digest_invalid")

    event_rows: dict[str, sqlite3.Row] = {}
    if evidence_event_ids:
        placeholders = ",".join("?" for _ in evidence_event_ids)
        rows = connection.execute(
            f"""
            SELECT event.event_id, event.event_type, event.actor_kind, event.assistant,
                   event.authority, event.scope, event.project_id, event.privacy,
                   event.content_digest, event.content_text, event.parser_version,
                   event.correction_id, event.occurred_at, event.ingested_at, access.access
            FROM events_current event
            LEFT JOIN event_access access ON access.event_id = event.event_id
            WHERE event.event_id IN ({placeholders})
            """,
            tuple(evidence_event_ids),
        ).fetchall()
        event_rows = {cast(str, row[0]): row for row in rows}
    if not evidence_event_ids:
        blockers.append("evidence_missing")
    if len(event_rows) != len(evidence_event_ids):
        blockers.append("evidence_missing_or_excluded")

    evidence_states: list[dict[str, object]] = []
    evidence_authorities: list[Authority] = []
    evidence_scopes: list[Scope] = []
    evidence_projects: list[str | None] = []
    for event_id in evidence_event_ids:
        row = event_rows.get(event_id)
        if row is None:
            continue
        state = {
            "event_type": cast(str, row[1]),
            "actor_kind": cast(str, row[2]),
            "assistant": cast(str | None, row[3]),
            "authority": cast(str, row[4]),
            "scope": cast(str, row[5]),
            "project_id": cast(str | None, row[6]),
            "privacy": cast(str, row[7]),
            "content_digest": cast(str, row[8]),
            "content_text": cast(str, row[9]),
            "parser_version": cast(str, row[10]),
        }
        access = cast(str | None, row[14])
        if (
            not state["event_type"]
            or not state["actor_kind"]
            or not state["authority"]
            or not state["content_digest"]
            or not state["parser_version"]
            or state["privacy"] != Privacy.INCLUDED.value
            or access is None
            or (row[12] is None and row[13] is None)
        ):
            blockers.append("evidence_metadata_incomplete")
        evidence_states.append(
            {
                "event_id": event_id,
                "state_digest": event_state_digest(state),
                "access": access,
                "occurred_at": cast(str | None, row[12]),
                "ingested_at": cast(str | None, row[13]),
            }
        )
        evidence_authorities.append(Authority(cast(str, row[4])))
        evidence_scopes.append(Scope(cast(str, row[5])))
        evidence_projects.append(cast(str | None, row[6]))

    candidate_scope = Scope(cast(str, candidate[4]))
    candidate_project = cast(str | None, candidate[5])
    candidate_access = cast(str | None, candidate[10])
    if candidate_access != _access_from_legacy_scope(candidate_scope).value:
        blockers.append("candidate_access_invalid")
    expected_contexts = (
        [{"kind": ContextKind.PROJECT.value, "key": candidate_project}]
        if candidate_scope is Scope.PROJECT and candidate_project is not None
        else []
    )
    if contexts != expected_contexts:
        blockers.append("candidate_context_invalid")
    if evidence_scopes:
        try:
            _validate_proposal_scope(
                candidate_scope,
                candidate_project,
                evidence_scopes,
                evidence_projects,
            )
        except ValueError:
            blockers.append("candidate_scope_invalid")
        if _authority_floor(evidence_authorities).value != cast(str, candidate[3]):
            blockers.append("candidate_authority_invalid")

    decision = classify_record(
        source_system=SourceSystem.CODEX,
        content_text=cast(str, candidate[1]),
        raw_record=cast(str, candidate[1]).encode(),
        max_record_bytes=MAX_PROPOSAL_STATEMENT_BYTES,
    )
    if not decision.accepted:
        blockers.append("candidate_admission_rejected")

    relations: list[dict[str, str]] = []
    if evidence_event_ids:
        placeholders = ",".join("?" for _ in evidence_event_ids)
        relation_rows = connection.execute(
            f"""
            SELECT relation_id, from_event_id, to_event_id, relation_type
            FROM event_relations
            WHERE from_event_id IN ({placeholders}) OR to_event_id IN ({placeholders})
            ORDER BY relation_id
            """,
            (*evidence_event_ids, *evidence_event_ids),
        ).fetchall()
        evidence_set = set(evidence_event_ids)
        for relation in relation_rows:
            relation_type = cast(str, relation[3])
            from_event_id = cast(str, relation[1])
            to_event_id = cast(str, relation[2])
            relations.append(
                {
                    "relation_id": cast(str, relation[0]),
                    "from_event_id": from_event_id,
                    "to_event_id": to_event_id,
                    "relation_type": relation_type,
                }
            )
            if relation_type == "contradiction":
                blockers.append("contradictory_evidence_requires_review")
            if (
                relation_type in {"correction", "supersession"}
                and from_event_id in evidence_set
                and to_event_id not in evidence_set
            ):
                blockers.append("superseded_evidence_requires_current_version")

    duplicate_ids, duplicate_scan_truncated = _candidate_duplicate_ids(
        connection,
        memory_id=memory_id,
        statement=cast(str, candidate[1]),
        memory_type=MemoryType(cast(str, candidate[0])),
        authority=Authority(cast(str, candidate[3])),
        scope=candidate_scope,
        project_id=candidate_project,
        access=candidate_access,
        context_ids=context_ids,
        evidence_event_ids=sorted(evidence_event_ids),
    )
    if duplicate_ids:
        blockers.append("duplicate_candidate")
    basis = {
        "review_policy_version": CANDIDATE_REVIEW_POLICY_VERSION,
        "memory_id": memory_id,
        "memory_type": cast(str, candidate[0]),
        "statement_digest": cast(str, candidate[2]),
        "authority": cast(str, candidate[3]),
        "scope": candidate_scope.value,
        "project_id": candidate_project,
        "temporal_status": cast(str, candidate[6]),
        "evidence_event_ids": evidence_event_ids,
        "access": candidate_access,
        "contexts": contexts,
        "proposal_receipt": proposal_state,
        "pending_claim": pending_claim_state,
        "lifecycle": lifecycle.value,
        "last_transition_id": last_transition_id,
        "review_history": review_history,
        "evidence_states": evidence_states,
        "relations": relations,
        "duplicate_candidate_ids": duplicate_ids,
        "duplicate_scan_truncated": duplicate_scan_truncated,
    }
    basis_digest = _sha256_text(
        json.dumps(basis, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    )
    return {
        "memory_id": memory_id,
        "lifecycle": lifecycle.value,
        "review_basis_digest": basis_digest,
        "review_policy_version": CANDIDATE_REVIEW_POLICY_VERSION,
        "proposal_authenticated": proposal_authenticated,
        "qualification_blockers": sorted(set(blockers)),
        "evidence_event_ids": evidence_event_ids,
        "last_transition_id": last_transition_id,
        "review_transition_count": len(review_history),
    }


def _administration_candidate_record(
    connection: sqlite3.Connection,
    row: sqlite3.Row | tuple[Any, ...],
) -> dict[str, Any]:
    review = _candidate_review_state(connection, cast(str, row[0]))
    return {
        "memory_id": row[0],
        "memory_type": row[1],
        "statement": row[2],
        "statement_digest": row[3],
        "authority": row[4],
        "scope": row[5],
        "project_id": row[6],
        "temporal_status": row[7],
        "evidence_event_ids": _validated_string_array(row[8]),
        "created_by": row[9],
        "created_at": row[10],
        "pending_claim": (
            {
                "claim_id": row[11],
                "status": row[12],
                "event_id": row[13],
            }
            if row[11] is not None
            else None
        ),
        **review,
    }


def _validated_candidate_review_transition_rows(
    connection: sqlite3.Connection,
) -> list[tuple[object, ...]]:
    rows = connection.execute(
        """
        SELECT review_sequence, transition_id, memory_id, operation,
               previous_lifecycle, new_lifecycle,
               candidate_basis_digest, previous_transition_id, review_policy_version,
               authorized_by, authorization_scope, reason_code, created_at
        FROM memory_candidate_review_transitions
        ORDER BY review_sequence
        """,
    ).fetchall()
    sequence_row = connection.execute(
        "SELECT seq FROM sqlite_sequence WHERE name = 'memory_candidate_review_transitions'"
    ).fetchone()
    sequence = 0 if sequence_row is None else sequence_row[0]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence != len(rows)
        or [row[0] for row in rows] != list(range(1, sequence + 1))
    ):
        raise RuntimeError("memory candidate review history is invalid")
    for transition in rows:
        try:
            transition_id = _bounded_text_value(
                cast(str, transition[1]),
                "stored candidate transition id",
                max_bytes=256,
            )
            transition_memory_id = _bounded_text_value(
                cast(str, transition[2]),
                "stored candidate transition memory id",
                max_bytes=256,
            )
            operation = CandidateReviewOperation(cast(str, transition[3]))
            previous = MemoryLifecycle(cast(str, transition[4]))
            new = MemoryLifecycle(cast(str, transition[5]))
            _validate_sha256(cast(str, transition[6]), "stored candidate basis")
            _bounded_text_value(
                cast(str, transition[9]),
                "stored candidate reviewer",
                max_bytes=1024,
            )
            if transition[7] is not None:
                _bounded_text_value(
                    cast(str, transition[7]),
                    "stored previous candidate transition id",
                    max_bytes=256,
                )
            reason = CandidateReviewReason(cast(str, transition[11]))
            _validate_candidate_review_reason(operation, reason)
            created_at = cast(str, transition[12])
            _parse_timestamp(created_at)
            expected_transition_id = _candidate_review_transition_id(
                memory_id=transition_memory_id,
                operation=operation,
                previous_lifecycle=previous,
                new_lifecycle=new,
                candidate_basis_digest=cast(str, transition[6]),
                previous_transition_id=cast(str | None, transition[7]),
                authorized_by=cast(str, transition[9]),
                authorization_scope=cast(str, transition[10]),
                reason_code=reason,
                created_at=created_at,
            )
        except (TypeError, ValueError, RuntimeError) as error:
            raise RuntimeError("memory candidate review history is invalid") from error
        if (
            not hmac.compare_digest(transition_id, expected_transition_id)
            or cast(str, transition[8]) != CANDIDATE_REVIEW_POLICY_VERSION
            or cast(str, transition[10]) != "memory:curate"
        ):
            raise RuntimeError("memory candidate review history is invalid")
    return [tuple(row[1:]) for row in rows]


def _validated_candidate_review_history(
    connection: sqlite3.Connection,
    memory_id: str,
) -> tuple[MemoryLifecycle, str | None, list[dict[str, object]]]:
    history = [
        (transition[0], *transition[2:])
        for transition in _validated_candidate_review_transition_rows(connection)
        if transition[1] == memory_id
    ]
    lifecycle = MemoryLifecycle.CANDIDATE
    last_transition_id: str | None = None
    review_history: list[dict[str, object]] = []
    for transition in history:
        try:
            transition_id = _bounded_text_value(
                cast(str, transition[0]),
                "stored candidate transition id",
                max_bytes=256,
            )
            operation = CandidateReviewOperation(cast(str, transition[1]))
            previous = MemoryLifecycle(cast(str, transition[2]))
            new = MemoryLifecycle(cast(str, transition[3]))
            _validate_sha256(cast(str, transition[4]), "stored candidate basis")
            _bounded_text_value(
                cast(str, transition[7]),
                "stored candidate reviewer",
                max_bytes=1024,
            )
            if transition[5] is not None:
                _bounded_text_value(
                    cast(str, transition[5]),
                    "stored previous candidate transition id",
                    max_bytes=256,
                )
            reason = CandidateReviewReason(cast(str, transition[9]))
            _validate_candidate_review_reason(operation, reason)
            created_at = cast(str, transition[10])
            _parse_timestamp(created_at)
            expected_new = _candidate_review_transition(operation, previous)
            expected_transition_id = _candidate_review_transition_id(
                memory_id=memory_id,
                operation=operation,
                previous_lifecycle=previous,
                new_lifecycle=new,
                candidate_basis_digest=cast(str, transition[4]),
                previous_transition_id=cast(str | None, transition[5]),
                authorized_by=cast(str, transition[7]),
                authorization_scope=cast(str, transition[8]),
                reason_code=reason,
                created_at=created_at,
            )
        except (TypeError, ValueError, RuntimeError) as error:
            raise RuntimeError("memory candidate review history is invalid") from error
        if (
            not hmac.compare_digest(transition_id, expected_transition_id)
            or previous is not lifecycle
            or cast(str | None, transition[5]) != last_transition_id
            or cast(str, transition[6]) != CANDIDATE_REVIEW_POLICY_VERSION
            or cast(str, transition[8]) != "memory:curate"
            or expected_new is not new
        ):
            raise RuntimeError("memory candidate review history is invalid")
        review_history.append(
            {
                "transition_id": transition_id,
                "operation": operation.value,
                "previous_lifecycle": previous.value,
                "new_lifecycle": new.value,
                "candidate_basis_digest": cast(str, transition[4]),
                "previous_transition_id": cast(str | None, transition[5]),
                "review_policy_version": cast(str, transition[6]),
                "authorized_by": cast(str, transition[7]),
                "authorization_scope": cast(str, transition[8]),
                "reason_code": reason.value,
                "created_at": created_at,
            }
        )
        lifecycle = new
        last_transition_id = transition_id
    return lifecycle, last_transition_id, review_history


def _candidate_duplicate_ids(
    connection: sqlite3.Connection,
    *,
    memory_id: str,
    statement: str,
    memory_type: MemoryType,
    authority: Authority,
    scope: Scope,
    project_id: str | None,
    access: str | None,
    context_ids: list[str],
    evidence_event_ids: list[str],
) -> tuple[list[str], bool]:
    if context_ids:
        context_placeholders = ",".join("?" for _ in context_ids)
        context_clause = f"""
          AND (
            SELECT COUNT(*)
            FROM memory_candidate_contexts context_count
            WHERE context_count.memory_id = candidate.memory_id
          ) = ?
          AND NOT EXISTS (
            SELECT 1
            FROM memory_candidate_contexts other_context
            WHERE other_context.memory_id = candidate.memory_id
              AND other_context.context_id NOT IN ({context_placeholders})
          )
        """
        context_parameters: tuple[object, ...] = (len(context_ids), *context_ids)
    else:
        context_clause = """
          AND NOT EXISTS (
            SELECT 1
            FROM memory_candidate_contexts other_context
            WHERE other_context.memory_id = candidate.memory_id
          )
        """
        context_parameters = ()
    rows = connection.execute(
        f"""
        SELECT candidate.memory_id, candidate.statement, candidate.scope,
               candidate.project_id, candidate_access.access,
               candidate.evidence_event_ids_json
        FROM memory_candidates candidate
        LEFT JOIN memory_candidate_access candidate_access
          ON candidate_access.memory_id = candidate.memory_id
        WHERE candidate.memory_id != ?
          AND candidate.memory_type = ?
          AND candidate.statement_digest = ?
          AND candidate.authority = ?
          AND candidate.scope = ?
          AND candidate.project_id IS ?
          AND candidate_access.access IS ?
          {context_clause}
        ORDER BY candidate.memory_id
        """,
        (
            memory_id,
            memory_type.value,
            _sha256_text(statement),
            authority.value,
            scope.value,
            project_id,
            access,
            *context_parameters,
        ),
    )
    truncated = False
    duplicates: list[str] = []
    for row in rows:
        other_id = cast(str, row[0])
        if cast(str, row[1]) != statement or cast(str | None, row[4]) != access:
            continue
        try:
            other_evidence_event_ids = _validated_string_array(row[5])
        except RuntimeError:
            continue
        if (
            any(not event_id for event_id in other_evidence_event_ids)
            or len(set(other_evidence_event_ids)) != len(other_evidence_event_ids)
            or sorted(other_evidence_event_ids) != evidence_event_ids
        ):
            continue
        other_lifecycle, _, _ = _validated_candidate_review_history(
            connection,
            other_id,
        )
        if other_lifecycle is MemoryLifecycle.REJECTED:
            continue
        if len(duplicates) == MAX_ADMIN_ROWS:
            truncated = True
            break
        duplicates.append(other_id)
    return duplicates, truncated


def _candidate_review_transition(
    operation: CandidateReviewOperation,
    previous: MemoryLifecycle,
) -> MemoryLifecycle:
    transitions = {
        (CandidateReviewOperation.QUALIFY, MemoryLifecycle.CANDIDATE): (MemoryLifecycle.QUALIFIED),
        (CandidateReviewOperation.APPROVE, MemoryLifecycle.QUALIFIED): (MemoryLifecycle.APPROVED),
        (CandidateReviewOperation.REJECT, MemoryLifecycle.CANDIDATE): MemoryLifecycle.REJECTED,
        (CandidateReviewOperation.REJECT, MemoryLifecycle.QUALIFIED): MemoryLifecycle.REJECTED,
    }
    try:
        return transitions[(operation, previous)]
    except KeyError as error:
        raise ValueError(
            f"candidate cannot transition from {previous.value} with {operation.value}"
        ) from error


def _candidate_review_transition_id(
    *,
    memory_id: str,
    operation: CandidateReviewOperation,
    previous_lifecycle: MemoryLifecycle,
    new_lifecycle: MemoryLifecycle,
    candidate_basis_digest: str,
    previous_transition_id: str | None,
    authorized_by: str,
    authorization_scope: str,
    reason_code: CandidateReviewReason,
    created_at: str,
) -> str:
    return _stable_id(
        "memory_candidate_review",
        memory_id,
        operation.value,
        previous_lifecycle.value,
        new_lifecycle.value,
        candidate_basis_digest,
        previous_transition_id or "",
        CANDIDATE_REVIEW_POLICY_VERSION,
        authorized_by,
        authorization_scope,
        reason_code.value,
        created_at,
    )


def _validate_candidate_review_reason(
    operation: CandidateReviewOperation,
    reason: CandidateReviewReason,
) -> None:
    allowed = {
        CandidateReviewOperation.QUALIFY: {
            CandidateReviewReason.DETERMINISTIC_CHECKS_PASSED,
        },
        CandidateReviewOperation.APPROVE: {CandidateReviewReason.OWNER_APPROVED},
        CandidateReviewOperation.REJECT: {
            CandidateReviewReason.DUPLICATE,
            CandidateReviewReason.INCORRECT,
            CandidateReviewReason.OUT_OF_SCOPE,
            CandidateReviewReason.SUPERSEDED,
            CandidateReviewReason.INSUFFICIENT_EVIDENCE,
        },
    }
    if reason not in allowed[operation]:
        raise ValueError("candidate review reason is invalid for the requested transition")


def _authority_floor(authorities: Iterable[Authority]) -> Authority:
    order = {
        Authority.EXTERNAL_CONTENT: 0,
        Authority.ASSISTANT_OUTPUT: 1,
        Authority.TOOL_OBSERVATION: 2,
        Authority.USER_ASSERTION: 3,
        Authority.SYSTEM_POLICY: 4,
        Authority.ADMIN_APPROVED_POLICY: 5,
    }
    values = list(authorities)
    if not values:
        raise ValueError("authority requires evidence")
    return min(values, key=order.__getitem__)


def _memory_candidate_creation_digest(
    *,
    memory_id: str,
    memory_type: MemoryType,
    statement_digest: str,
    authority: Authority,
    scope: Scope,
    project_id: str | None,
    evidence_event_ids: Sequence[str],
    created_by: str,
    pending_web_evidence: _NormalizedPendingWebEvidenceClaim | None,
) -> str:
    payload = {
        "policy_version": CANDIDATE_CREATION_POLICY_VERSION,
        "memory_id": memory_id,
        "memory_type": memory_type.value,
        "statement_digest": statement_digest,
        "authority": authority.value,
        "scope": scope.value,
        "project_id": project_id,
        "evidence_event_ids": list(evidence_event_ids),
        "created_by": created_by,
        "pending_web_evidence": (
            {
                "source_account_id": pending_web_evidence.source_account_id,
                "source_system": pending_web_evidence.source_system.value,
                "family_key": pending_web_evidence.family_key,
                "conversation_id": pending_web_evidence.conversation_id,
                "message_id": pending_web_evidence.message_id,
                "parent_message_id": pending_web_evidence.parent_message_id,
                "branch_id": pending_web_evidence.branch_id,
                "content_digest": pending_web_evidence.content_digest,
            }
            if pending_web_evidence is not None
            else None
        ),
    }
    return _sha256_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    )


def _memory_candidate_proposal_id(
    *,
    memory_id: str,
    candidate_creation_digest: str,
    proposed_by: str,
    proposer_kind: ClientKind,
    authorization_scope: str,
    policy_version: str,
    created_at: str,
) -> str:
    return _stable_id(
        "memory_candidate_proposal",
        memory_id,
        candidate_creation_digest,
        proposed_by,
        proposer_kind.value,
        authorization_scope,
        policy_version,
        created_at,
    )


def _validate_proposal_scope(
    requested_scope: Scope,
    requested_project_id: str | None,
    evidence_scopes: Sequence[Scope],
    evidence_projects: Sequence[str | None],
) -> None:
    if requested_scope is Scope.USER_GLOBAL:
        if any(scope is not Scope.USER_GLOBAL for scope in evidence_scopes):
            raise ValueError(
                "project, session, or private evidence cannot propose user-global memory"
            )
        return
    if requested_scope is Scope.PROJECT:
        disallowed = {
            project
            for scope, project in zip(evidence_scopes, evidence_projects, strict=False)
            if scope is Scope.PROJECT and project != requested_project_id
        }
        if disallowed:
            raise ValueError("evidence from another project cannot propose this project memory")
        if any(scope not in (Scope.USER_GLOBAL, Scope.PROJECT) for scope in evidence_scopes):
            raise ValueError("session or assistant-private evidence cannot widen to project scope")
        return
    if any(scope is not requested_scope for scope in evidence_scopes):
        raise ValueError("evidence scope cannot be widened by a memory proposal")


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
