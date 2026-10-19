from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

MAX_PROPOSAL_STATEMENT_BYTES = 16 * 1024
MAX_PROPOSAL_EVIDENCE_EVENTS = 100
MAX_PROPOSAL_EVENT_ID_BYTES = 256
MAX_PENDING_EVIDENCE_ID_BYTES = 4096


class SourceSystem(StrEnum):
    CODEX = "codex"
    CLAUDE_CODE = "claude_code"
    GROK_BUILD = "grok_build"
    CHATGPT_WEB = "chatgpt_web"
    CLAUDE_WEB = "claude_web"
    GROK_WEB = "grok_web"


class SourceKind(StrEnum):
    INTERACTIVE = "interactive"
    SUBAGENT = "subagent"
    AUTOMATION = "automation"
    UNKNOWN = "unknown"


class Authority(StrEnum):
    USER_ASSERTION = "user_assertion"
    ASSISTANT_OUTPUT = "assistant_output"
    TOOL_OBSERVATION = "tool_observation"
    EXTERNAL_CONTENT = "external_content"
    SYSTEM_POLICY = "system_policy"
    ADMIN_APPROVED_POLICY = "admin_approved_policy"


class Scope(StrEnum):
    USER_GLOBAL = "user_global"
    PROJECT = "project"
    ASSISTANT_PRIVATE = "assistant_private"
    SESSION = "session"


class Access(StrEnum):
    OWNER = "owner"
    ASSISTANT_PRIVATE = "assistant_private"
    SESSION = "session"


class ClientKind(StrEnum):
    ASSISTANT = "assistant"
    COLLECTOR = "collector"
    SCHEDULER = "scheduler"
    LOCAL_ADMIN = "local_admin"


class Capability(StrEnum):
    MEMORY_SEARCH = "memory:search"
    MEMORY_EVIDENCE_READ = "memory:evidence-read"
    MEMORY_STATUS = "memory:status"
    MEMORY_PROPOSE_WRITE = "memory:propose-write"
    SOURCE_UPLOAD = "source:upload"
    CLIENT_ADMIN = "client:admin"


class DeletionKind(StrEnum):
    CONVERSATION = "conversation"
    SOURCE_ACCOUNT = "source_account"
    WEB_CONTAINERS = "web_containers"
    NO_MEMORY_RECORDS = "no_memory_records"
    OBSOLETE_OBSERVATIONS = "obsolete_observations"


@dataclass(frozen=True, order=True)
class ObservationRetirement:
    event_id: str
    replacement_event_id: str


CLIENT_KIND_CAPABILITIES = {
    ClientKind.ASSISTANT: frozenset(
        {
            Capability.MEMORY_SEARCH,
            Capability.MEMORY_EVIDENCE_READ,
            Capability.MEMORY_STATUS,
            Capability.MEMORY_PROPOSE_WRITE,
        }
    ),
    ClientKind.COLLECTOR: frozenset({Capability.SOURCE_UPLOAD, Capability.MEMORY_STATUS}),
    ClientKind.SCHEDULER: frozenset({Capability.SOURCE_UPLOAD, Capability.MEMORY_STATUS}),
    ClientKind.LOCAL_ADMIN: frozenset(Capability),
}


class ContextKind(StrEnum):
    PROJECT = "project"
    TOPIC = "topic"
    PERSON_OR_RELATIONSHIP = "person_or_relationship"
    LIFE_AREA = "life_area"
    CUSTOM = "custom"


class Privacy(StrEnum):
    INCLUDED = "included"
    PRIVATE = "private"
    NO_MEMORY = "no_memory"


class QueryMode(StrEnum):
    WHERE_DID_I_LEAVE_OFF = "where_did_i_leave_off"
    WHAT_DID_I_SAY = "what_did_i_say"
    WHAT_DID_I_THINK = "what_did_i_think"
    WHAT_IS_CURRENT = "what_is_current"
    HOW_DID_IT_CHANGE = "how_did_it_change"
    OPEN_THREADS = "open_threads"
    FIND_EVIDENCE = "find_evidence"


class RetrievalControl(StrEnum):
    AUTO = "auto"
    FORCE = "force"
    SUPPRESS = "suppress"


class MemoryType(StrEnum):
    EPISODIC_EVENT = "episodic_event"
    CLAIM = "claim"
    PREFERENCE = "preference"
    DECISION = "decision"
    TASK = "task"
    PROCEDURE = "procedure"
    ARTIFACT = "artifact"


class MemoryLifecycle(StrEnum):
    CANDIDATE = "candidate"
    QUALIFIED = "qualified"
    APPROVED = "approved"
    REJECTED = "rejected"


class CandidateReviewOperation(StrEnum):
    QUALIFY = "qualify"
    APPROVE = "approve"
    REJECT = "reject"


class CandidateReviewReason(StrEnum):
    DETERMINISTIC_CHECKS_PASSED = "deterministic_checks_passed"
    OWNER_APPROVED = "owner_approved"
    DUPLICATE = "duplicate"
    INCORRECT = "incorrect"
    OUT_OF_SCOPE = "out_of_scope"
    SUPERSEDED = "superseded"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass(frozen=True)
class ContextFilter:
    kind: ContextKind
    key: str

    def __post_init__(self) -> None:
        normalized = self.key.strip()
        if not normalized:
            raise ValueError("context filter key is required")
        if len(normalized.encode("utf-8")) > 512:
            raise ValueError("context filter key exceeds 512 bytes")
        if "\x00" in normalized:
            raise ValueError("context filter key must not contain a null byte")
        object.__setattr__(self, "key", normalized)

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind.value, "key": self.key}


@dataclass(frozen=True)
class HistoryBase:
    thread_id: str
    end_ordinal_exclusive: int
    end_byte_offset: int


@dataclass(frozen=True)
class ParsedRecord:
    raw_record: bytes
    record_ordinal: int
    byte_start: int
    byte_end: int
    event_type: str
    actor_kind: str
    assistant: str | None
    authority: Authority
    content_text: str
    occurred_at: str | None
    message_id: str | None
    parent_message_id: str | None
    branch_id: str | None
    turn_id: str | None = None
    message_id_kind: str | None = None


@dataclass(frozen=True)
class ParseResult:
    source_system: SourceSystem
    parser_name: str
    parser_version: str
    path: Path
    file_digest: str
    file_size: int
    file_mtime_ns: int
    conversation_id: str
    branch_id: str | None
    captured_at: str | None
    history_base: HistoryBase | None
    records: tuple[ParsedRecord, ...]
    unknown_record_types: tuple[str, ...]
    malformed_records: int
    source_kind: SourceKind = SourceKind.UNKNOWN
    source_label: str | None = None
    parent_conversation_id: str | None = None
    segment_start_ordinal: int = 0
    segment_start_byte: int = 0
    segment_end_ordinal_exclusive: int = 0
    segment_end_byte: int = 0
    start_prefix_digest: str = ""
    end_prefix_digest: str = ""
    observed_file_size: int = 0
    schema_fingerprint: str = ""
    schema_descriptors: tuple[str, ...] = ()


@dataclass(frozen=True)
class CollectorProvenance:
    source_client: str
    source_client_version: str
    capture_capability: str
    adapter_name: str
    adapter_version: str
    schema_fingerprint: str


@dataclass(frozen=True)
class SourceSchemaProvenance:
    source_client: str
    source_client_version: str
    capture_capability: str
    adapter_name: str
    adapter_version: str
    schema_fingerprint: str
    parser_versions: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class WebExportArchiveMemberProvenance:
    archive_member_index: int
    locator: str
    name_sha256: str
    content_sha256: str
    compressed_bytes: int
    byte_length: int
    compression_method: int
    media_type_hint: str


@dataclass(frozen=True)
class WebExportAttachmentReferenceProvenance:
    archive_member_index: int
    conversation_index: int
    source_record_ordinal: int
    reference_ordinal: int
    reference_sha256: str


@dataclass(frozen=True)
class WebExportBatchProvenance:
    manifest_sha256: str
    code_revision: str
    prepared_at: str
    archive_sha256: str
    archive_byte_length: int
    selected_member_name_sha256: str
    selected_member_sha256: str
    selected_member_byte_length: int
    archive_members: tuple[WebExportArchiveMemberProvenance, ...]
    attachment_references: tuple[WebExportAttachmentReferenceProvenance, ...] = ()
    extracted_attachment_indices: tuple[int, ...] = ()


@dataclass(frozen=True)
class WebExportConversationObservation:
    batch_id: str
    conversation_index: int
    source_byte_start: int
    source_byte_end: int
    conversation_sha256: str
    source_locator: str


@dataclass(frozen=True)
class PendingWebEvidenceClaim:
    source_account_id: str
    source_system: SourceSystem
    conversation_id: str
    message_id: str
    parent_message_id: str | None
    branch_id: str | None
    content_text: str


@dataclass(frozen=True)
class SourceCursor:
    source_stream_id: str
    conversation_id: str
    source_kind: SourceKind
    next_record_ordinal: int
    next_byte_offset: int
    prefix_digest: str


class SourceCursorGap(RuntimeError):
    def __init__(self, cursor: SourceCursor) -> None:
        super().__init__("parsed source segment leaves a gap after the registered cursor")
        self.cursor = cursor


@dataclass(frozen=True)
class VerifiedClient:
    client_id: str
    kind: ClientKind
    capabilities: tuple[Capability, ...]
    expires_at_epoch: int
    device_id: str | None


@dataclass(frozen=True)
class UploadReceipt:
    batch_id: str
    status: str
    source_file_id: str
    conversation_id: str
    event_count: int
    quarantined_records: int
    quarantine_reasons: dict[str, int]
    created_at: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"batch:[0-9a-f]{64}", self.batch_id) is None:
            raise ValueError("upload receipt batch id is invalid")
        if self.status not in {"applied", "already_applied"}:
            raise ValueError("upload receipt status is invalid")
        if re.fullmatch(r"source_segment:[0-9a-f]{64}", self.source_file_id) is None:
            raise ValueError("upload receipt source file id is invalid")
        for field, value, limit in (
            ("conversation id", self.conversation_id, 4096),
            ("created at", self.created_at, 128),
        ):
            if not value or value != value.strip() or len(value.encode()) > limit:
                raise ValueError(f"upload receipt {field} is invalid")
        try:
            created_at = datetime.fromisoformat(self.created_at)
        except ValueError as error:
            raise ValueError("upload receipt created at is invalid") from error
        if created_at.utcoffset() is None:
            raise ValueError("upload receipt created at is invalid")
        for field, value in (
            ("event count", self.event_count),
            ("quarantined records", self.quarantined_records),
        ):
            if isinstance(value, bool) or value < 0:
                raise ValueError(f"upload receipt {field} is invalid")
        if any(
            not reason
            or reason != reason.strip()
            or len(reason.encode()) > 256
            or isinstance(count, bool)
            or count < 0
            for reason, count in self.quarantine_reasons.items()
        ):
            raise ValueError("upload receipt quarantine reasons are invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "status": self.status,
            "source_file_id": self.source_file_id,
            "conversation_id": self.conversation_id,
            "event_count": self.event_count,
            "quarantined_records": self.quarantined_records,
            "quarantine_reasons": self.quarantine_reasons,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> UploadReceipt:
        expected = {
            "batch_id",
            "status",
            "source_file_id",
            "conversation_id",
            "event_count",
            "quarantined_records",
            "quarantine_reasons",
            "created_at",
        }
        if set(value) != expected:
            raise ValueError("upload receipt fields are invalid")
        strings: dict[str, str] = {}
        for field in ("batch_id", "status", "source_file_id", "conversation_id", "created_at"):
            item = value[field]
            if not isinstance(item, str):
                raise ValueError(f"upload receipt {field} is invalid")
            strings[field] = item
        counts: dict[str, int] = {}
        for field in ("event_count", "quarantined_records"):
            item = value[field]
            if isinstance(item, bool) or not isinstance(item, int):
                raise ValueError(f"upload receipt {field} is invalid")
            counts[field] = item
        raw_reasons = value["quarantine_reasons"]
        if not isinstance(raw_reasons, dict):
            raise ValueError("upload receipt quarantine reasons are invalid")
        reasons: dict[str, int] = {}
        for reason, count in cast(dict[object, object], raw_reasons).items():
            if not isinstance(reason, str) or isinstance(count, bool) or not isinstance(count, int):
                raise ValueError("upload receipt quarantine reasons are invalid")
            reasons[reason] = count
        return cls(
            batch_id=strings["batch_id"],
            status=strings["status"],
            source_file_id=strings["source_file_id"],
            conversation_id=strings["conversation_id"],
            event_count=counts["event_count"],
            quarantined_records=counts["quarantined_records"],
            quarantine_reasons=reasons,
            created_at=strings["created_at"],
        )


@dataclass(frozen=True)
class ExclusionReceipt:
    record_ordinal: int
    byte_start: int
    byte_end: int
    reason: str


@dataclass(frozen=True)
class AdmissionDecision:
    accepted: bool
    privacy: Privacy
    reason: str


@dataclass(frozen=True)
class IngestionReport:
    source_file_id: str
    source_system: SourceSystem
    conversation_id: str
    status: str
    inserted_events: int
    existing_events: int
    quarantined_records: int
    quarantine_reasons: dict[str, int]


@dataclass(frozen=True)
class SearchResult:
    event_id: str
    content_text: str
    event_type: str
    actor_kind: str
    assistant: str | None
    authority: str
    scope: str
    project_id: str | None
    conversation_id: str
    branch_id: str | None
    occurred_at: str | None
    source_system: str
    source_object_id: str
    record_ordinal: int
    byte_start: int
    byte_end: int
    rank: float
    correction_id: str | None = None
    corrected_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "content_text": self.content_text,
            "event_type": self.event_type,
            "actor_kind": self.actor_kind,
            "assistant": self.assistant,
            "authority": self.authority,
            "scope": self.scope,
            "project_id": self.project_id,
            "conversation_id": self.conversation_id,
            "branch_id": self.branch_id,
            "occurred_at": self.occurred_at,
            "source_system": self.source_system,
            "source_object_id": self.source_object_id,
            "record_ordinal": self.record_ordinal,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "rank": self.rank,
            "correction_id": self.correction_id,
            "corrected_at": self.corrected_at,
        }


class EvidencePreview(TypedDict):
    strategy: Literal["complete", "query_snippet", "prefix"]
    truncated: bool
    total_utf8_bytes: int


@dataclass(frozen=True)
class RetrievalCandidate:
    event_id: str
    score: float

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("retrieval candidate event id is required")
        if not math.isfinite(self.score):
            raise ValueError("retrieval candidate score must be finite")


@dataclass(frozen=True)
class EvidenceRelation:
    from_event_id: str
    to_event_id: str
    relation_type: str


@dataclass(frozen=True)
class EventCorrection:
    event_id: str
    expected_state_digest: str
    event_type: str
    actor_kind: str
    assistant: str | None
    authority: Authority
    scope: Scope
    project_id: str | None
    privacy: Privacy
    content_text: str
    parser_version: str
    reason: str
