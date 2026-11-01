from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NoReturn, cast
from uuid import UUID

from cross_assistant_memory.admission import classify_record
from cross_assistant_memory.grok_bot_outward import (
    StructuredRequestKind,
    canonical_outward_request,
)
from cross_assistant_memory.models import (
    Authority,
    CollectorProvenance,
    ParsedRecord,
    ParseResult,
    SourceKind,
    SourceSystem,
)
from cross_assistant_memory.parsers.common import native_jsonl_schema_fingerprint

if TYPE_CHECKING:
    from cross_assistant_memory.collector import CollectorNodeConfig
    from cross_assistant_memory.collector_queue import CollectorQueue
    from cross_assistant_memory.collector_runtime import FlushResult, UploadTransport
    from cross_assistant_memory.grok_bot_transcript import TranscriptProjection

PARSER_NAME = "grok-bot-native-observation"
PARSER_VERSION = "0.1.0"
STRUCTURED_PARSER_VERSION = "0.2.0"
CAPTURE_CAPABILITY = "filtered-native-transcript-observation"
SOURCE_LABEL = "grok_bot_personal_app_observation"
ADAPTER_NAME = "cross-memory-grok-bot-collector"
ADAPTER_VERSION = "0.1.0"
MAX_CAPTURE_BYTES = 128 * 1024
MAX_TEXT_BYTES = 64 * 1024
_EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()
_FIELDS = frozenset(
    {
        "format_version",
        "bot_id",
        "surface",
        "kind",
        "native_tool_call_id",
        "content_text",
        "end_turn",
        "delivery",
        "native_conversation_id",
        "native_author_id",
        "native_occurred_at",
    }
)


@dataclass(frozen=True)
class GrokBotCaptureScope:
    source_account_id: str
    bot_ids: tuple[str, ...]
    collector_bot_id: str
    excluded_bot_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.source_account_id) is not str
            or re.fullmatch(r"source_account:[0-9a-f]{64}", self.source_account_id) is None
            or type(self.bot_ids) is not tuple
            or not 1 <= len(self.bot_ids) <= 64
            or type(self.excluded_bot_ids) is not tuple
            or len(self.excluded_bot_ids) > 64
        ):
            raise ValueError("Grok Bot capture enrollment is invalid")
        try:
            for identifier in (self.collector_bot_id, *self.bot_ids, *self.excluded_bot_ids):
                if type(identifier) is not str or str(UUID(identifier)) != identifier:
                    raise ValueError("invalid native target")
        except ValueError:
            raise ValueError("Grok Bot capture target identifiers are invalid") from None
        if (
            len(set(self.bot_ids)) != len(self.bot_ids)
            or len(set(self.excluded_bot_ids)) != len(self.excluded_bot_ids)
            or self.collector_bot_id in self.bot_ids
            or set(self.bot_ids) & set(self.excluded_bot_ids)
        ):
            raise ValueError("Grok Bot capture enrollment includes excluded or duplicate targets")

    def allows(self, bot_id: str) -> bool:
        return (
            bot_id in self.bot_ids
            and bot_id != self.collector_bot_id
            and bot_id not in self.excluded_bot_ids
        )


@dataclass(frozen=True)
class CapturePageResult:
    pending_replies: int
    already_acknowledged: int
    excluded_replies: int
    source_bytes: int
    source_sha256: str
    before: int | None
    coverage: Literal["user_text_and_outward_requests"] = "user_text_and_outward_requests"
    pending_user_texts: int = 0
    excluded_user_texts: int = 0
    question_requests: int = 0
    attachment_references: int = 0


def capture_transcript_page(
    queue: CollectorQueue,
    data: bytes,
    *,
    bot_id: str,
    scope: GrokBotCaptureScope,
    now_epoch: int | None = None,
) -> CapturePageResult:
    from cross_assistant_memory.collector_queue import source_key_for
    from cross_assistant_memory.uploads import parse_upload_batch

    projection, excluded_users, bodies = transcript_page_uploads(data, bot_id=bot_id, scope=scope)
    pending = pending_users = acknowledged = 0
    for body, is_reply in bodies:
        batch = parse_upload_batch(body)
        source_key = source_key_for(
            SourceSystem.GROK_BOT, scope.source_account_id, batch.source_path_hash
        )
        cursor = queue.cursor(source_key)
        if cursor is not None and (
            cursor.conversation_id == batch.parsed.conversation_id
            and cursor.source_kind is batch.parsed.source_kind
            and cursor.next_record_ordinal == batch.parsed.segment_end_ordinal_exclusive
            and cursor.next_byte_offset == batch.parsed.segment_end_byte
            and cursor.prefix_digest == batch.parsed.end_prefix_digest
        ):
            acknowledged += 1
            continue
        queue.enqueue_upload(body, now_epoch=now_epoch)
        if is_reply:
            pending += 1
        else:
            pending_users += 1
    return CapturePageResult(
        pending,
        acknowledged,
        projection.excluded_replies,
        projection.source_bytes,
        projection.source_sha256,
        projection.inspection.before,
        pending_user_texts=pending_users,
        excluded_user_texts=excluded_users,
        question_requests=sum(item.kind == "question_request" for item in projection.replies),
        attachment_references=sum(
            item.kind == "attachment_reference" for item in projection.replies
        ),
    )


def transcript_page_uploads(
    data: bytes, *, bot_id: str, scope: GrokBotCaptureScope
) -> tuple[TranscriptProjection, int, tuple[tuple[bytes, bool], ...]]:
    from cross_assistant_memory.grok_bot_transcript import (
        project_transcript_page,
        project_user_texts,
    )

    if type(scope) is not GrokBotCaptureScope or not scope.allows(bot_id):
        raise PermissionError("Grok Bot target is not enrolled for capture")
    projection = project_transcript_page(data, expected_bot_id=bot_id)
    user_texts, excluded_users = project_user_texts(data, expected_bot_id=bot_id)
    # Validate every eligible record before any queue write; retain no native internals.
    bodies = tuple(
        (
            build_grok_bot_capture_upload(
                (
                    GrokBotReplyObservation(
                        bot_id, reply.native_tool_call_id, reply.content_text, reply.end_turn
                    )
                    if reply.kind == "reply_request"
                    else GrokBotStructuredRequestObservation(
                        bot_id, reply.native_tool_call_id, reply.content_text, kind=reply.kind
                    )
                ),
                source_account_id=scope.source_account_id,
            ),
            True,
        )
        for reply in projection.replies
    ) + tuple(
        (
            build_grok_bot_capture_upload(
                GrokBotUserTextObservation(bot_id, text), source_account_id=scope.source_account_id
            ),
            False,
        )
        for text in user_texts
    )
    return projection, excluded_users, bodies


def flush_queued_grok_bot_capture(
    queue: CollectorQueue,
    node: CollectorNodeConfig,
    *,
    scope: GrokBotCaptureScope,
    transport: UploadTransport | None = None,
    limit: int = 4,
    now_epoch: int | None = None,
    preserve_sent_artifacts: bool = False,
) -> FlushResult:
    from cross_assistant_memory.collector_queue import QueueFailureCode
    from cross_assistant_memory.collector_runtime import flush_capture_uploads, post_upload_batch
    from cross_assistant_memory.uploads import (
        UploadCursorGap,
        UploadPublicationPending,
        parse_upload_batch,
    )

    if type(scope) is not GrokBotCaptureScope:
        raise ValueError("Grok Bot capture enrollment is required")
    send = post_upload_batch if transport is None else transport

    def authorized_send(
        node: CollectorNodeConfig, credential: str, body: bytes
    ) -> QueueFailureCode | UploadCursorGap | UploadPublicationPending | None:
        batch = parse_upload_batch(body)
        if (
            batch.parsed.source_system is not SourceSystem.GROK_BOT
            or batch.source_account_id != scope.source_account_id
            or len(batch.parsed.records) != 1
            or (batch.native_attachments and not preserve_sent_artifacts)
        ):
            return QueueFailureCode.SOURCE_EXCLUDED
        observation = parse_grok_bot_capture_record(batch.parsed.records[0].raw_record)
        if not scope.allows(observation.bot_id):
            return QueueFailureCode.SOURCE_EXCLUDED
        return send(node, credential, body)

    return flush_capture_uploads(
        queue,
        node,
        source_system=SourceSystem.GROK_BOT,
        source_account_id=scope.source_account_id,
        transport=authorized_send,
        limit=limit,
        now_epoch=now_epoch,
    )


@dataclass(frozen=True)
class GrokBotReplyObservation:
    bot_id: str
    native_tool_call_id: str
    content_text: str = field(repr=False)
    end_turn: bool | None
    format_version: Literal[1] = 1
    surface: Literal["operator_enrolled_personal_app_chat"] = "operator_enrolled_personal_app_chat"
    kind: Literal["reply_request"] = "reply_request"
    delivery: Literal["requested_not_verified"] = "requested_not_verified"
    native_conversation_id: None = None
    native_author_id: None = None
    native_occurred_at: None = None

    def __post_init__(self) -> None:
        try:
            valid_id = type(self.bot_id) is str and str(UUID(self.bot_id)) == self.bot_id
        except ValueError:
            valid_id = False
        if not valid_id:
            raise ValueError("Grok Bot capture target identifier is invalid")
        if (
            type(self.format_version) is not int
            or self.format_version != 1
            or self.surface != "operator_enrolled_personal_app_chat"
            or self.kind != "reply_request"
            or self.delivery != "requested_not_verified"
            or self.native_conversation_id is not None
            or self.native_author_id is not None
            or self.native_occurred_at is not None
            or (self.end_turn is not None and type(self.end_turn) is not bool)
        ):
            raise ValueError("Grok Bot capture scope or provenance is unsupported")
        if (
            type(self.native_tool_call_id) is not str
            or re.fullmatch(r"[A-Za-z0-9_:-]{1,256}", self.native_tool_call_id) is None
            or type(self.content_text) is not str
            or not self.content_text.strip()
        ):
            raise ValueError("Grok Bot capture reply fields are invalid")
        try:
            if len(self.content_text.encode("utf-8")) > MAX_TEXT_BYTES:
                raise ValueError("Grok Bot capture text exceeds its byte limit")
            raw = self.canonical_bytes()
        except UnicodeError:
            raise ValueError("Grok Bot capture text encoding is invalid") from None
        decision = classify_record(
            SourceSystem.GROK_BOT, self.content_text, raw, max_record_bytes=MAX_CAPTURE_BYTES
        )
        if not decision.accepted:
            raise ValueError("Grok Bot capture failed privacy admission")

    @property
    def conversation_id(self) -> str:
        # Internal source scope, deliberately not a provider conversation identifier.
        return f"grok-bot-app:{self.bot_id}"

    def as_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "bot_id": self.bot_id,
            "surface": self.surface,
            "kind": self.kind,
            "native_tool_call_id": self.native_tool_call_id,
            "content_text": self.content_text,
            "end_turn": self.end_turn,
            "delivery": self.delivery,
            "native_conversation_id": self.native_conversation_id,
            "native_author_id": self.native_author_id,
            "native_occurred_at": self.native_occurred_at,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


@dataclass(frozen=True)
class GrokBotUserTextObservation:
    bot_id: str
    content_text: str = field(repr=False)
    format_version: Literal[1] = 1
    surface: Literal["operator_enrolled_personal_app_chat"] = "operator_enrolled_personal_app_chat"
    kind: Literal["user_role_text"] = "user_role_text"
    native_tool_call_id: None = None
    end_turn: None = None
    delivery: Literal["not_applicable"] = "not_applicable"
    native_conversation_id: None = None
    native_author_id: None = None
    native_occurred_at: None = None

    def __post_init__(self) -> None:
        try:
            if type(self.bot_id) is not str or str(UUID(self.bot_id)) != self.bot_id:
                raise ValueError("invalid target")
            if (
                type(self.format_version) is not int
                or self.format_version != 1
                or self.surface != "operator_enrolled_personal_app_chat"
                or self.kind != "user_role_text"
                or self.native_tool_call_id is not None
                or self.end_turn is not None
                or self.delivery != "not_applicable"
                or self.native_conversation_id is not None
                or self.native_author_id is not None
                or self.native_occurred_at is not None
                or type(self.content_text) is not str
                or not self.content_text.strip()
                or len(self.content_text.encode("utf-8")) > MAX_TEXT_BYTES
            ):
                raise ValueError("invalid user-role observation")
            decision = classify_record(
                SourceSystem.GROK_BOT,
                self.content_text,
                self.canonical_bytes(),
                max_record_bytes=MAX_CAPTURE_BYTES,
            )
            if not decision.accepted:
                raise ValueError("privacy refusal")
        except (ValueError, UnicodeError):
            raise ValueError("Grok Bot user-role observation is invalid or excluded") from None

    @property
    def conversation_id(self) -> str:
        return f"grok-bot-app:{self.bot_id}"

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            asdict(self), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


@dataclass(frozen=True)
class GrokBotStructuredRequestObservation:
    bot_id: str
    native_tool_call_id: str
    content_text: str = field(repr=False)
    kind: StructuredRequestKind
    format_version: Literal[2] = 2
    surface: Literal["operator_enrolled_personal_app_chat"] = "operator_enrolled_personal_app_chat"
    end_turn: None = None
    delivery: Literal["requested_not_verified"] = "requested_not_verified"
    native_conversation_id: None = None
    native_author_id: None = None
    native_occurred_at: None = None

    def __post_init__(self) -> None:
        if (
            type(self.format_version) is not int
            or self.format_version != 2
            or self.end_turn is not None
        ):
            raise ValueError("Grok Bot structured request version or turn marker is unsupported")
        # Reuse the existing scope and privacy checks without claiming a native text reply.
        GrokBotReplyObservation(
            self.bot_id,
            self.native_tool_call_id,
            self.content_text,
            None,
            surface=self.surface,
            delivery=self.delivery,
            native_conversation_id=self.native_conversation_id,
            native_author_id=self.native_author_id,
            native_occurred_at=self.native_occurred_at,
        )
        try:
            value: object = json.loads(
                self.content_text, object_pairs_hook=_unique_object, parse_constant=_reject_constant
            )
            kind, content = canonical_outward_request(value)
        except (ValueError, RecursionError, UnicodeError):
            raise ValueError("Grok Bot structured request is invalid") from None
        if kind != self.kind or content != self.content_text:
            raise ValueError("Grok Bot structured request kind or representation is invalid")

    @property
    def conversation_id(self) -> str:
        return f"grok-bot-app:{self.bot_id}"

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            asdict(self), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


def parse_grok_bot_capture_record(
    raw: bytes,
) -> GrokBotReplyObservation | GrokBotUserTextObservation | GrokBotStructuredRequestObservation:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CAPTURE_BYTES:
        raise ValueError("Grok Bot capture byte envelope is invalid")
    try:
        loaded: object = json.loads(
            raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        if not isinstance(loaded, dict) or loaded.keys() != _FIELDS:
            raise ValueError("Grok Bot capture fields are unsupported")
        value = cast(dict[str, object], loaded)
        if value["kind"] in ("question_request", "attachment_reference"):
            return GrokBotStructuredRequestObservation(
                bot_id=cast(str, value["bot_id"]),
                native_tool_call_id=cast(str, value["native_tool_call_id"]),
                content_text=cast(str, value["content_text"]),
                kind=value["kind"],
                format_version=cast(Literal[2], value["format_version"]),
                surface=cast(Literal["operator_enrolled_personal_app_chat"], value["surface"]),
                end_turn=cast(None, value["end_turn"]),
                delivery=cast(Literal["requested_not_verified"], value["delivery"]),
                native_conversation_id=cast(None, value["native_conversation_id"]),
                native_author_id=cast(None, value["native_author_id"]),
                native_occurred_at=cast(None, value["native_occurred_at"]),
            )
        if value["kind"] == "user_role_text":
            return GrokBotUserTextObservation(
                bot_id=cast(str, value["bot_id"]),
                content_text=cast(str, value["content_text"]),
                format_version=cast(Literal[1], value["format_version"]),
                surface=cast(Literal["operator_enrolled_personal_app_chat"], value["surface"]),
                kind=cast(Literal["user_role_text"], value["kind"]),
                native_tool_call_id=cast(None, value["native_tool_call_id"]),
                end_turn=cast(None, value["end_turn"]),
                delivery=cast(Literal["not_applicable"], value["delivery"]),
                native_conversation_id=cast(None, value["native_conversation_id"]),
                native_author_id=cast(None, value["native_author_id"]),
                native_occurred_at=cast(None, value["native_occurred_at"]),
            )
        return GrokBotReplyObservation(
            bot_id=cast(str, value["bot_id"]),
            native_tool_call_id=cast(str, value["native_tool_call_id"]),
            content_text=cast(str, value["content_text"]),
            end_turn=cast(bool | None, value["end_turn"]),
            format_version=cast(Literal[1], value["format_version"]),
            surface=cast(Literal["operator_enrolled_personal_app_chat"], value["surface"]),
            kind=cast(Literal["reply_request"], value["kind"]),
            delivery=cast(Literal["requested_not_verified"], value["delivery"]),
            native_conversation_id=cast(None, value["native_conversation_id"]),
            native_author_id=cast(None, value["native_author_id"]),
            native_occurred_at=cast(None, value["native_occurred_at"]),
        )
    except (ValueError, TypeError, RecursionError, UnicodeError, OverflowError):
        raise ValueError("Grok Bot capture record is invalid or unsupported") from None


def parse_grok_bot_capture(
    raw: bytes, path: Path, *, parser_version: str | None = None
) -> ParseResult:
    observation = parse_grok_bot_capture_record(raw)
    is_reply = not isinstance(observation, GrokBotUserTextObservation)
    version = (
        STRUCTURED_PARSER_VERSION
        if isinstance(observation, GrokBotStructuredRequestObservation)
        else PARSER_VERSION
    )
    if parser_version is not None and parser_version != version:
        raise ValueError("Grok Bot observation does not match its pinned parser version")
    digest = hashlib.sha256(raw).hexdigest()
    record = ParsedRecord(
        raw_record=raw,
        record_ordinal=0,
        byte_start=0,
        byte_end=len(raw),
        event_type=f"native_{observation.kind}" if is_reply else "native_user_role_text",
        actor_kind="assistant" if is_reply else "source",
        assistant="grok_bot",
        authority=Authority.ASSISTANT_OUTPUT if is_reply else Authority.TOOL_OBSERVATION,
        content_text=observation.content_text,
        occurred_at=None,
        message_id=observation.native_tool_call_id,
        parent_message_id=None,
        branch_id=observation.conversation_id,
        message_id_kind="native_tool_call_id" if is_reply else None,
    )
    return ParseResult(
        source_system=SourceSystem.GROK_BOT,
        parser_name=PARSER_NAME,
        parser_version=version,
        path=path,
        file_digest=digest,
        file_size=len(raw),
        file_mtime_ns=0,
        conversation_id=observation.conversation_id,
        branch_id=observation.conversation_id,
        captured_at=None,
        history_base=None,
        records=(record,),
        unknown_record_types=(),
        malformed_records=0,
        source_kind=SourceKind.UNKNOWN,
        source_label=SOURCE_LABEL,
        segment_start_ordinal=0,
        segment_start_byte=0,
        segment_end_ordinal_exclusive=1,
        segment_end_byte=len(raw),
        start_prefix_digest=_EMPTY_DIGEST,
        end_prefix_digest=digest,
        observed_file_size=len(raw),
        schema_fingerprint=native_jsonl_schema_fingerprint(raw),
    )


def grok_bot_observation_path(digest: str) -> Path:
    return Path(f"/grok-bot-observations/{digest}.json")


def build_grok_bot_capture_upload(
    observation: GrokBotReplyObservation
    | GrokBotUserTextObservation
    | GrokBotStructuredRequestObservation,
    *,
    source_account_id: str,
    source_client_version: str = "unknown",
    captured_at: str | None = None,
) -> bytes:
    from cross_assistant_memory.uploads import build_upload_batch

    if type(observation) not in {
        GrokBotReplyObservation,
        GrokBotUserTextObservation,
        GrokBotStructuredRequestObservation,
    }:
        raise ValueError("Grok Bot capture observation is required")
    if captured_at is not None:
        try:
            if type(captured_at) is not str or len(captured_at) > 64:
                raise ValueError("invalid observed time")
            observed_time = datetime.fromisoformat(captured_at)
            if observed_time.utcoffset() is None:
                raise ValueError("missing timezone")
        except ValueError:
            raise ValueError("Grok Bot capture observation time is invalid") from None
    raw = observation.canonical_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    parsed = replace(
        parse_grok_bot_capture(raw, grok_bot_observation_path(digest)),
        captured_at=captured_at,
    )
    return build_upload_batch(
        parsed,
        source_account_id=source_account_id,
        provenance=CollectorProvenance(
            source_client="grok-bot",
            source_client_version=source_client_version,
            capture_capability=CAPTURE_CAPABILITY,
            adapter_name=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            schema_fingerprint=parsed.schema_fingerprint,
        ),
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Grok Bot capture contains duplicate fields")
        value[key] = item
    return value


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("Grok Bot capture contains a non-JSON numeric constant")
