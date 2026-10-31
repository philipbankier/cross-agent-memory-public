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

PARSER_NAME = "grok-bot-native-observation"
PARSER_VERSION = "0.1.0"
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
    coverage: Literal["user_text_and_reply_requests"] = "user_text_and_reply_requests"
    pending_user_texts: int = 0
    excluded_user_texts: int = 0


def capture_transcript_page(
    queue: CollectorQueue,
    data: bytes,
    *,
    bot_id: str,
    scope: GrokBotCaptureScope,
    now_epoch: int | None = None,
) -> CapturePageResult:
    from cross_assistant_memory.collector_queue import source_key_for
    from cross_assistant_memory.grok_bot_transcript import (
        project_transcript_page,
        project_user_texts,
    )
    from cross_assistant_memory.uploads import parse_upload_batch

    if type(scope) is not GrokBotCaptureScope or not scope.allows(bot_id):
        raise PermissionError("Grok Bot target is not enrolled for capture")
    projection = project_transcript_page(data, expected_bot_id=bot_id)
    user_texts, excluded_users = project_user_texts(data, expected_bot_id=bot_id)
    # Validate every eligible record before any queue write; retain no native internals.
    bodies = tuple(
        (
            build_grok_bot_capture_upload(
                GrokBotReplyObservation(
                    bot_id, reply.native_tool_call_id, reply.content_text, reply.end_turn
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
        len(data),
        projection.source_sha256,
        projection.inspection.before,
        pending_user_texts=pending_users,
        excluded_user_texts=excluded_users,
    )


def flush_queued_grok_bot_capture(
    queue: CollectorQueue,
    node: CollectorNodeConfig,
    *,
    scope: GrokBotCaptureScope,
    transport: UploadTransport | None = None,
    limit: int = 4,
    now_epoch: int | None = None,
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


def parse_grok_bot_capture_record(
    raw: bytes,
) -> GrokBotReplyObservation | GrokBotUserTextObservation:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CAPTURE_BYTES:
        raise ValueError("Grok Bot capture byte envelope is invalid")
    try:
        loaded: object = json.loads(
            raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        if not isinstance(loaded, dict) or loaded.keys() != _FIELDS:
            raise ValueError("Grok Bot capture fields are unsupported")
        value = cast(dict[str, object], loaded)
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


def parse_grok_bot_capture(raw: bytes, path: Path) -> ParseResult:
    observation = parse_grok_bot_capture_record(raw)
    is_reply = isinstance(observation, GrokBotReplyObservation)
    digest = hashlib.sha256(raw).hexdigest()
    record = ParsedRecord(
        raw_record=raw,
        record_ordinal=0,
        byte_start=0,
        byte_end=len(raw),
        event_type="native_reply_request" if is_reply else "native_user_role_text",
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
        parser_version=PARSER_VERSION,
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


def build_grok_bot_capture_upload(
    observation: GrokBotReplyObservation | GrokBotUserTextObservation,
    *,
    source_account_id: str,
    source_client_version: str = "unknown",
    captured_at: str | None = None,
) -> bytes:
    from cross_assistant_memory.uploads import build_upload_batch

    if type(observation) not in {GrokBotReplyObservation, GrokBotUserTextObservation}:
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
        parse_grok_bot_capture(raw, Path(f"/grok-bot-observations/{digest}.json")),
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
