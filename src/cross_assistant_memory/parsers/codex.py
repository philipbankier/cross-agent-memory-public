from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from cross_assistant_memory.models import Authority, HistoryBase, ParsedRecord, SourceKind
from cross_assistant_memory.parsers.common import content_text, optional_text

PARSER_NAME = "codex-jsonl"
PARSER_VERSION = "0.2.3"
LEGACY_PARSER_NAME = "codex-unwrapped-jsonl"
LEGACY_PARSER_VERSION = "0.1.0"
LEGACY_METADATA_TYPES = frozenset(
    {
        "reasoning",
        "local_shell_call",
        "function_call",
        "function_call_output",
        "custom_tool_call",
        "custom_tool_call_output",
    }
)
COPIED_HISTORY_PRODUCERS = frozenset(
    {
        "0.147.0-alpha.6.5",
        "0.148.0-alpha.9",
        "0.148.0-alpha.15",
        "0.148.0-alpha.21",
        "0.149.0-alpha.4.1",
        "0.149.1",
        "0.150.0-alpha.8",
        "0.150.0-alpha.12.2",
        "0.151.0-alpha.7.1",
        "0.151.0-alpha.7.2",
        "0.153.0",
        "0.153.1",
    }
)
KNOWN_RECORD_TYPES = {
    "session_meta",
    "response_item",
    "inter_agent_communication",
    "inter_agent_communication_metadata",
    "compacted",
    "turn_context",
    "world_state",
    "event_msg",
    "token_usage_record",
}
INTERACTIVE_SOURCE_LABELS = {"app", "cli", "desktop", "terminal", "vscode"}
AUTOMATION_SOURCE_LABELS = {"automation", "codex_exec", "cron", "exec"}
MEMORY_CITATION_FOOTER = re.compile(
    r"\s*<oai-mem-citation>.*?</oai-mem-citation>\s*$",
    re.DOTALL,
)


@dataclass(frozen=True)
class CodexMetadata:
    conversation_id: str
    branch_id: str
    parent_conversation_id: str | None
    captured_at: str | None
    history_base: HistoryBase | None
    source_kind: SourceKind
    source_label: str | None
    forked_from_id: str | None = None
    has_inherited_history: bool = False
    referenced_history_ordinal_base: int | None = None
    copied_history_start_ordinal: int | None = None
    legacy_format: bool = False


def inspect_codex_metadata(data: bytes, path: Path) -> CodexMetadata:
    for ordinal, raw in enumerate(data.splitlines(keepends=True)):
        try:
            loaded: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            continue
        if not isinstance(loaded, dict):
            continue
        item = cast(dict[str, Any], loaded)
        if ordinal == 0 and "type" not in item and {"id", "timestamp"} <= item.keys():
            return _legacy_metadata(json.loads(raw, object_pairs_hook=_legacy_object))
        if item.get("type") != "session_meta":
            continue
        payload_value = item.get("payload")
        if not isinstance(payload_value, dict):
            continue
        payload = cast(dict[str, Any], payload_value)
        timestamp = optional_text(item.get("timestamp")) or optional_text(payload.get("timestamp"))
        return _metadata_from_payload(payload, path, timestamp, item.get("ordinal"))
    fallback = path.stem
    return CodexMetadata(
        conversation_id=fallback,
        branch_id=fallback,
        parent_conversation_id=None,
        captured_at=None,
        history_base=None,
        source_kind=SourceKind.UNKNOWN,
        source_label=None,
    )


def _legacy_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key in unwrapped Codex record")
        result[key] = value
    return result


def _has_retained_type(pairs: list[tuple[str, Any]]) -> bool:
    # Nested objects reduce to booleans, so only the physical root's discriminator survives.
    return any(key == "type" and value == "retained_context" for key, value in pairs)


def _legacy_metadata(item: dict[str, Any]) -> CodexMetadata:
    # Codex d77b33d (September 2025) wrote this unwrapped header without origin/version.
    if not {"id", "timestamp", "instructions"} <= item.keys() or not item.keys() <= {
        "id",
        "timestamp",
        "instructions",
        "git",
    }:
        raise ValueError("unsupported unwrapped Codex metadata")
    identity, timestamp = item["id"], item["timestamp"]
    if (
        not isinstance(identity, str)
        or str(UUID(identity)) != identity
        or not isinstance(timestamp, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", timestamp) is None
        or (item["instructions"] is not None and not isinstance(item["instructions"], str))
    ):
        raise ValueError("invalid unwrapped Codex metadata")
    datetime.fromisoformat(timestamp)
    if "git" in item:
        git = item["git"]
        if (
            not isinstance(git, dict)
            or not git.keys() <= {"commit_hash", "branch", "repository_url"}
            or any(not isinstance(value, str) for value in cast(dict[str, object], git).values())
        ):
            raise ValueError("unsupported unwrapped Codex git metadata")
    return CodexMetadata(
        conversation_id=identity,
        branch_id=identity,
        parent_conversation_id=None,
        captured_at=timestamp,
        history_base=None,
        source_kind=SourceKind.UNKNOWN,
        source_label=None,
        legacy_format=True,
    )


def _legacy_message(
    item: dict[str, Any],
    raw: bytes,
    ordinal: int,
    start: int,
    end: int,
    metadata: CodexMetadata,
) -> ParsedRecord | None:
    if ordinal == 0:
        if _legacy_metadata(item) != metadata:
            raise ValueError("unwrapped Codex metadata changed")
        return None
    if item == {"record_type": "state"}:
        return None
    record_type = item.get("type")
    if isinstance(record_type, str) and record_type in LEGACY_METADATA_TYPES:
        return None
    if record_type != "message" or set(item) != {"type", "id", "role", "content"}:
        raise ValueError("unsupported unwrapped Codex record")
    if (
        (item["id"] is not None and not isinstance(item["id"], str))
        or item["role"] not in ("user", "assistant", "system", "developer")
        or not isinstance(item["content"], list)
    ):
        raise ValueError("invalid unwrapped Codex message")
    for content_part in cast(list[object], item["content"]):
        if not isinstance(content_part, dict):
            raise ValueError("invalid unwrapped Codex message content")
        part = cast(dict[str, object], content_part)
        kind = part.get("type")
        if kind not in ("input_text", "output_text", "input_image"):
            raise ValueError("unsupported unwrapped Codex content type")
        field = "image_url" if kind == "input_image" else "text"
        if set(part) != {"type", field} or not isinstance(part[field], str):
            raise ValueError("invalid unwrapped Codex message content")
    return _response_message(item, raw, ordinal, start, end, None, metadata, None)


def parse_codex_records(
    data: bytes,
    path: Path,
    *,
    ordinal_base: int = 0,
    byte_base: int = 0,
    metadata: CodexMetadata | None = None,
    parser_version: str = PARSER_VERSION,
) -> tuple[
    CodexMetadata,
    tuple[ParsedRecord, ...],
    tuple[str, ...],
    int,
]:
    source_metadata = metadata or inspect_codex_metadata(data, path)
    unknown_types: set[str] = set()
    malformed = 0
    response_records: list[ParsedRecord] = []
    fallback_records: list[ParsedRecord] = []
    turn_order: list[str] = []
    rolled_back_turns: set[str] = set()
    active_turn_id: str | None = None

    offset = byte_base
    for ordinal, raw in enumerate(data.splitlines(keepends=True), start=ordinal_base):
        start = offset
        offset += len(raw)
        try:
            loaded: object = json.loads(
                raw, object_pairs_hook=_legacy_object if source_metadata.legacy_format else None
            )
            if (
                not source_metadata.legacy_format
                and parser_version == "0.2.3"
                and json.loads(raw, object_pairs_hook=_has_retained_type) is True
            ):
                loaded = json.loads(raw, object_pairs_hook=_legacy_object)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            if source_metadata.legacy_format:
                raise ValueError("invalid unwrapped Codex record") from None
            if source_metadata.copied_history_start_ordinal is not None:
                raise ValueError(
                    "copied Codex history contains an invalid physical record"
                ) from None
            malformed += 1
            continue
        if source_metadata.copied_history_start_ordinal is not None:
            _validate_copied_record(loaded, raw, ordinal, source_metadata, path)
            if ordinal < source_metadata.copied_history_start_ordinal:
                continue
        if not isinstance(loaded, dict):
            if source_metadata.legacy_format:
                raise ValueError("invalid unwrapped Codex record")
            malformed += 1
            continue
        item = cast(dict[str, Any], loaded)
        if source_metadata.legacy_format:
            parsed = _legacy_message(item, raw, ordinal, start, offset, source_metadata)
            if parsed is not None:
                response_records.append(parsed)
            continue
        record_type = item.get("type")
        if not isinstance(record_type, str):
            malformed += 1
            continue
        if record_type == "retained_context" and parser_version == "0.2.3":
            try:
                parsed = _retained_answer(raw, ordinal, start, offset, source_metadata)
                if (
                    active_turn_id is not None
                    and parsed.turn_id != active_turn_id
                    and parsed.turn_id not in turn_order
                    and parsed.turn_id not in rolled_back_turns
                ):
                    raise ValueError("retained Codex turn chronology is unresolved")
            except ValueError:
                malformed += 1
            else:
                response_records.append(parsed)
                if (
                    parsed.turn_id is not None
                    and parsed.turn_id not in turn_order
                    and parsed.turn_id not in rolled_back_turns
                ):
                    _remember_turn(turn_order, parsed.turn_id)
            continue
        if record_type not in KNOWN_RECORD_TYPES:
            unknown_types.add(record_type)
            continue
        payload_value = item.get("payload")
        if not isinstance(payload_value, dict):
            continue
        payload = cast(dict[str, Any], payload_value)
        timestamp = optional_text(item.get("timestamp")) or optional_text(payload.get("timestamp"))

        if record_type == "session_meta":
            continue

        if record_type == "turn_context":
            context_turn = optional_text(payload.get("turn_id"))
            if context_turn is not None:
                active_turn_id = context_turn
                _remember_turn(turn_order, context_turn)
            continue

        if record_type == "event_msg":
            payload_type = payload.get("type")
            if payload_type == "task_started":
                started_turn = optional_text(payload.get("turn_id"))
                if started_turn is not None:
                    active_turn_id = started_turn
                    _remember_turn(turn_order, started_turn)
                continue
            if payload_type == "thread_rolled_back":
                count = payload.get("num_turns")
                if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                    for _ in range(min(count, len(turn_order))):
                        rolled_back_turns.add(turn_order.pop())
                    if active_turn_id in rolled_back_turns:
                        active_turn_id = turn_order[-1] if turn_order else None
                continue

        if record_type == "response_item" and payload.get("type") == "message":
            parsed = _response_message(
                payload,
                raw,
                ordinal,
                start,
                offset,
                timestamp,
                source_metadata,
                active_turn_id,
            )
            if parsed is not None:
                response_records.append(parsed)
            continue

        if record_type == "event_msg":
            parsed = _event_message(
                payload,
                raw,
                ordinal,
                start,
                offset,
                timestamp,
                source_metadata,
                active_turn_id,
            )
            if parsed is not None:
                fallback_records.append(parsed)

    response_records = [
        record for record in response_records if record.turn_id not in rolled_back_turns
    ]
    fallback_records = [
        record for record in fallback_records if record.turn_id not in rolled_back_turns
    ]
    response_signatures = {
        _transport_signature(record)
        for record in response_records
        if record.event_type == "message"
    }
    seen_fallback: set[tuple[str, str, str | None]] = set()
    records = list(response_records)
    for record in fallback_records:
        if _transport_signature(record) in response_signatures:
            continue
        fallback_signature = (record.actor_kind, record.content_text, record.turn_id)
        if fallback_signature in seen_fallback:
            continue
        seen_fallback.add(fallback_signature)
        records.append(record)

    records.sort(key=lambda item: item.record_ordinal)
    return source_metadata, tuple(records), tuple(sorted(unknown_types)), malformed


def _retained_answer(
    raw: bytes, ordinal: int, start: int, end: int, metadata: CodexMetadata
) -> ParsedRecord:
    # Refuse duplicate keys as well as future variants; only this source event is qualified.
    loaded: object = json.loads(raw, object_pairs_hook=_legacy_object)
    if not isinstance(loaded, dict):
        raise ValueError("invalid retained Codex record")
    item = cast(dict[str, Any], loaded)
    if (
        not {"type", "payload"} <= item.keys() <= {"type", "payload", "timestamp", "ordinal"}
        or ("timestamp" in item and not isinstance(item["timestamp"], str))
        or (
            "ordinal" in item
            and (type(item["ordinal"]) is not int or not 0 <= item["ordinal"] < 2**64)
        )
    ):
        raise ValueError("invalid retained Codex record")
    payload_value = item["payload"]
    if not isinstance(payload_value, dict):
        raise ValueError("unsupported retained Codex answer schema")
    payload = cast(dict[str, Any], payload_value)
    required = {"type", "turn_id", "call_id", "questions"}
    if (
        not required <= payload.keys() <= required | {"acceptance_order"}
        or payload["type"] != "verified_answer"
        or any(
            not isinstance(payload[key], str) or not payload[key].strip()
            for key in ("turn_id", "call_id")
        )
        or not isinstance(payload["questions"], list)
    ):
        raise ValueError("unsupported retained Codex answer schema")
    order = payload.get("acceptance_order")
    if order is not None and (type(order) is not int or not 0 <= order < 2**64):
        raise ValueError("invalid retained Codex acceptance order")
    answers: list[str] = []
    for value in cast(list[object], payload["questions"]):
        if not isinstance(value, dict):
            raise ValueError("invalid retained Codex question and answer")
        pair = cast(dict[str, Any], value)
        if (
            set(pair) != {"question", "answer"}
            or not isinstance(pair["question"], str)
            or not isinstance(pair["answer"], str)
            or not pair["answer"].strip()
        ):
            raise ValueError("invalid retained Codex question and answer")
        answers.append(pair["answer"])
    if answers:
        actor_kind, assistant, authority = _prompt_authority(metadata.source_kind)
        event_type = "user_input_response"
        # Assistant questions and answer pairing remain in exact raw evidence, not user text.
        text = "\n\n".join(answers)
    else:
        actor_kind, assistant, authority = "source", "codex", Authority.TOOL_OBSERVATION
        event_type = "user_input_response_omitted"
        text = "Codex recorded a user-input response but omitted its question and answer text."
    return ParsedRecord(
        raw_record=raw,
        record_ordinal=ordinal,
        byte_start=start,
        byte_end=end,
        event_type=event_type,
        actor_kind=actor_kind,
        assistant=assistant,
        authority=authority,
        content_text=text,
        occurred_at=item.get("timestamp"),
        message_id=None,
        parent_message_id=None,
        branch_id=metadata.branch_id,
        turn_id=payload["turn_id"],
    )


def _validate_copied_record(
    loaded: object, raw: bytes, ordinal: int, metadata: CodexMetadata, path: Path
) -> None:
    if not isinstance(loaded, dict) or not raw.endswith(b"\n"):
        raise ValueError("copied Codex history contains an invalid physical record")
    item = cast(dict[str, Any], loaded)
    native = item.get("ordinal")
    if type(native) is not int or native != ordinal or native >= 2**64:
        raise ValueError("copied Codex history has an invalid ordinal sequence")
    record_type = item.get("type")
    if (
        not isinstance(record_type, str)
        or record_type not in KNOWN_RECORD_TYPES
        or not isinstance(item.get("payload"), dict)
    ):
        # A raw hold here could retain inherited/private context. Leave the source untouched.
        raise ValueError("copied Codex history contains an unverified record schema")
    if ordinal == 0:
        if item.get("type") != "session_meta" or inspect_codex_metadata(raw, path) != metadata:
            raise ValueError("copied Codex history changed its initial metadata")
    elif item.get("type") == "session_meta":
        assert metadata.copied_history_start_ordinal is not None
        if ordinal >= metadata.copied_history_start_ordinal:
            raise ValueError("copied Codex metadata occurs outside the inherited prefix")


def _response_message(
    payload: dict[str, Any],
    raw: bytes,
    ordinal: int,
    start: int,
    end: int,
    timestamp: str | None,
    metadata: CodexMetadata,
    active_turn_id: str | None,
) -> ParsedRecord | None:
    role = payload.get("role")
    text = content_text(payload.get("content"))
    if not text:
        return None
    if role == "user":
        actor_kind, assistant, authority = _prompt_authority(metadata.source_kind)
    elif role == "assistant":
        phase = payload.get("phase")
        if phase not in (None, "final_answer"):
            return None
        actor_kind = "assistant"
        assistant = "codex"
        authority = Authority.ASSISTANT_OUTPUT
        text = MEMORY_CITATION_FOOTER.sub("", text).rstrip()
        if not text:
            return None
    else:
        return None
    return ParsedRecord(
        raw_record=raw,
        record_ordinal=ordinal,
        byte_start=start,
        byte_end=end,
        event_type="message",
        actor_kind=actor_kind,
        assistant=assistant,
        authority=authority,
        content_text=text,
        occurred_at=timestamp,
        message_id=optional_text(payload.get("id")),
        parent_message_id=None,
        branch_id=metadata.branch_id,
        turn_id=_response_turn_id(payload) or active_turn_id,
    )


def _event_message(
    payload: dict[str, Any],
    raw: bytes,
    ordinal: int,
    start: int,
    end: int,
    timestamp: str | None,
    metadata: CodexMetadata,
    active_turn_id: str | None,
) -> ParsedRecord | None:
    payload_type = payload.get("type")
    if payload_type == "user_message":
        text = payload.get("message")
        actor_kind, assistant, authority = _prompt_authority(metadata.source_kind)
    elif payload_type == "agent_message" and payload.get("phase") == "final_answer":
        text = payload.get("message")
        actor_kind = "assistant"
        assistant = "codex"
        authority = Authority.ASSISTANT_OUTPUT
    elif payload_type == "task_complete":
        text = payload.get("last_agent_message")
        actor_kind = "assistant"
        assistant = "codex"
        authority = Authority.ASSISTANT_OUTPUT
    else:
        return None
    if not isinstance(text, str) or not text:
        return None
    if actor_kind == "assistant":
        text = MEMORY_CITATION_FOOTER.sub("", text).rstrip()
        if not text:
            return None
    return ParsedRecord(
        raw_record=raw,
        record_ordinal=ordinal,
        byte_start=start,
        byte_end=end,
        event_type="message",
        actor_kind=actor_kind,
        assistant=assistant,
        authority=authority,
        content_text=text,
        occurred_at=timestamp,
        message_id=optional_text(payload.get("turn_id")),
        parent_message_id=None,
        branch_id=metadata.branch_id,
        turn_id=optional_text(payload.get("turn_id")) or active_turn_id,
    )


def _metadata_from_payload(
    payload: dict[str, Any], path: Path, timestamp: str | None, native_ordinal: object
) -> CodexMetadata:
    conversation_id = optional_text(payload.get("id")) or path.stem
    source_kind, source_label, source_parent = _source_provenance(payload.get("source"))
    forked_from_id = optional_text(payload.get("forked_from_id"))
    parent_id = forked_from_id or source_parent
    session_id = optional_text(payload.get("session_id"))
    branch_id = conversation_id if parent_id else session_id or conversation_id
    history_base = _history_base(payload.get("history_base"))
    copied_start = _copied_history_start_ordinal(
        payload, native_ordinal, source_kind, source_parent
    )
    if payload.get("subagent_history_start_ordinal") is not None and copied_start is None:
        raise ValueError("unverified copied Codex sources require an explicit replay boundary")
    return CodexMetadata(
        conversation_id=conversation_id,
        branch_id=branch_id,
        parent_conversation_id=parent_id,
        captured_at=optional_text(payload.get("timestamp")) or timestamp,
        history_base=history_base,
        source_kind=source_kind,
        source_label=source_label,
        forked_from_id=forked_from_id,
        has_inherited_history=any(
            payload.get(key) is not None
            for key in ("forked_from_id", "history_base", "subagent_history_start_ordinal")
        ),
        referenced_history_ordinal_base=_referenced_history_ordinal_base(
            payload, history_base, native_ordinal
        ),
        copied_history_start_ordinal=copied_start,
    )


def _copied_history_start_ordinal(
    payload: dict[str, Any],
    native_ordinal: object,
    source_kind: SourceKind,
    source_parent: str | None,
) -> int | None:
    boundary = payload.get("subagent_history_start_ordinal")
    version = payload.get("cli_version")
    if (
        not isinstance(version, str)
        or version not in COPIED_HISTORY_PRODUCERS
        or payload.get("history_mode") != "paginated"
        or not optional_text(payload.get("id"))
        or payload.get("history_base") is not None
        or source_kind is not SourceKind.SUBAGENT
        or source_parent is None
        or (
            payload.get("forked_from_id") is not None
            and not optional_text(payload.get("forked_from_id"))
        )
        or type(native_ordinal) is not int
        or native_ordinal != 0
        or type(boundary) is not int
        or not 1 <= boundary < 2**64
    ):
        return None
    return boundary


def _referenced_history_ordinal_base(
    payload: dict[str, Any], history_base: HistoryBase | None, native_ordinal: object
) -> int | None:
    # These pinned producers reference another rollout, not bytes in this physical file.
    # A reference-only replacement need not have a logical fork.
    version = payload.get("cli_version")
    forked_from_id = payload.get("forked_from_id")
    if (
        version
        not in (
            "0.150.0-alpha.8",
            "0.153.1",
            "0.153.4",
            "0.154.0-alpha.6.2",
            "0.155.0-alpha.9.2",
            "0.158.0-alpha.2.1",
            "0.159.0",
            "0.159.0-alpha.12.1",
            "0.159.2",
            "0.160.0",
            "0.160.1",
            "0.162.0-alpha.2",
            "0.162.0-alpha.17.2",
        )
        or payload.get("history_mode") != "paginated"
        or not optional_text(payload.get("id"))
        or (forked_from_id is not None and not optional_text(forked_from_id))
        or payload.get("subagent_history_start_ordinal") is not None
        or history_base is None
        or not history_base.thread_id
        or history_base.end_ordinal_exclusive >= 2**64
        or history_base.end_byte_offset >= 2**64
        or not isinstance(native_ordinal, int)
        or isinstance(native_ordinal, bool)
        or native_ordinal != history_base.end_ordinal_exclusive
    ):
        return None
    return native_ordinal


def _source_provenance(value: Any) -> tuple[SourceKind, str | None, str | None]:
    if value is None:
        return SourceKind.UNKNOWN, None, None
    if isinstance(value, str):
        if value in INTERACTIVE_SOURCE_LABELS:
            return SourceKind.INTERACTIVE, value, None
        if value in AUTOMATION_SOURCE_LABELS:
            return SourceKind.AUTOMATION, value, None
        return SourceKind.UNKNOWN, value, None
    if isinstance(value, dict):
        typed_value = cast(dict[str, Any], value)
        subagent_value = typed_value.get("subagent")
        if isinstance(subagent_value, dict):
            subagent = cast(dict[str, Any], subagent_value)
            spawn_value = subagent.get("thread_spawn")
            if isinstance(spawn_value, dict):
                spawn = cast(dict[str, Any], spawn_value)
                return (
                    SourceKind.SUBAGENT,
                    "subagent",
                    optional_text(spawn.get("parent_thread_id")),
                )
            return SourceKind.SUBAGENT, "subagent", None
    return SourceKind.UNKNOWN, "structured_unknown", None


def _prompt_authority(source_kind: SourceKind) -> tuple[str, str | None, Authority]:
    if source_kind is SourceKind.INTERACTIVE:
        return "user", None, Authority.USER_ASSERTION
    if source_kind is SourceKind.SUBAGENT:
        return "assistant", "codex", Authority.ASSISTANT_OUTPUT
    if source_kind is SourceKind.AUTOMATION:
        return "automation", "codex", Authority.TOOL_OBSERVATION
    return "source", "codex", Authority.TOOL_OBSERVATION


def _response_turn_id(payload: dict[str, Any]) -> str | None:
    metadata_value = payload.get("internal_chat_message_metadata_passthrough")
    if not isinstance(metadata_value, dict):
        return None
    metadata = cast(dict[str, Any], metadata_value)
    return optional_text(metadata.get("turn_id"))


def _remember_turn(turn_order: list[str], turn_id: str) -> None:
    if not turn_order or turn_order[-1] != turn_id:
        turn_order.append(turn_id)


def _transport_signature(record: ParsedRecord) -> tuple[str, str]:
    return record.actor_kind, record.content_text


def _history_base(value: Any) -> HistoryBase | None:
    if not isinstance(value, dict):
        return None
    typed_value = cast(dict[str, Any], value)
    thread_id = typed_value.get("thread_id")
    ordinal = typed_value.get("end_ordinal_exclusive")
    byte_offset = typed_value.get("end_byte_offset")
    if (
        not isinstance(thread_id, str)
        or not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or ordinal < 0
        or not isinstance(byte_offset, int)
        or isinstance(byte_offset, bool)
        or byte_offset < 0
    ):
        return None
    return HistoryBase(thread_id, ordinal, byte_offset)
