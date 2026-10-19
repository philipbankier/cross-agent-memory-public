from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.models import Authority, ParsedRecord
from cross_assistant_memory.parsers.common import optional_text

PARSER_NAME = "grok-build-updates-jsonl"
PARSER_VERSION = "0.1.0"
KNOWN_UPDATE_TYPES = {
    "agent_message_chunk",
    "agent_thought_chunk",
    "available_commands_update",
    "hook_execution",
    "plan",
    "tool_call",
    "tool_call_update",
    "user_message_chunk",
}


def inspect_grok_build_conversation_id(records: Iterable[bytes], path: Path) -> str:
    for raw in records:
        try:
            loaded: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            continue
        if not isinstance(loaded, dict):
            continue
        params = cast(dict[str, Any], loaded).get("params")
        if not isinstance(params, dict):
            continue
        session_id = optional_text(cast(dict[str, Any], params).get("sessionId"))
        if session_id is not None:
            return session_id
    return path.parent.name or path.stem


def parse_grok_build_records(
    data: bytes,
    path: Path,
    *,
    ordinal_base: int = 0,
    byte_base: int = 0,
    expected_conversation_id: str | None = None,
) -> tuple[
    str,
    str,
    str | None,
    tuple[ParsedRecord, ...],
    tuple[str, ...],
    int,
]:
    if ordinal_base < 0 or byte_base < 0:
        raise ValueError("Grok Build parser bases must be non-negative")
    conversation_id = expected_conversation_id or path.parent.name or path.stem
    captured_at: str | None = None
    records: list[ParsedRecord] = []
    unknown_types: set[str] = set()
    malformed = 0
    offset = byte_base
    active_turn_id: str | None = None
    source_session_id = expected_conversation_id

    for relative_ordinal, raw in enumerate(data.splitlines(keepends=True)):
        ordinal = ordinal_base + relative_ordinal
        start = offset
        offset += len(raw)
        try:
            loaded: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            malformed += 1
            continue
        if not isinstance(loaded, dict):
            malformed += 1
            continue
        item = cast(dict[str, Any], loaded)
        method = item.get("method")
        if method == "_x.ai/session/update":
            continue
        if method != "session/update":
            if isinstance(method, str):
                unknown_types.add(f"method:{method}")
            else:
                malformed += 1
            continue
        params_value = item.get("params")
        if not isinstance(params_value, dict):
            malformed += 1
            continue
        params = cast(dict[str, Any], params_value)
        item_session = optional_text(params.get("sessionId"))
        if source_session_id is None and item_session is not None:
            source_session_id = item_session
            conversation_id = item_session
        elif item_session is not None and item_session != source_session_id:
            unknown_types.add("session_id_mismatch")
            continue
        update_value = params.get("update")
        if not isinstance(update_value, dict):
            malformed += 1
            continue
        update = cast(dict[str, Any], update_value)
        update_type = update.get("sessionUpdate")
        if not isinstance(update_type, str):
            malformed += 1
            continue
        if update_type not in KNOWN_UPDATE_TYPES:
            unknown_types.add(update_type)
            continue
        if update_type == "plan":
            entries = update.get("entries")
            if not isinstance(entries, list) or any(
                not isinstance(entry, dict)
                or not isinstance(cast(dict[str, object], entry).get("content"), str)
                or cast(dict[str, object], entry).get("priority") not in ("high", "medium", "low")
                or cast(dict[str, object], entry).get("status")
                not in ("pending", "in_progress", "completed")
                for entry in cast(list[object], entries)
            ):
                malformed += 1
                continue
        timestamp = _timestamp_text(item.get("timestamp"))
        captured_at = captured_at or timestamp
        if update_type not in ("user_message_chunk", "agent_message_chunk"):
            continue
        content_value = update.get("content")
        if not isinstance(content_value, dict):
            malformed += 1
            continue
        content = cast(dict[str, Any], content_value)
        if content.get("type") != "text":
            continue
        text = optional_text(content.get("text"))
        if text is None:
            continue

        if update_type == "user_message_chunk":
            actor_kind = "user"
            assistant = None
            authority = Authority.USER_ASSERTION
            prompt_index = _prompt_index(update.get("_meta"))
            active_turn_id = (
                f"prompt-{prompt_index}" if prompt_index is not None else active_turn_id
            )
        else:
            actor_kind = "assistant"
            assistant = "grok_build"
            authority = Authority.ASSISTANT_OUTPUT

        records.append(
            ParsedRecord(
                raw_record=raw,
                record_ordinal=ordinal,
                byte_start=start,
                byte_end=offset,
                event_type="message",
                actor_kind=actor_kind,
                assistant=assistant,
                authority=authority,
                content_text=text,
                occurred_at=timestamp,
                message_id=None,
                parent_message_id=None,
                branch_id=conversation_id,
                turn_id=active_turn_id,
            )
        )

    return (
        conversation_id,
        conversation_id,
        captured_at,
        tuple(records),
        tuple(sorted(unknown_types)),
        malformed,
    )


def _prompt_index(value: Any) -> int | None:
    if not isinstance(value, dict):
        return None
    prompt_index = cast(dict[str, Any], value).get("promptIndex")
    if isinstance(prompt_index, int) and not isinstance(prompt_index, bool) and prompt_index >= 0:
        return prompt_index
    return None


def _timestamp_text(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return optional_text(value)
    try:
        return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError):
        return None
