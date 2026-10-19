from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.models import Authority, ParsedRecord
from cross_assistant_memory.parsers.common import (
    content_text,
    optional_text,
    source_branch_path,
    timestamp_text,
)
from cross_assistant_memory.parsers.json_bytes import object_array_value_spans, object_field_span

PARSER_NAME = "claude-web-export-json"
PARSER_VERSION = "0.2.0"


def parse_claude_web_records(
    data: bytes, path: Path
) -> tuple[
    str,
    str,
    str | None,
    tuple[ParsedRecord, ...],
    tuple[str, ...],
    int,
]:
    document = _object(data, "Claude web conversation")
    conversation_id = _required_text(document, "uuid", "Claude web conversation")
    captured_at = timestamp_text(document.get("created_at"))
    message_spans = object_array_value_spans(data, "chat_messages")
    messages_value = document.get("chat_messages")
    messages = cast(list[object], messages_value) if isinstance(messages_value, list) else []
    parents = {
        message_id: optional_text(message.get("parent_message_uuid"))
        for item in messages
        if isinstance(item, dict)
        for message in [cast(dict[str, Any], item)]
        if (message_id := optional_text(message.get("uuid"))) is not None
    }
    records: list[ParsedRecord] = []
    unknown_types: set[str] = set()
    malformed = 0

    for ordinal, message_span in enumerate(message_spans):
        try:
            message = _object(message_span.bytes(data), "Claude web message")
        except ValueError:
            malformed += 1
            continue
        sender = message.get("sender")
        if sender == "human":
            actor_kind = "user"
            assistant = None
            authority = Authority.USER_ASSERTION
        elif sender == "assistant":
            actor_kind = "assistant"
            assistant = "claude_web"
            authority = Authority.ASSISTANT_OUTPUT
        elif isinstance(sender, str):
            unknown_types.add(f"sender:{sender}")
            continue
        else:
            malformed += 1
            continue

        text = optional_text(message.get("text"))
        if text is not None:
            try:
                object_field_span(data, "text", container=message_span)
            except ValueError:
                malformed += 1
                continue
        else:
            text = content_text(message.get("content"))
            if text:
                try:
                    object_field_span(data, "content", container=message_span)
                except ValueError:
                    malformed += 1
                    continue
        if not text:
            continue

        message_id = optional_text(message.get("uuid"))
        records.append(
            ParsedRecord(
                raw_record=message_span.bytes(data),
                record_ordinal=ordinal,
                byte_start=message_span.start,
                byte_end=message_span.end,
                event_type="message",
                actor_kind=actor_kind,
                assistant=assistant,
                authority=authority,
                content_text=text,
                occurred_at=timestamp_text(message.get("created_at")),
                message_id=message_id,
                parent_message_id=optional_text(message.get("parent_message_uuid")),
                branch_id=source_branch_path("claude-path", message_id, parents),
                message_id_kind=("provider_message_id" if message_id is not None else None),
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


def _object(data: bytes, label: str) -> dict[str, Any]:
    try:
        loaded: object = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{label} is not a JSON object")
    return cast(dict[str, Any], loaded)


def _required_text(item: dict[str, Any], key: str, label: str) -> str:
    value = optional_text(item.get(key))
    if value is None:
        raise ValueError(f"{label} is missing {key}")
    return value
