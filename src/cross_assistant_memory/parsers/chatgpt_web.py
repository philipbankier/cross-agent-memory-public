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
from cross_assistant_memory.parsers.json_bytes import object_field_span, object_item_spans

PARSER_NAME = "chatgpt-web-export-json"
PARSER_VERSION = "0.2.0"
_NONCONVERSATIONAL_ROLES = {"developer", "system", "tool"}
_TEXT_CONTENT_TYPES = {"multimodal_text", "text"}


def parse_chatgpt_web_records(
    data: bytes, path: Path
) -> tuple[
    str,
    str,
    str | None,
    tuple[ParsedRecord, ...],
    tuple[str, ...],
    int,
]:
    document = _object(data, "ChatGPT web conversation")
    conversation_id = optional_text(document.get("conversation_id")) or optional_text(
        document.get("id")
    )
    if conversation_id is None:
        raise ValueError("ChatGPT web conversation is missing conversation_id")
    current_node = optional_text(document.get("current_node"))
    captured_at = timestamp_text(document.get("create_time"))
    node_spans = object_item_spans(data, "mapping")
    mapping_value = document.get("mapping")
    mapping = cast(dict[str, Any], mapping_value) if isinstance(mapping_value, dict) else {}
    message_ids: dict[str, str] = {}
    parents: dict[str, str | None] = {}
    for mapping_id, node_value in mapping.items():
        if not isinstance(node_value, dict):
            continue
        node = cast(dict[str, Any], node_value)
        parents[mapping_id] = optional_text(node.get("parent"))
        message_value = node.get("message")
        if isinstance(message_value, dict):
            message_id = optional_text(cast(dict[str, Any], message_value).get("id"))
            if message_id is not None:
                message_ids[mapping_id] = message_id
    records: list[ParsedRecord] = []
    unknown_types: set[str] = set()
    malformed = 0
    active_turn_id: str | None = None

    for ordinal, (mapping_id, node_span) in enumerate(node_spans):
        try:
            node = _object(node_span.bytes(data), "ChatGPT mapping node")
        except ValueError:
            malformed += 1
            continue
        message_value = node.get("message")
        if message_value is None:
            continue
        if not isinstance(message_value, dict):
            malformed += 1
            continue
        message = cast(dict[str, Any], message_value)
        author_value = message.get("author")
        if not isinstance(author_value, dict):
            malformed += 1
            continue
        author = cast(dict[str, Any], author_value)
        role = author.get("role")
        if role == "user":
            actor_kind = "user"
            assistant = None
            authority = Authority.USER_ASSERTION
        elif role == "assistant":
            actor_kind = "assistant"
            assistant = "chatgpt_web"
            authority = Authority.ASSISTANT_OUTPUT
        elif role in _NONCONVERSATIONAL_ROLES:
            continue
        elif isinstance(role, str):
            unknown_types.add(f"role:{role}")
            continue
        else:
            malformed += 1
            continue

        if actor_kind == "assistant" and not _is_final_assistant_message(message):
            continue
        content_value = message.get("content")
        if not isinstance(content_value, dict):
            malformed += 1
            continue
        content = cast(dict[str, Any], content_value)
        content_type = content.get("content_type")
        if content_type not in _TEXT_CONTENT_TYPES:
            if isinstance(content_type, str) and content_type not in {
                "audio_transcription",
                "code",
                "computer_output",
                "execution_output",
                "reasoning_recap",
                "thoughts",
                "tether_browsing_display",
                "tether_quote",
                "tool_result",
            }:
                unknown_types.add(f"content_type:{content_type}")
            continue
        text = content_text(content.get("parts"))
        if not text:
            continue
        try:
            message_span = object_field_span(data, "message", container=node_span)
        except ValueError:
            malformed += 1
            continue

        message_id = optional_text(message.get("id"))
        parent_node_id = optional_text(node.get("parent"))
        if actor_kind == "user":
            active_turn_id = message_id or mapping_id
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
                occurred_at=timestamp_text(message.get("create_time")),
                message_id=message_id,
                parent_message_id=(
                    message_ids.get(parent_node_id) if parent_node_id is not None else None
                ),
                branch_id=source_branch_path("chatgpt-path", mapping_id, parents),
                turn_id=active_turn_id,
                message_id_kind=("provider_message_id" if message_id is not None else None),
            )
        )

    return (
        conversation_id,
        current_node or conversation_id,
        captured_at,
        tuple(records),
        tuple(sorted(unknown_types)),
        malformed,
    )


def _is_final_assistant_message(message: dict[str, Any]) -> bool:
    recipient = message.get("recipient")
    if isinstance(recipient, str) and recipient not in ("", "all"):
        return False
    channel = message.get("channel")
    return not isinstance(channel, str) or channel in ("", "final")


def _object(data: bytes, label: str) -> dict[str, Any]:
    try:
        loaded: object = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{label} is not a JSON object")
    return cast(dict[str, Any], loaded)
