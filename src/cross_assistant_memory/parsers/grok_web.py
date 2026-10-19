from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.models import Authority, ParsedRecord
from cross_assistant_memory.parsers.common import optional_text, source_branch_path, timestamp_text
from cross_assistant_memory.parsers.json_bytes import object_array_value_spans, object_field_span

PARSER_NAME = "grok-web-export-json"
PARSER_VERSION = "0.3.0"
_ASSISTANT_SENDERS = frozenset({"assistant", "ASSISTANT", "grok-4"})


def parse_grok_web_records(
    data: bytes, path: Path
) -> tuple[
    str,
    str,
    str | None,
    tuple[ParsedRecord, ...],
    tuple[str, ...],
    int,
]:
    document = _object(data, "Grok web conversation")
    conversation = document.get("conversation")
    if not isinstance(conversation, dict):
        raise ValueError("Grok web conversation metadata is missing")
    metadata = cast(dict[str, Any], conversation)
    conversation_id = _required_text(metadata, "id", "Grok web conversation")
    leaf_response_id = optional_text(metadata.get("leaf_response_id"))
    captured_at = timestamp_text(metadata.get("create_time"))
    response_spans = object_array_value_spans(data, "responses")
    responses_value = document.get("responses")
    responses = cast(list[object], responses_value) if isinstance(responses_value, list) else []
    parents: dict[str, str | None] = {}
    for item in responses:
        if not isinstance(item, dict):
            continue
        response_value = cast(dict[str, Any], item).get("response")
        if not isinstance(response_value, dict):
            continue
        response = cast(dict[str, Any], response_value)
        message_id = optional_text(response.get("_id"))
        if message_id is not None:
            parents[message_id] = optional_text(response.get("parent_response_id"))
    records: list[ParsedRecord] = []
    unknown_types: set[str] = set()
    malformed = 0
    active_turn_id: str | None = None

    for ordinal, wrapper_span in enumerate(response_spans):
        try:
            wrapper = _object(wrapper_span.bytes(data), "Grok web response wrapper")
            response_value = wrapper.get("response")
            if not isinstance(response_value, dict):
                raise ValueError("Grok web response is missing")
            response = cast(dict[str, Any], response_value)
            response_span = object_field_span(data, "response", container=wrapper_span)
        except ValueError:
            malformed += 1
            continue

        sender = response.get("sender")
        if sender in ("human", "user"):
            actor_kind = "user"
            assistant = None
            authority = Authority.USER_ASSERTION
        elif isinstance(sender, str) and sender in _ASSISTANT_SENDERS:
            actor_kind = "assistant"
            assistant = "grok_web"
            authority = Authority.ASSISTANT_OUTPUT
        elif sender in ("system", "tool"):
            continue
        elif isinstance(sender, str):
            unknown_types.add(f"sender:{sender}")
            continue
        else:
            malformed += 1
            continue

        text = optional_text(response.get("message"))
        field_name = "message"
        if text is None:
            text = optional_text(response.get("query"))
            field_name = "query"
        if text is None:
            continue
        try:
            object_field_span(data, field_name, container=response_span)
        except ValueError:
            malformed += 1
            continue

        message_id = optional_text(response.get("_id"))
        if actor_kind == "user":
            active_turn_id = message_id or f"response-{ordinal}"
        records.append(
            ParsedRecord(
                raw_record=response_span.bytes(data),
                record_ordinal=ordinal,
                byte_start=response_span.start,
                byte_end=response_span.end,
                event_type="message",
                actor_kind=actor_kind,
                assistant=assistant,
                authority=authority,
                content_text=text,
                occurred_at=timestamp_text(response.get("create_time")),
                message_id=message_id,
                parent_message_id=optional_text(response.get("parent_response_id")),
                branch_id=source_branch_path("grok-path", message_id, parents),
                turn_id=active_turn_id,
                message_id_kind=("provider_message_id" if message_id is not None else None),
            )
        )

    return (
        conversation_id,
        leaf_response_id or conversation_id,
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
