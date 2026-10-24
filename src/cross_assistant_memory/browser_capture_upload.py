from __future__ import annotations

import hashlib
import json
from dataclasses import fields, replace
from pathlib import Path
from typing import NoReturn, cast

from cross_assistant_memory.browser_observation import (
    MAX_ENVELOPE_BYTES,
    MAX_TEXT_BYTES,
    BrowserObservation,
    parse_browser_observation,
)
from cross_assistant_memory.models import (
    Authority,
    CollectorProvenance,
    ParsedRecord,
    ParseResult,
    SourceKind,
    SourceSystem,
)
from cross_assistant_memory.uploads import UploadBatch

PARSER_NAME = "browser-rendered-observation"
PARSER_VERSION = "0.1.0"
CAPTURE_CAPABILITY = "rendered_visible_messages_only"
_EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()
_UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_PROVIDER_URLS = {
    "chatgpt_web": r"^https://chatgpt\.com/c/",
    "claude_web": r"^https://claude\.ai/chat/",
    "grok_web": r"^https://grok\.com/c/",
}

# This describes the durable record, not an official export or the native upload wire format.
SCHEMA_JSON = json.dumps(
    {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format_version",
            "provider",
            "account_binding",
            "conversation_id",
            "canonical_url",
            "capture_kind",
            "completeness",
            "messages",
        ],
        "properties": {
            "format_version": {"type": "integer", "const": 1},
            "provider": {"type": "string", "enum": list(_PROVIDER_URLS)},
            "account_binding": {"type": "string", "pattern": r"^source_account:[0-9a-f]{64}$"},
            "conversation_id": {"type": "string", "pattern": _UUID_PATTERN},
            "canonical_url": {
                "type": "string",
                "x-conversation-id-must-match": True,
            },
            "capture_kind": {"type": "string", "const": "rendered_browser_observation"},
            "completeness": {"type": "string", "const": "visible_messages_only"},
            "messages": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["locator", "locator_kind", "role", "text"],
                    "properties": {
                        "locator": {"type": "string", "maxLength": 1024},
                        "locator_kind": {
                            "type": "string",
                            "enum": ["provider_message_id", "rendered_position"],
                        },
                        "role": {"type": "string", "enum": ["user", "assistant"]},
                        "text": {
                            "type": "string",
                            "x-nonblank": True,
                            "x-max-utf8-bytes": MAX_TEXT_BYTES,
                        },
                    },
                },
            },
        },
        "allOf": [
            {
                "if": {"properties": {"provider": {"const": provider}}},
                "then": {
                    "properties": {
                        "canonical_url": {"pattern": prefix + _UUID_PATTERN.removeprefix("^")},
                        "messages": {
                            "items": {
                                "properties": {
                                    "locator_kind": {
                                        "const": (
                                            "rendered_position"
                                            if provider == "claude_web"
                                            else "provider_message_id"
                                        )
                                    },
                                    "locator": {
                                        "pattern": (
                                            r"^(0|[1-9][0-9]*)$"
                                            if provider == "claude_web"
                                            else _UUID_PATTERN
                                        )
                                    },
                                }
                            }
                        },
                    }
                },
            }
            for provider, prefix in _PROVIDER_URLS.items()
        ],
        "x-max-envelope-bytes": MAX_ENVELOPE_BYTES,
        "x-observed-at": "external captured_at metadata only; absent from durable record",
    },
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
SCHEMA_FINGERPRINT = hashlib.sha256(SCHEMA_JSON).hexdigest()


def browser_observation_uploads(observation: BrowserObservation) -> tuple[UploadBatch, ...]:
    try:
        if type(observation) is not BrowserObservation:
            raise ValueError("browser observation is required")
        # Validate the whole snapshot before splitting, including cross-message admission.
        validated = parse_browser_observation(observation.canonical_bytes())
        return tuple(
            _single_message_upload(replace(validated, messages=(message,)))
            for message in validated.messages
        )
    except Exception:
        raise ValueError("browser observation cannot be adapted for upload") from None


def validate_browser_upload_batch(batch: UploadBatch) -> BrowserObservation:
    try:
        if (
            type(batch) is not UploadBatch
            or type(batch.parsed) is not ParseResult
            or type(batch.parsed.records) is not tuple
            or len(batch.parsed.records) != 1
            or type(batch.parsed.records[0]) is not ParsedRecord
            or type(batch.parsed.captured_at) is not str
        ):
            raise ValueError("browser upload shape is invalid")
        raw = batch.parsed.records[0].raw_record
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_ENVELOPE_BYTES:
            raise ValueError("browser upload raw record is invalid")
        value: object = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if not isinstance(value, dict):
            raise ValueError("browser upload raw record must be an object")
        root = cast(dict[str, object], value)
        if "observed_at" in root:
            raise ValueError("browser upload raw record must not contain observation time")
        root["observed_at"] = batch.parsed.captured_at
        observation = parse_browser_observation(_canonical_json(root))
        if len(observation.messages) != 1:
            raise ValueError("browser upload requires one message")
        if not _exact_match(batch, _single_message_upload(observation)):
            raise ValueError("browser upload fields do not match the raw observation")
        return observation
    except Exception:
        raise ValueError("browser observation upload batch is invalid") from None


def _single_message_upload(observation: BrowserObservation) -> UploadBatch:
    value = observation.as_dict()
    del value["observed_at"]
    raw = _canonical_json(value)
    digest = hashlib.sha256(raw).hexdigest()
    path = Path(f"/browser-observations/{digest}.json")
    message = observation.messages[0]
    provider_id = message.locator if message.locator_kind == "provider_message_id" else None
    record = ParsedRecord(
        raw_record=raw,
        record_ordinal=0,
        byte_start=0,
        byte_end=len(raw),
        event_type="message",
        actor_kind=message.role,
        assistant=observation.provider if message.role == "assistant" else None,
        authority=(
            Authority.USER_ASSERTION if message.role == "user" else Authority.ASSISTANT_OUTPUT
        ),
        content_text=message.text,
        occurred_at=None,
        message_id=provider_id,
        parent_message_id=None,
        branch_id=None,
        turn_id=None,
        message_id_kind="provider_message_id" if provider_id is not None else None,
    )
    parsed = ParseResult(
        source_system=SourceSystem(observation.provider),
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        path=path,
        file_digest=digest,
        file_size=len(raw),
        file_mtime_ns=0,
        conversation_id=observation.conversation_id,
        branch_id=None,
        captured_at=observation.observed_at,
        history_base=None,
        records=(record,),
        unknown_record_types=(),
        malformed_records=0,
        source_kind=SourceKind.UNKNOWN,
        source_label="browser_observation",
        parent_conversation_id=None,
        segment_start_ordinal=0,
        segment_start_byte=0,
        segment_end_ordinal_exclusive=1,
        segment_end_byte=len(raw),
        start_prefix_digest=_EMPTY_DIGEST,
        end_prefix_digest=digest,
        observed_file_size=len(raw),
        schema_fingerprint=SCHEMA_FINGERPRINT,
        schema_descriptors=(),
    )
    return UploadBatch(
        batch_id=f"batch:{digest}",
        request_digest=digest,
        source_account_id=observation.account_binding,
        source_path_hash=hashlib.sha256(str(path).encode("utf-8")).hexdigest(),
        provenance=CollectorProvenance(
            source_client=observation.provider,
            source_client_version="unknown",
            capture_capability=CAPTURE_CAPABILITY,
            adapter_name=PARSER_NAME,
            adapter_version=PARSER_VERSION,
            schema_fingerprint=SCHEMA_FINGERPRINT,
        ),
        parsed=parsed,
        exclusion_receipts=(),
    )


def _exact_match(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, (UploadBatch, ParseResult, ParsedRecord, CollectorProvenance)):
        members = fields(expected)
        if set(vars(actual)) != {member.name for member in members}:
            return False
        return all(
            _exact_match(getattr(actual, member.name), getattr(expected, member.name))
            for member in members
        )
    if isinstance(expected, tuple):
        left = cast(tuple[object, ...], actual)
        right = cast(tuple[object, ...], expected)
        return len(left) == len(right) and all(
            _exact_match(item, counterpart) for item, counterpart in zip(left, right, strict=True)
        )
    return actual == expected


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("browser upload contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise ValueError("browser upload contains a non-JSON constant")
