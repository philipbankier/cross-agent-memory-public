from __future__ import annotations

import hashlib
import json
import traceback
from dataclasses import fields, replace
from pathlib import Path
from typing import Any, cast

import pytest

from cross_assistant_memory.browser_capture_upload import (
    CAPTURE_CAPABILITY,
    PARSER_NAME,
    PARSER_VERSION,
    SCHEMA_FINGERPRINT,
    SCHEMA_JSON,
    browser_observation_uploads,
    validate_browser_upload_batch,
)
from cross_assistant_memory.browser_observation import (
    MAX_ENVELOPE_BYTES,
    BrowserObservation,
    parse_browser_observation,
)
from cross_assistant_memory.models import (
    Authority,
    CollectorProvenance,
    ExclusionReceipt,
    HistoryBase,
    ParsedRecord,
    SourceKind,
    SourceSystem,
)
from cross_assistant_memory.uploads import UploadBatch, build_upload_batch

CONVERSATION = "11111111-2222-4333-8444-555555555555"
MESSAGE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OTHER_MESSAGE = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
ACCOUNT = "source_account:" + "a" * 64


def _observation(provider: str = "chatgpt_web") -> BrowserObservation:
    prefix = {
        "chatgpt_web": "https://chatgpt.com/c/",
        "claude_web": "https://claude.ai/chat/",
        "grok_web": "https://grok.com/c/",
    }[provider]
    value = {
        "format_version": 1,
        "provider": provider,
        "account_binding": ACCOUNT,
        "conversation_id": CONVERSATION,
        "canonical_url": prefix + CONVERSATION,
        "observed_at": "2026-10-20T14:00:00-04:00",
        "capture_kind": "rendered_browser_observation",
        "completeness": "visible_messages_only",
        "messages": [
            {
                "locator": str(index) if provider == "claude_web" else locator,
                "locator_kind": (
                    "rendered_position" if provider == "claude_web" else "provider_message_id"
                ),
                "role": role,
                "text": f"Synthetic {role} text.\nPreserve exact whitespace. ",
            }
            for index, (role, locator) in enumerate(
                [("user", MESSAGE), ("assistant", OTHER_MESSAGE)]
            )
        ],
    }
    return parse_browser_observation(json.dumps(value).encode())


def _batch(provider: str = "chatgpt_web") -> UploadBatch:
    return browser_observation_uploads(_observation(provider))[0]


def _with_record(batch: UploadBatch, **changes: Any) -> UploadBatch:
    return replace(
        batch, parsed=replace(batch.parsed, records=(replace(batch.parsed.records[0], **changes),))
    )


@pytest.mark.parametrize("provider", ["chatgpt_web", "claude_web", "grok_web"])
def test_each_batch_is_one_exact_message_without_historical_time(provider: str) -> None:
    observation = _observation(provider)
    batches = browser_observation_uploads(observation)
    assert type(batches) is tuple
    assert len(batches) == 2
    for batch, message in zip(batches, observation.messages, strict=True):
        parsed = batch.parsed
        record = parsed.records[0]
        assert len(parsed.records) == 1
        single = replace(observation, messages=(message,))
        expected_raw = single.as_dict()
        del expected_raw["observed_at"]
        assert json.loads(record.raw_record) == expected_raw
        assert (
            record.raw_record
            == json.dumps(
                expected_raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        assert validate_browser_upload_batch(batch) == single
        assert batch.request_digest == single.content_digest
        assert batch.batch_id == f"batch:{single.content_digest}"
        assert parsed.file_digest == hashlib.sha256(record.raw_record).hexdigest()
        assert parsed.path == Path(f"/browser-observations/{single.content_digest}.json")
        assert batch.source_path_hash == hashlib.sha256(str(parsed.path).encode()).hexdigest()
        assert parsed.source_system is SourceSystem(provider)
        assert parsed.source_kind is SourceKind.UNKNOWN
        assert parsed.source_label == "browser_observation"
        assert parsed.parser_name == PARSER_NAME == "browser-rendered-observation"
        assert parsed.parser_version == PARSER_VERSION == "0.1.0"
        assert batch.provenance.capture_capability == "rendered_visible_messages_only"
        assert batch.provenance.source_client_version == "unknown"
        assert parsed.captured_at == observation.observed_at
        assert parsed.file_mtime_ns == 0
        assert record.occurred_at is None
        assert parsed.history_base is None
        assert parsed.branch_id is None
        assert parsed.parent_conversation_id is None
        assert record.branch_id is None
        assert record.parent_message_id is None
        assert record.turn_id is None
        assert record.content_text == message.text
        assert record.actor_kind == message.role
        assert record.assistant == (provider if message.role == "assistant" else None)
        assert record.authority is (
            Authority.USER_ASSERTION if message.role == "user" else Authority.ASSISTANT_OUTPUT
        )
        assert (record.record_ordinal, record.byte_start, record.byte_end) == (
            0,
            0,
            len(record.raw_record),
        )
        assert parsed.segment_start_ordinal == parsed.segment_start_byte == 0
        assert parsed.segment_end_ordinal_exclusive == 1
        assert (
            parsed.segment_end_byte
            == parsed.observed_file_size
            == parsed.file_size
            == len(record.raw_record)
        )
        assert parsed.start_prefix_digest == hashlib.sha256(b"").hexdigest()
        assert parsed.end_prefix_digest == parsed.file_digest
        assert not batch.exclusion_receipts
        assert not parsed.unknown_record_types
        assert not parsed.malformed_records


@pytest.mark.parametrize("provider", ["chatgpt_web", "claude_web", "grok_web"])
def test_reopened_capture_reuses_identity_but_keeps_separate_capture_metadata(
    provider: str,
) -> None:
    original = _observation(provider)
    later = replace(original, observed_at="2026-10-21T00:00:00Z")
    for first, replay in zip(
        browser_observation_uploads(original), browser_observation_uploads(later), strict=True
    ):
        assert first.batch_id == replay.batch_id
        assert first.request_digest == replay.request_digest
        assert first.source_path_hash == replay.source_path_hash
        assert first.parsed.records == replay.parsed.records
        assert first.parsed.captured_at != replay.parsed.captured_at
        assert (
            replace(replay, parsed=replace(replay.parsed, captured_at=original.observed_at))
            == first
        )
        assert validate_browser_upload_batch(first).observed_at == original.observed_at
        assert validate_browser_upload_batch(replay).observed_at == later.observed_at


def test_account_isolation_and_content_changes_change_identity() -> None:
    observation = _observation()
    original = browser_observation_uploads(observation)[0]
    changed = [
        replace(observation, account_binding="source_account:" + "b" * 64),
        replace(
            observation,
            conversation_id=OTHER_MESSAGE,
            canonical_url="https://chatgpt.com/c/" + OTHER_MESSAGE,
        ),
        replace(
            observation,
            messages=(replace(observation.messages[0], text="Edited synthetic text."),),
        ),
        replace(
            observation,
            messages=(replace(observation.messages[0], role="assistant"),),
        ),
        replace(
            observation,
            messages=(replace(observation.messages[0], locator=CONVERSATION),),
        ),
        replace(
            observation,
            provider="grok_web",
            canonical_url="https://grok.com/c/" + CONVERSATION,
        ),
    ]
    for alternative in changed:
        batch = browser_observation_uploads(alternative)[0]
        assert batch.batch_id != original.batch_id
        assert batch.source_path_hash != original.source_path_hash
        validate_browser_upload_batch(batch)


def test_message_order_and_neighbors_do_not_change_single_message_identity() -> None:
    original = _observation()
    first, second = browser_observation_uploads(original)
    reversed_batches = browser_observation_uploads(
        replace(original, messages=tuple(reversed(original.messages)))
    )
    assert reversed_batches == (second, first)
    assert browser_observation_uploads(replace(original, messages=(original.messages[0],))) == (
        first,
    )


@pytest.mark.parametrize("provider", ["chatgpt_web", "grok_web"])
def test_provider_message_uuid_is_preserved(provider: str) -> None:
    record = _batch(provider).parsed.records[0]
    assert record.message_id == MESSAGE
    assert record.message_id_kind == "provider_message_id"


def test_claude_position_never_becomes_provider_message_identity() -> None:
    batch = _batch("claude_web")
    record = batch.parsed.records[0]
    assert record.message_id is None
    assert record.message_id_kind is None
    assert json.loads(record.raw_record)["messages"][0]["locator"] == "0"
    assert json.loads(record.raw_record)["messages"][0]["locator_kind"] == "rendered_position"
    with pytest.raises(ValueError):
        validate_browser_upload_batch(
            _with_record(batch, message_id="0", message_id_kind="provider_message_id")
        )


def test_fingerprint_hashes_fixed_durable_schema_not_content() -> None:
    assert hashlib.sha256(SCHEMA_JSON).hexdigest() == SCHEMA_FINGERPRINT
    schema = json.loads(SCHEMA_JSON)
    assert schema["additionalProperties"] is False
    assert "observed_at" not in schema["properties"]
    assert schema["properties"]["messages"]["maxItems"] == 1
    for provider in ["chatgpt_web", "claude_web", "grok_web"]:
        batch = _batch(provider)
        assert batch.parsed.schema_fingerprint == SCHEMA_FINGERPRINT
        assert batch.provenance.schema_fingerprint == SCHEMA_FINGERPRINT


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("batch_id", "batch:" + "0" * 64),
        ("request_digest", "0" * 64),
        ("source_account_id", "source_account:" + "b" * 64),
        ("source_path_hash", "0" * 64),
        ("exclusion_receipts", []),
        ("exclusion_receipts", (ExclusionReceipt(0, 0, 1, "private_marker"),)),
    ],
)
def test_forged_batch_fields_refuse(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        validate_browser_upload_batch(replace(_batch(), **{field: value}))


@pytest.mark.parametrize("field", [item.name for item in fields(CollectorProvenance)])
def test_every_provenance_field_is_bound(field: str) -> None:
    batch = _batch()
    forged = replace(batch, provenance=replace(batch.provenance, **{field: "forged"}))
    with pytest.raises(ValueError):
        validate_browser_upload_batch(forged)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_system", SourceSystem.CODEX),
        ("parser_name", "chatgpt-web"),
        ("parser_version", "9.9.9"),
        ("path", Path("/forged/path.json")),
        ("file_digest", "0" * 64),
        ("file_size", 0),
        ("file_mtime_ns", 1),
        ("conversation_id", OTHER_MESSAGE),
        ("branch_id", "invented"),
        ("captured_at", None),
        ("captured_at", "2026-10-20"),
        ("history_base", HistoryBase(CONVERSATION, 1, 1)),
        ("records", ()),
        ("unknown_record_types", ("unknown",)),
        ("malformed_records", 1),
        ("source_kind", SourceKind.INTERACTIVE),
        ("source_label", "official_export"),
        ("parent_conversation_id", OTHER_MESSAGE),
        ("segment_start_ordinal", 1),
        ("segment_start_byte", 1),
        ("segment_end_ordinal_exclusive", 2),
        ("segment_end_byte", 0),
        ("start_prefix_digest", "0" * 64),
        ("end_prefix_digest", "0" * 64),
        ("observed_file_size", 0),
        ("schema_fingerprint", "0" * 64),
        ("schema_descriptors", ("forged",)),
    ],
)
def test_forged_parse_fields_refuse(field: str, value: object) -> None:
    batch = _batch()
    with pytest.raises(ValueError):
        validate_browser_upload_batch(
            replace(batch, parsed=replace(batch.parsed, **{field: value}))
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("record_ordinal", 1),
        ("byte_start", 1),
        ("byte_end", 0),
        ("event_type", "forged"),
        ("actor_kind", "assistant"),
        ("assistant", "chatgpt_web"),
        ("authority", Authority.ASSISTANT_OUTPUT),
        ("content_text", "Forged synthetic text."),
        ("occurred_at", "2026-10-20T00:00:00Z"),
        ("message_id", OTHER_MESSAGE),
        ("parent_message_id", OTHER_MESSAGE),
        ("branch_id", "invented"),
        ("turn_id", "invented"),
        ("message_id_kind", "rendered_position"),
    ],
)
def test_forged_record_fields_refuse(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        validate_browser_upload_batch(_with_record(_batch(), **{field: value}))


def test_dataclass_equality_cannot_mask_enum_or_boolean_type_forgery() -> None:
    batch = _batch()
    forged = [
        replace(batch, parsed=replace(batch.parsed, file_mtime_ns=cast(int, False))),
        replace(batch, parsed=replace(batch.parsed, segment_end_ordinal_exclusive=cast(int, True))),
        replace(
            batch, parsed=replace(batch.parsed, file_size=cast(int, float(batch.parsed.file_size)))
        ),
        replace(
            batch, parsed=replace(batch.parsed, source_system=cast(SourceSystem, "chatgpt_web"))
        ),
        replace(batch, parsed=replace(batch.parsed, source_kind=cast(SourceKind, "unknown"))),
        _with_record(batch, authority="user_assertion"),
        _with_record(batch, byte_start=False),
    ]
    for item in forged:
        assert item == batch
        with pytest.raises(ValueError):
            validate_browser_upload_batch(item)


@pytest.mark.parametrize("target", ["batch", "parsed", "record", "provenance"])
def test_extra_dataclass_fields_refuse(target: str) -> None:
    batch = _batch()
    item = {
        "batch": batch,
        "parsed": batch.parsed,
        "record": batch.parsed.records[0],
        "provenance": batch.provenance,
    }[target]
    object.__setattr__(item, "unexpected", "synthetic extra field")
    with pytest.raises(ValueError):
        validate_browser_upload_batch(batch)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff",
        b"null",
        b"[]",
        b"{}",
        b'{"value":NaN}',
        b"[" * 2000 + b"]" * 2000,
        b"x" * (MAX_ENVELOPE_BYTES + 1),
        "{}".encode("utf-16"),
    ],
)
def test_invalid_raw_record_refuses(raw: bytes) -> None:
    with pytest.raises(ValueError):
        validate_browser_upload_batch(_with_record(_batch(), raw_record=raw))


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "duplicate",
        "time",
        "many_messages",
        "text",
        "role",
        "account",
        "secret",
        "private",
        "space",
    ],
)
def test_raw_record_is_strict_reparsed_and_not_trusted(change: str) -> None:
    batch = _batch()
    original = batch.parsed.records[0].raw_record
    raw: dict[str, Any] = json.loads(original)
    if change == "extra":
        raw["unexpected"] = "synthetic"
    elif change == "time":
        raw["observed_at"] = batch.parsed.captured_at
    elif change == "many_messages":
        raw["messages"].append({**raw["messages"][0], "locator": OTHER_MESSAGE})
    elif change == "text":
        raw["messages"][0]["text"] = "Different synthetic text."
    elif change == "role":
        raw["messages"][0]["role"] = "assistant"
    elif change == "account":
        raw["account_binding"] = "source_account:" + "b" * 64
    elif change == "secret":
        raw["messages"][0]["text"] = "sk-" + "a" * 24
    elif change == "private":
        raw["messages"][0]["text"] = "[private] Synthetic exclusion"
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    if change == "duplicate":
        encoded = b'{"provider":"grok_web",' + original[1:]
    elif change == "space":
        encoded = original + b" "
    with pytest.raises(ValueError):
        validate_browser_upload_batch(_with_record(batch, raw_record=encoded))


def test_whole_snapshot_admission_happens_before_splitting() -> None:
    observation = _observation()
    object.__setattr__(observation.messages[1], "text", "[no-memory] Synthetic exclusion")
    with pytest.raises(ValueError):
        browser_observation_uploads(observation)


def test_exact_one_record_and_immutable_containers_are_required() -> None:
    batch = _batch()
    for records in [
        batch.parsed.records * 2,
        cast(tuple[ParsedRecord, ...], list(batch.parsed.records)),
    ]:
        with pytest.raises(ValueError):
            validate_browser_upload_batch(
                replace(batch, parsed=replace(batch.parsed, records=records))
            )
    with pytest.raises(ValueError):
        validate_browser_upload_batch(cast(UploadBatch, batch.parsed))
    with pytest.raises(ValueError):
        browser_observation_uploads(cast(BrowserObservation, batch))


def test_failures_are_sanitized() -> None:
    sentinel = "SYNTHETIC_PRIVATE_SENTINEL"
    batch = _with_record(_batch(), raw_record=b'{"' + sentinel.encode() + b'":')
    with pytest.raises(ValueError) as caught:
        validate_browser_upload_batch(batch)
    assert sentinel not in "".join(traceback.format_exception(caught.value))
    assert caught.value.__cause__ is None


def test_native_upload_builder_remains_native_only() -> None:
    batch = _batch()
    with pytest.raises(ValueError, match="native sources only"):
        build_upload_batch(
            batch.parsed,
            source_account_id=batch.source_account_id,
            provenance=batch.provenance,
        )
    assert CAPTURE_CAPABILITY != "native-jsonl-history"
