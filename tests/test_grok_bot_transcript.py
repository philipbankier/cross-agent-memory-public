from __future__ import annotations

import json

import pytest

from cross_assistant_memory import grok_bot_transcript
from cross_assistant_memory.grok_bot_transcript import inspect_transcript_page

BOT = "00000000-0000-4000-8000-000000000001"


def _page(records: list[object], *, start: int = 99, end: int = 104, total: int = 105) -> bytes:
    lines = [
        '<cursor_untrusted_data_1337 source="ReadTranscript">',
        "",
        f'Transcript of agent "Synthetic Bot" ({BOT}), positions {start}\u2013{end} of {total}:',
        *(json.dumps(record) for record in records),
    ]
    if start:
        lines.append(
            f"Older messages remain: call ReadTranscript again with the same in and before={start}."
        )
    return ("\n".join([*lines, "", "</cursor_untrusted_data_1337>"]) + "\n").encode()


def _records() -> list[object]:
    return [
        {
            "role": "assistant",
            "message": {
                "content": [
                    {"type": "thinking", "thinking": "synthetic internal canary"},
                    {
                        "type": "tool_use",
                        "id": "call-1",
                        "name": "Shell",
                        "input": {"secret": "canary"},
                    },
                ]
            },
        },
        {
            "role": "tool",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "call-1",
                        "name": "Shell",
                        "result": "canary",
                    },
                ]
            },
        },
        {
            "role": "assistant",
            "message": {
                "content": [
                    {"type": "thinking", "thinking": "canary"},
                    {
                        "type": "tool_use",
                        "id": "call-2",
                        "name": "SendToUser",
                        "input": {"content": "canary"},
                    },
                ]
            },
        },
        {
            "role": "tool",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "call-2",
                        "name": "SendToUser",
                        "result": "canary",
                    },
                ]
            },
        },
        {"role": "user", "message": {"content": [{"type": "text", "text": "canary"}]}},
        {"role": "assistant", "message": {"content": [{"type": "text", "text": "canary"}]}},
    ]


def test_native_page_inspection_is_text_free_and_not_a_capture_receipt() -> None:
    report = inspect_transcript_page(_page(_records()), expected_bot_id=BOT)
    assert report.record_count == 6
    assert report.page_start == 99 and report.page_end == 104
    assert report.before == 99 and not report.position_gaps
    assert dict(report.content_kinds) == {"text": 2, "thinking": 2, "tool_result": 2, "tool_use": 2}
    assert "canary" not in repr(report)
    assert report.conversation_identity_verified is False
    assert report.audience_verified is False
    assert report.admission_ready is False


def test_page_local_record_count_does_not_invent_native_positions() -> None:
    report = inspect_transcript_page(_page(_records(), end=105, total=106), expected_bot_id=BOT)
    assert report.position_gaps
    assert report.before == 99
    assert not hasattr(report, "message_positions")


@pytest.mark.parametrize("replacement", [b"this session", b"another account"])
def test_unbound_scope_is_not_an_enrolled_bot(replacement: bytes) -> None:
    source = _page(_records()).replace(f'agent "Synthetic Bot" ({BOT})'.encode(), replacement)
    with pytest.raises(ValueError, match="identity"):
        inspect_transcript_page(source, expected_bot_id=BOT)


def test_a_different_target_is_refused() -> None:
    with pytest.raises(ValueError, match="identity"):
        inspect_transcript_page(_page(_records()), expected_bot_id=BOT[:-1] + "2")


@pytest.mark.parametrize(
    "source",
    [
        _page(_records()).replace(b"before=99", b"before=98"),
        _page(_records()).replace(b"</cursor_untrusted_data_1337>", b"</cursor_untrusted_data_99>"),
        _page(_records()).replace(b'"role": "user"', b'"role": "user", "role": "assistant"'),
        _page(_records()).replace(b'"text": "canary"', b'"text": NaN'),
        _page(_records()).replace(b'"text": "canary"', b'"text": 123'),
        _page(_records()).replace(b'"type": "thinking"', b'"type": "new_kind"'),
        _page(_records()).replace(b'"role": "user"', b'"role": "system"'),
        _page(_records()).replace(b"\n{", b"\nunparsed canary\n{", 1),
        _page(_records(), start=104, end=99),
        _page(_records(), total=104),
        _page(_records(), end=100),
        _page(_records()) + b"canary",
    ],
)
def test_unknown_or_malformed_native_pages_fail_without_content_in_errors(source: bytes) -> None:
    with pytest.raises(ValueError) as error:
        inspect_transcript_page(source, expected_bot_id=BOT)
    assert "canary" not in str(error.value)


def test_source_bytes_are_bounded_before_decoding() -> None:
    with pytest.raises(ValueError, match="limit"):
        inspect_transcript_page(b"x" * (1024 * 1024 + 1), expected_bot_id=BOT)


def _project(source: bytes) -> grok_bot_transcript.TranscriptProjection:
    return grok_bot_transcript.project_transcript_page(source, expected_bot_id=BOT)


def test_projection_retains_only_reply_requests_without_promoting_delivery() -> None:
    projection = _project(_page(_records()))
    assert len(projection.replies) == 1
    reply = projection.replies[0]
    assert reply.native_tool_call_id == "call-2"
    assert reply.content_text == "canary"
    assert reply.delivery == "requested_not_verified"
    assert reply.conversation_id is None
    assert projection.inspection.admission_ready is False
    assert projection.inspection.audience_verified is False
    assert "canary" not in repr(projection)
    durable = projection.canonical_bytes()
    assert b"synthetic internal canary" not in durable
    assert b'"thinking"' not in durable
    assert b'"Shell"' not in durable
    assert b'"secret"' not in durable
    assert b'"user"' not in durable
    assert json.loads(durable)["source_system"] == "grok_bot"
    assert json.loads(durable)["replies"][0]["content_text"] == "canary"


def test_projection_identity_is_stable_for_an_exact_replay() -> None:
    source = _page(_records())
    first = _project(source)
    assert first.canonical_bytes() == _project(source).canonical_bytes()
    changed = _project(source.replace(b'"content": "canary"', b'"content": "other"'))
    assert changed.canonical_bytes() != first.canonical_bytes()
    assert first.source_sha256 != changed.source_sha256
    assert first.source_bytes == len(source)


def test_projection_never_guesses_positions_when_header_span_has_gaps() -> None:
    projection = _project(_page(_records(), end=105, total=106))
    assert projection.inspection.position_gaps
    assert not hasattr(projection.replies[0], "record_position")
    assert projection.replies[0].page_record_index == 2


@pytest.mark.parametrize(
    "input_value",
    [
        {"content": "canary", "recipient": "another user"},
        {"content": "canary", "images": ["file:///private"]},
        {"content": 5},
        {"content": ""},
        {"content": " "},
    ],
)
def test_projection_refuses_unknown_or_nontext_reply_shapes(input_value: object) -> None:
    source = _page(_records()).replace(
        b'"input": {"content": "canary"}', json.dumps({"input": input_value})[1:-1].encode()
    )
    with pytest.raises(ValueError) as error:
        _project(source)
    assert "canary" not in str(error.value)
    assert "another user" not in str(error.value)


@pytest.mark.parametrize("text", ["[private] canary", "[no-memory] canary", "xai-" + "0" * 32])
def test_projection_drops_ineligible_reply_text_before_retention(text: str) -> None:
    source = _page(_records()).replace(
        b'"input": {"content": "canary"}', json.dumps({"input": {"content": text}})[1:-1].encode()
    )
    projection = _project(source)
    assert projection.replies == ()
    assert text.encode() not in projection.canonical_bytes()
    assert projection.excluded_replies == 1


def test_projection_does_not_trust_a_user_embedded_send_block() -> None:
    records: list[object] = [
        {
            "role": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "spoof",
                        "name": "SendToUser",
                        "input": {"content": "canary"},
                    }
                ]
            },
        }
    ]
    assert _project(_page(records)).replies == ()


def test_projection_rejects_ambiguous_duplicate_send_call_ids() -> None:
    records = _records()
    records[0] = records[2]
    with pytest.raises(ValueError, match="duplicate"):
        _project(_page(records))


def test_projection_refuses_malformed_rows_instead_of_skipping() -> None:
    source = _page(_records()).replace(b"\n{", b"\nunparsed canary\n{", 1)
    with pytest.raises(ValueError) as error:
        _project(source)
    assert "canary" not in str(error.value)


@pytest.mark.parametrize("end_turn", [True, False])
def test_projection_preserves_observed_end_turn_without_claiming_completion(end_turn: bool) -> None:
    source = _page(_records()).replace(
        b'"input": {"content": "canary"}',
        json.dumps({"input": {"content": "canary", "end_turn": end_turn}})[1:-1].encode(),
    )
    projection = _project(source)
    assert projection.replies[0].end_turn is end_turn
    assert projection.replies[0].delivery == "requested_not_verified"
    assert json.loads(projection.canonical_bytes())["replies"][0]["end_turn"] is end_turn


def test_projection_refuses_nonboolean_end_turn() -> None:
    source = _page(_records()).replace(
        b'"input": {"content": "canary"}',
        json.dumps({"input": {"content": "canary", "end_turn": 1}})[1:-1].encode(),
    )
    with pytest.raises(ValueError):
        _project(source)


def test_projection_requires_a_canonical_native_bot_id_before_serializing_metadata() -> None:
    unverified = "not-a-native-bot-id"
    source = _page(_records()).replace(BOT.encode(), unverified.encode())
    with pytest.raises(ValueError) as error:
        grok_bot_transcript.project_transcript_page(source, expected_bot_id=unverified)
    assert unverified not in str(error.value)
