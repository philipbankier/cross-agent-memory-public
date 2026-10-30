from __future__ import annotations

import json

import pytest

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
