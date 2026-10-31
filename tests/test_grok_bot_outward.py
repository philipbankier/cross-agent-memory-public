from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory import grok_bot_capture as capture
from cross_assistant_memory.grok_bot_outward import canonical_outward_request
from cross_assistant_memory.grok_bot_transcript import project_transcript_page
from cross_assistant_memory.models import Authority
from cross_assistant_memory.uploads import parse_upload_batch

BOT = "abcdef00-0000-4000-8000-000000000001"


def widget() -> dict[str, object]:
    return {
        "type": "widget",
        "widget": {
            "prompt": "Synthetic decision question",
            "steps": [
                {
                    "prompt": "Choose a synthetic option",
                    "options": [{"label": "Synthetic option", "value": "option-a"}],
                    "allowCustom": True,
                }
            ],
        },
    }


def source(arguments: dict[str, object]) -> bytes:
    record = {
        "role": "assistant",
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "synthetic-structured-send",
                    "name": "SendToUser",
                    "input": arguments,
                }
            ]
        },
    }
    return (
        '<cursor_untrusted_data_fixture source="ReadTranscript">\n\n'
        f'Transcript of agent "Synthetic" ({BOT}), positions 0\u20130 of 1:\n'
        + json.dumps(record)
        + "\n\n</cursor_untrusted_data_fixture>\n"
    ).encode()


@pytest.mark.parametrize(
    ("arguments", "kind"),
    [
        (widget(), "question_request"),
        (
            {"type": "attachment", "url": "file:///workspace/results/synthetic.md"},
            "attachment_reference",
        ),
    ],
)
def test_observed_outward_requests_remain_distinct_and_replayable(
    arguments: dict[str, object], kind: str
) -> None:
    native_kind, content = canonical_outward_request(arguments)
    assert native_kind == kind and json.loads(content) == arguments
    projection = project_transcript_page(source(arguments), expected_bot_id=BOT)
    assert len(projection.replies) == 1
    request = projection.replies[0]
    assert request.kind == kind and request.content_text == content
    assert request.delivery == "requested_not_verified" and request.end_turn is None
    observation = capture.GrokBotStructuredRequestObservation(
        BOT, request.native_tool_call_id, content, kind=cast(capture.StructuredRequestKind, kind)
    )
    raw = observation.canonical_bytes()
    parsed = capture.parse_grok_bot_capture(raw, Path("/synthetic/request.json"))
    assert parsed.parser_version == "0.2.0"
    assert parsed.records[0].event_type == f"native_{kind}"
    assert parsed.records[0].authority is Authority.ASSISTANT_OUTPUT
    assert parsed.records[0].occurred_at is None
    body = capture.build_grok_bot_capture_upload(
        observation, source_account_id="source_account:" + "0" * 64
    )
    batch = parse_upload_batch(body)
    assert batch.parsed.records[0].raw_record == raw
    assert capture.parse_grok_bot_capture_record(raw) == observation
    assert capture.parse_grok_bot_capture_record(raw).canonical_bytes() == raw
    assert "Synthetic decision" not in repr(observation)
    forged = json.loads(body)
    forged["parser"]["version"] = "0.1.0"
    forged.pop("batch_id")
    digest = hashlib.sha256(
        json.dumps(forged, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    forged["batch_id"] = "batch:" + digest
    with pytest.raises(ValueError, match="pinned parser"):
        parse_upload_batch(json.dumps(forged).encode())


def test_text_observation_keeps_its_legacy_wire_identity() -> None:
    original = capture.GrokBotReplyObservation(BOT, "old-call", "Synthetic text", True)
    parsed = capture.parse_grok_bot_capture(original.canonical_bytes(), Path("/synthetic/old.json"))
    assert parsed.parser_version == "0.1.0"
    assert json.loads(original.canonical_bytes())["format_version"] == 1
    with pytest.raises(ValueError):
        capture.parse_grok_bot_capture(
            original.canonical_bytes(), Path("/synthetic/old.json"), parser_version="0.2.0"
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://example.invalid/file?token=private-canary",
        "file://another-host/workspace/results/file.md",
        "file:///workspace/results/file.md?token=private-canary",
        "file:///workspace/results/file.md#private-canary",
        "file:///Users/private-canary.md",
        "file:///workspace/results/../private-canary.md",
        "file:///workspace/results/%2e%2e/private-canary.md",
    ],
)
def test_attachment_references_refuse_unqualified_or_credential_bearing_urls(url: str) -> None:
    with pytest.raises(ValueError) as error:
        canonical_outward_request({"type": "attachment", "url": url})
    assert url not in str(error.value) and "private-canary" not in str(error.value)


@pytest.mark.parametrize("marker", ["[private]", "[no-memory]", "xai-" + "0" * 32])
def test_question_privacy_filter_runs_before_retention(marker: str) -> None:
    arguments = widget()
    cast(dict[str, object], arguments["widget"])["prompt"] = marker
    projected = project_transcript_page(source(arguments), expected_bot_id=BOT)
    assert projected.replies == () and projected.excluded_replies == 1
    assert marker.encode() not in projected.canonical_bytes()


@pytest.mark.parametrize("tamper", ["unknown", "approval", "answer", "option_type", "custom_type"])
def test_unknown_widget_shapes_do_not_become_answers_or_approvals(tamper: str) -> None:
    arguments = widget()
    detail = cast(dict[str, object], arguments["widget"])
    steps = cast(list[dict[str, object]], detail["steps"])
    if tamper in {"unknown", "approval", "answer"}:
        detail[tamper] = "private-canary"
    elif tamper == "option_type":
        cast(list[dict[str, object]], steps[0]["options"])[0]["value"] = True
    else:
        steps[0]["allowCustom"] = "private-canary"
    with pytest.raises(ValueError) as error:
        project_transcript_page(source(arguments), expected_bot_id=BOT)
    assert "private-canary" not in str(error.value)


def test_attachment_reference_does_not_open_its_file(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_read(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("an attachment locator is not permission to read its contents")

    monkeypatch.setattr(Path, "open", no_read)
    kind, content = canonical_outward_request(
        {"type": "attachment", "url": "file:///workspace/results/absent.md"}
    )
    assert kind == "attachment_reference" and "absent.md" in content


@pytest.mark.parametrize("kind", ["question_request", "attachment_reference"])
def test_structured_observation_cannot_claim_native_author_time_or_delivery(kind: str) -> None:
    arguments = (
        widget()
        if kind == "question_request"
        else {"type": "attachment", "url": "file:///workspace/results/absent.md"}
    )
    _kind, content = canonical_outward_request(arguments)
    observation = capture.GrokBotStructuredRequestObservation(
        BOT, "synthetic-send", content, kind=cast(capture.StructuredRequestKind, kind)
    )
    for key, value in (("delivery", "verified"), ("native_author_id", "user"), ("end_turn", True)):
        raw = json.loads(observation.canonical_bytes())
        raw[key] = value
        with pytest.raises(ValueError):
            capture.parse_grok_bot_capture_record(json.dumps(raw).encode())
