from __future__ import annotations

import json
import traceback
from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

from cross_assistant_memory.browser_observation import (
    MAX_ENVELOPE_BYTES,
    MAX_MESSAGES,
    MAX_TEXT_BYTES,
    BrowserObservation,
    parse_browser_observation,
)

CONVERSATION = "11111111-2222-4333-8444-555555555555"
MESSAGE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OTHER_MESSAGE = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
ACCOUNT = "source_account:" + "a" * 64
OTHER_ACCOUNT = "source_account:" + "b" * 64


def _envelope(provider: str = "chatgpt_web") -> dict[str, Any]:
    prefixes = {
        "chatgpt_web": "https://chatgpt.com/c/",
        "claude_web": "https://claude.ai/chat/",
        "grok_web": "https://grok.com/c/",
    }
    return {
        "format_version": 1,
        "provider": provider,
        "account_binding": ACCOUNT,
        "conversation_id": CONVERSATION,
        "canonical_url": prefixes[provider] + CONVERSATION,
        "observed_at": "2026-10-20T14:30:00-04:00",
        "capture_kind": "rendered_browser_observation",
        "completeness": "visible_messages_only",
        "messages": [
            {
                "locator": "0" if provider == "claude_web" else MESSAGE,
                "locator_kind": (
                    "rendered_position" if provider == "claude_web" else "provider_message_id"
                ),
                "role": "user",
                "text": "Synthetic request.",
            },
            {
                "locator": "1" if provider == "claude_web" else OTHER_MESSAGE,
                "locator_kind": (
                    "rendered_position" if provider == "claude_web" else "provider_message_id"
                ),
                "role": "assistant",
                "text": "Synthetic response.\nNo provider time was observed.",
            },
        ],
    }


def _encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


@pytest.mark.parametrize("provider", ["chatgpt_web", "claude_web", "grok_web"])
def test_valid_snapshot_is_immutable_and_round_trips(provider: str) -> None:
    value = _envelope(provider)
    snapshot = parse_browser_observation(_encode(value))
    assert snapshot.as_dict() == value
    assert parse_browser_observation(snapshot.canonical_bytes()) == snapshot
    assert isinstance(snapshot.messages, tuple)
    for target, attribute in [(snapshot, "observed_at"), (snapshot.messages[0], "text")]:
        with pytest.raises(FrozenInstanceError):
            setattr(target, attribute, "Changed")
    copied = snapshot.as_dict()
    copied["messages"] = []
    assert len(snapshot.messages) == 2
    assert not hasattr(snapshot, "occurred_at")
    assert "occurred_at" not in snapshot.as_dict()


def test_canonical_serialization_and_time_independent_digest() -> None:
    value = _envelope()
    first = parse_browser_observation(_encode(value))
    reordered = {key: value[key] for key in reversed(value)}
    assert (
        parse_browser_observation(_encode(reordered)).canonical_bytes() == first.canonical_bytes()
    )
    value["observed_at"] = "2026-10-22T10:00:00.123456Z"
    later = parse_browser_observation(_encode(value))
    assert later.content_digest == first.content_digest
    assert later.canonical_bytes() != first.canonical_bytes()
    assert later.observed_at == value["observed_at"]
    assert len(first.content_digest) == 64


@pytest.mark.parametrize(
    "change",
    ["account", "provider", "conversation", "role", "order", "locator", "text", "whitespace"],
)
def test_digest_binds_all_content_identity_fields(change: str) -> None:
    value = _envelope()
    original = parse_browser_observation(_encode(value))
    if change == "account":
        value["account_binding"] = OTHER_ACCOUNT
    elif change == "provider":
        value["provider"] = "grok_web"
        value["canonical_url"] = "https://grok.com/c/" + CONVERSATION
    elif change == "conversation":
        value["conversation_id"] = OTHER_MESSAGE
        value["canonical_url"] = "https://chatgpt.com/c/" + OTHER_MESSAGE
    elif change == "role":
        value["messages"][0]["role"] = "assistant"
    elif change == "order":
        value["messages"].reverse()
    elif change == "locator":
        value["messages"][0]["locator"] = CONVERSATION
    else:
        value["messages"][0]["text"] += " " if change == "whitespace" else " Edited."
    assert parse_browser_observation(_encode(value)).content_digest != original.content_digest


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("format_version", True),
        ("format_version", 1.0),
        ("format_version", "1"),
        ("format_version", 2),
        ("provider", "codex"),
        ("provider", "chatgpt"),
        ("provider", None),
        ("account_binding", ""),
        ("account_binding", "primary"),
        ("account_binding", "synthetic@example.invalid"),
        ("account_binding", " " + ACCOUNT),
        ("account_binding", ACCOUNT + "\n"),
        ("account_binding", ACCOUNT.upper()),
        ("account_binding", [ACCOUNT, OTHER_ACCOUNT]),
        ("account_binding", {"source_account_id": ACCOUNT}),
        ("conversation_id", MESSAGE.upper()),
        ("conversation_id", "not-a-uuid"),
        ("conversation_id", CONVERSATION.replace("-", "")),
        ("conversation_id", OTHER_MESSAGE),
        ("capture_kind", "official_export"),
        ("completeness", "complete"),
        ("messages", []),
        ("messages", {}),
        ("messages", None),
    ],
)
def test_invalid_envelope_fields(field: str, bad: object) -> None:
    value = _envelope()
    value[field] = bad
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


@pytest.mark.parametrize(
    "url",
    [
        "http://chatgpt.com/c/" + CONVERSATION,
        "https://chatgpt.com.evil.invalid/c/" + CONVERSATION,
        "https://chatgpt.com@evil.invalid/c/" + CONVERSATION,
        "https://user@chatgpt.com/c/" + CONVERSATION,
        "https://chatgpt.com:443/c/" + CONVERSATION,
        "https://chatgpt.com/c/" + CONVERSATION + "?",
        "https://chatgpt.com/c/" + CONVERSATION + "#",
        "https://chatgpt.com/c/" + CONVERSATION + "/",
        "https://chatgpt.com/c/%31" + CONVERSATION[1:],
        "https://chatgpt.com/chat/" + CONVERSATION,
        "https://grok.com/c/" + CONVERSATION,
        "https://CHATGPT.COM/c/" + CONVERSATION,
        "\nhttps://chatgpt.com/c/" + CONVERSATION,
    ],
)
def test_noncanonical_or_wrong_origin_urls_refuse(url: str) -> None:
    value = _envelope()
    value["canonical_url"] = url
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-10-20",
        "2026-10-20T14:30:00",
        "2026-10-20 14:30:00Z",
        "20261020T143000Z",
        "2026-02-30T14:30:00Z",
        "2026-10-20T24:00:00Z",
        "2026-10-20T14:30:60Z",
        "2026-10-20T14:30:00+24:00",
        "2026-10-20T14:30:00+01:60",
        "2026-10-20T14:30:00-00:00",
        "2026-10-20T14:30:00Z\n",
        1792500000,
        None,
    ],
)
def test_invalid_or_ambiguous_observed_time(timestamp: object) -> None:
    value = _envelope()
    value["observed_at"] = timestamp
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


@pytest.mark.parametrize("provider", ["chatgpt_web", "grok_web", "claude_web"])
def test_locator_kinds_are_provider_bound(provider: str) -> None:
    value = _envelope(provider)
    value["messages"][0]["locator_kind"] = (
        "provider_message_id" if provider == "claude_web" else "rendered_position"
    )
    value["messages"][0]["locator"] = MESSAGE
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("locator", ""),
        ("locator", "transcript:0"),
        ("locator", MESSAGE.upper()),
        ("locator", MESSAGE.replace("-", "")),
        ("locator", None),
        ("locator_kind", "provider_id"),
        ("role", "system"),
        ("role", "User"),
        ("role", None),
        ("text", ""),
        ("text", " \t\r\n"),
        ("text", "\u2003"),
        ("text", ["Synthetic request"]),
        ("text", None),
    ],
)
def test_invalid_message_fields(field: str, bad: object) -> None:
    value = _envelope()
    value["messages"][0][field] = bad
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


def test_claude_positions_are_local_not_provider_ids() -> None:
    snapshot = parse_browser_observation(_encode(_envelope("claude_web")))
    assert snapshot.messages[0].locator == "0"
    assert snapshot.messages[0].locator_kind == "rendered_position"
    assert "message_id" not in snapshot.messages[0].as_dict()


@pytest.mark.parametrize(
    "locator",
    [" 0", "0\n", "\x000", "x" * 1025, "00", "01", "-1", "+1", "1.0", "\u0661", "transcript:0"],
)
def test_claude_position_locators_are_bounded(locator: str) -> None:
    value = _envelope("claude_web")
    value["messages"][0]["locator"] = locator
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


def test_duplicate_locator_role_pairs_refuse_but_distinct_roles_are_allowed() -> None:
    value = _envelope()
    value["messages"].append(dict(value["messages"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        parse_browser_observation(_encode(value))
    value["messages"][-1]["role"] = "assistant"
    assert len(parse_browser_observation(_encode(value)).messages) == 3


@pytest.mark.parametrize("location", ["envelope", "message"])
@pytest.mark.parametrize("operation", ["extra", "missing"])
def test_exact_object_shapes(location: str, operation: str) -> None:
    value = _envelope()
    target = value if location == "envelope" else value["messages"][0]
    if operation == "extra":
        target["unexpected"] = "Synthetic extra field."
    else:
        del target[next(iter(target))]
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\xff",
        b"null",
        b"[]",
        b"{}",
        b'{"provider": "chatgpt_web", "provider": "grok_web"}',
        b'{"messages":[{"text":"one","text":"two"}]}',
        b'{"value": NaN}',
        b'{"value": Infinity}',
        b"[" * 2000 + b"]" * 2000,
        b'{"text":"' + b"\\ud800" + b'"}',
        "{}".encode("utf-16"),
    ],
)
def test_invalid_json_refuses(body: bytes) -> None:
    with pytest.raises(ValueError):
        parse_browser_observation(body)


def test_surrogate_in_valid_envelope_refuses() -> None:
    value = _envelope()
    value["messages"][0]["text"] = "\ud800"
    with pytest.raises(ValueError):
        parse_browser_observation(json.dumps(value).encode("ascii"))


def test_message_count_limit() -> None:
    value = _envelope("claude_web")
    value["messages"] = [
        {**value["messages"][0], "locator": str(index)} for index in range(MAX_MESSAGES)
    ]
    assert len(parse_browser_observation(_encode(value)).messages) == MAX_MESSAGES
    value["messages"].append({**value["messages"][0], "locator": "100"})
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


def test_text_limit_counts_utf8_bytes_and_preserves_text() -> None:
    value = _envelope()
    text = "\u00e9" * (MAX_TEXT_BYTES // 2)
    value["messages"][0]["text"] = text
    snapshot = parse_browser_observation(_encode(value))
    assert snapshot.messages[0].text == text
    value["messages"][0]["text"] += "a"
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))


def test_input_and_canonical_envelope_byte_limits() -> None:
    raw = _encode(_envelope())
    padded = raw + b" " * (MAX_ENVELOPE_BYTES - len(raw))
    assert isinstance(parse_browser_observation(padded), BrowserObservation)
    with pytest.raises(ValueError):
        parse_browser_observation(padded + b" ")
    value = _envelope("claude_web")
    value["messages"] = [
        {**value["messages"][0], "locator": str(index), "text": "x" * MAX_TEXT_BYTES}
        for index in range(4)
    ]
    with pytest.raises(ValueError):
        parse_browser_observation(_encode(value))
    snapshot = parse_browser_observation(raw)
    large = replace(snapshot.messages[0], text="x" * MAX_TEXT_BYTES)
    with pytest.raises(ValueError, match="byte limit"):
        replace(
            snapshot,
            messages=tuple(
                replace(large, locator=f"{index:08x}-2222-4333-8444-555555555555")
                for index in range(4)
            ),
        )


@pytest.mark.parametrize(
    "text",
    [
        "Synthetic text <no-memory>do not retain</no-memory>",
        "# NO-MEMORY\nSynthetic text",
        "[private] Synthetic text",
        "<PRIVATE>Synthetic text</PRIVATE>",
        "sk-" + "s" * 24,
    ],
)
def test_entire_snapshot_refuses_admission_exclusions(text: str) -> None:
    value = _envelope()
    value["messages"][1]["text"] = text
    with pytest.raises(ValueError, match="failed admission"):
        parse_browser_observation(_encode(value))


def test_exceptions_do_not_expose_input_or_json_decoder_causes() -> None:
    sentinel = "SYNTHETIC_SENSITIVE_SENTINEL"
    bodies = [
        b'{"' + sentinel.encode() + b'": "' + sentinel.encode(),
        _encode({**_envelope(), sentinel: sentinel}),
        _encode({**_envelope(), "account_binding": sentinel}),
        _encode({**_envelope(), "observed_at": sentinel}),
    ]
    for body in bodies:
        with pytest.raises(ValueError) as caught:
            parse_browser_observation(body)
        rendered = "".join(traceback.format_exception(caught.value))
        assert sentinel not in rendered
        assert caught.value.__cause__ is None


def test_dataclass_replacement_cannot_bypass_contract() -> None:
    snapshot = parse_browser_observation(_encode(_envelope()))
    with pytest.raises(ValueError):
        replace(snapshot, canonical_url="https://example.invalid")
    with pytest.raises(ValueError):
        replace(snapshot, account_binding="unknown")
    with pytest.raises(ValueError):
        replace(snapshot.messages[0], text="")
    with pytest.raises(ValueError):
        replace(snapshot, messages=())
