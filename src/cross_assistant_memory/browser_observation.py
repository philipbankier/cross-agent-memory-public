from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, NoReturn, cast
from uuid import UUID

from cross_assistant_memory.admission import classify_record
from cross_assistant_memory.models import SourceSystem

MAX_ENVELOPE_BYTES = 256 * 1024
MAX_MESSAGES = 100
MAX_TEXT_BYTES = 64 * 1024
MAX_LOCATOR_BYTES = 1024

BrowserProvider = Literal["chatgpt_web", "claude_web", "grok_web"]
LocatorKind = Literal["provider_message_id", "rendered_position"]
MessageRole = Literal["user", "assistant"]

_URL_PREFIXES = {
    "chatgpt_web": "https://chatgpt.com/c/",
    "claude_web": "https://claude.ai/chat/",
    "grok_web": "https://grok.com/c/",
}
_ACCOUNT_BINDING = re.compile(r"source_account:[0-9a-f]{64}")
_OBSERVED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_ENVELOPE_FIELDS = {
    "format_version",
    "provider",
    "account_binding",
    "conversation_id",
    "canonical_url",
    "observed_at",
    "capture_kind",
    "completeness",
    "messages",
}
_MESSAGE_FIELDS = {"locator", "locator_kind", "role", "text"}


@dataclass(frozen=True)
class BrowserMessage:
    locator: str
    locator_kind: LocatorKind
    role: MessageRole
    text: str = field(repr=False)

    def __post_init__(self) -> None:
        locator = _string(self.locator, "locator", MAX_LOCATOR_BYTES)
        if locator != locator.strip() or any(
            ord(char) < 32 or ord(char) == 127 for char in locator
        ):
            raise ValueError("browser observation locator is invalid")
        if self.locator_kind not in ("provider_message_id", "rendered_position"):
            raise ValueError("browser observation locator kind is invalid")
        if self.role not in ("user", "assistant"):
            raise ValueError("browser observation role is invalid")
        _string(self.text, "text", MAX_TEXT_BYTES)

    def as_dict(self) -> dict[str, object]:
        return {
            "locator": self.locator,
            "locator_kind": self.locator_kind,
            "role": self.role,
            "text": self.text,
        }


@dataclass(frozen=True)
class BrowserObservation:
    format_version: Literal[1]
    provider: BrowserProvider
    account_binding: str
    conversation_id: str
    canonical_url: str
    observed_at: str
    capture_kind: Literal["rendered_browser_observation"]
    completeness: Literal["visible_messages_only"]
    messages: tuple[BrowserMessage, ...]

    def __post_init__(self) -> None:
        if type(self.format_version) is not int or self.format_version != 1:
            raise ValueError("browser observation format version is unsupported")
        if type(self.provider) is not str or self.provider not in _URL_PREFIXES:
            raise ValueError("browser observation provider is unsupported")
        binding = _string(self.account_binding, "account binding", 128)
        if _ACCOUNT_BINDING.fullmatch(binding) is None:
            raise ValueError("browser observation account binding is invalid")
        _uuid(self.conversation_id, "conversation id")
        if self.canonical_url != _URL_PREFIXES[self.provider] + self.conversation_id:
            raise ValueError("browser observation canonical URL is invalid")
        observed_at = _string(self.observed_at, "observed time", 64)
        if _OBSERVED_AT.fullmatch(observed_at) is None or observed_at.endswith("-00:00"):
            raise ValueError("browser observation observed time is invalid")
        try:
            parsed_time = datetime.fromisoformat(observed_at)
        except ValueError:
            raise ValueError("browser observation observed time is invalid") from None
        if parsed_time.tzinfo is None:
            raise ValueError("browser observation observed time requires a timezone")
        if self.capture_kind != "rendered_browser_observation":
            raise ValueError("browser observation capture kind is invalid")
        if self.completeness != "visible_messages_only":
            raise ValueError("browser observation completeness is invalid")
        if type(self.messages) is not tuple or not 1 <= len(self.messages) <= MAX_MESSAGES:
            raise ValueError("browser observation message count is invalid")
        seen: set[tuple[str, MessageRole]] = set()
        for message in self.messages:
            if type(message) is not BrowserMessage:
                raise ValueError("browser observation message is invalid")
            if self.provider == "claude_web":
                if message.locator_kind != "rendered_position":
                    raise ValueError("Claude browser observations require rendered positions")
                if re.fullmatch(r"0|[1-9][0-9]*", message.locator) is None:
                    raise ValueError(
                        "Claude browser position must be a canonical nonnegative decimal"
                    )
            else:
                if message.locator_kind != "provider_message_id":
                    raise ValueError("browser observation requires provider message ids")
                _uuid(message.locator, "message id")
            identity = (message.locator, message.role)
            if identity in seen:
                raise ValueError("browser observation contains duplicate message locators")
            seen.add(identity)
        raw = self.canonical_bytes()
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise ValueError("browser observation exceeds its byte limit")
        decision = classify_record(
            SourceSystem(self.provider),
            "",
            raw,
            max_record_bytes=MAX_ENVELOPE_BYTES,
        )
        if not decision.accepted:
            raise ValueError("browser observation failed admission")

    def as_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "provider": self.provider,
            "account_binding": self.account_binding,
            "conversation_id": self.conversation_id,
            "canonical_url": self.canonical_url,
            "observed_at": self.observed_at,
            "capture_kind": self.capture_kind,
            "completeness": self.completeness,
            "messages": [message.as_dict() for message in self.messages],
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.as_dict())

    @property
    def content_digest(self) -> str:
        # Capture time is not provider history or part of rendered content identity.
        value = self.as_dict()
        del value["observed_at"]
        return hashlib.sha256(_canonical_json(value)).hexdigest()


def parse_browser_observation(body: bytes) -> BrowserObservation:
    if type(body) is not bytes or not 0 < len(body) <= MAX_ENVELOPE_BYTES:
        raise ValueError("browser observation byte envelope is invalid")
    try:
        value: object = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):
        raise ValueError("browser observation must be valid unambiguous UTF-8 JSON") from None
    root = _exact_object(value, _ENVELOPE_FIELDS)
    raw_messages = root["messages"]
    if not isinstance(raw_messages, list):
        raise ValueError("browser observation message count is invalid")
    message_items = cast(list[object], raw_messages)
    if not 1 <= len(message_items) <= MAX_MESSAGES:
        raise ValueError("browser observation message count is invalid")
    messages: list[BrowserMessage] = []
    for item in message_items:
        message = _exact_object(item, _MESSAGE_FIELDS)
        messages.append(
            BrowserMessage(
                locator=_string(message["locator"], "locator", MAX_LOCATOR_BYTES),
                locator_kind=cast(
                    LocatorKind, _string(message["locator_kind"], "locator kind", 64)
                ),
                role=cast(MessageRole, _string(message["role"], "role", 64)),
                text=_string(message["text"], "text", MAX_TEXT_BYTES),
            )
        )
    version = root["format_version"]
    if type(version) is not int or version != 1:
        raise ValueError("browser observation format version is unsupported")
    return BrowserObservation(
        format_version=1,
        provider=cast(BrowserProvider, _string(root["provider"], "provider", 64)),
        account_binding=_string(root["account_binding"], "account binding", 128),
        conversation_id=_string(root["conversation_id"], "conversation id", 36),
        canonical_url=_string(root["canonical_url"], "canonical URL", 256),
        observed_at=_string(root["observed_at"], "observed time", 64),
        capture_kind=cast(
            Literal["rendered_browser_observation"],
            _string(root["capture_kind"], "capture kind", 64),
        ),
        completeness=cast(
            Literal["visible_messages_only"],
            _string(root["completeness"], "completeness", 64),
        ),
        messages=tuple(messages),
    )


def _string(value: object, label: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"browser observation {label} is invalid")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ValueError(f"browser observation {label} is invalid") from None
    if length > max_bytes:
        raise ValueError(f"browser observation {label} exceeds its byte limit")
    return value


def _uuid(value: object, label: str) -> None:
    text = _string(value, label, 36)
    try:
        canonical = str(UUID(text))
    except ValueError:
        raise ValueError(f"browser observation {label} is invalid") from None
    if text != canonical:
        raise ValueError(f"browser observation {label} must be a canonical UUID")


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _exact_object(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(cast(dict[str, object], value)) != fields:
        raise ValueError("browser observation object fields are invalid")
    return cast(dict[str, object], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("browser observation contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise ValueError("browser observation contains a non-JSON constant")
