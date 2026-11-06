from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Literal, NoReturn, cast
from uuid import UUID

from cross_assistant_memory.admission import classify_record
from cross_assistant_memory.grok_bot_identity import valid_native_tool_call_id
from cross_assistant_memory.grok_bot_outward import canonical_outward_request

MAX_PAGE_BYTES = 1024 * 1024
MAX_PAGE_RECORDS = 200
_OPEN = re.compile(r'<(?P<tag>cursor_untrusted_data_[A-Za-z0-9_]+) source="ReadTranscript">')
_HEADER = re.compile(
    r'Transcript of agent ".*" \((?P<bot>[^()\r\n]{1,256})\), '
    r"positions (?P<start>0|[1-9][0-9]*)\u2013(?P<end>0|[1-9][0-9]*) "
    r"of (?P<total>0|[1-9][0-9]*):"
)
_FOOTER = re.compile(
    r"Older messages remain: call ReadTranscript again with the same in "
    r"and before=(?P<before>0|[1-9][0-9]*)\."
)
_BLOCK_FIELDS = {
    "text": {"type", "text"},
    "thinking": {"type", "thinking"},
    "tool_use": {"type", "id", "name", "input"},
    "tool_result": {"type", "tool_use_id", "name", "result"},
}


@dataclass(frozen=True)
class TranscriptInspection:
    """Structural qualification only; never a capture receipt or an authorization claim."""

    page_start: int
    page_end: int
    total: int
    before: int | None
    record_count: int
    content_kinds: tuple[tuple[str, int], ...]

    @property
    def position_gaps(self) -> bool:
        return self.record_count != self.page_end - self.page_start + 1

    @property
    def conversation_identity_verified(self) -> bool:
        return False

    @property
    def audience_verified(self) -> bool:
        return False

    @property
    def admission_ready(self) -> bool:
        return False


@dataclass(frozen=True)
class ReplyRequest:
    page_record_index: int
    content_index: int
    native_tool_call_id: str
    content_text: str = dataclass_field(repr=False)
    end_turn: bool | None = None
    delivery: Literal["requested_not_verified"] = "requested_not_verified"
    conversation_id: None = None
    kind: Literal["reply_request", "question_request", "attachment_reference"] = "reply_request"


@dataclass(frozen=True)
class TranscriptProjection:
    """Filtered source representation, not an enrolled or admitted conversation."""

    bot_id: str
    source_sha256: str
    source_bytes: int
    inspection: TranscriptInspection
    replies: tuple[ReplyRequest, ...]
    excluded_replies: int

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "format_version": 1,
                "source_system": "grok_bot",
                "representation": "native_reply_request_projection",
                "bot_id": self.bot_id,
                "source_sha256": self.source_sha256,
                "source_bytes": self.source_bytes,
                "page_start": self.inspection.page_start,
                "page_end": self.inspection.page_end,
                "total": self.inspection.total,
                "before": self.inspection.before,
                "position_gaps": self.inspection.position_gaps,
                "conversation_identity_verified": False,
                "audience_verified": False,
                "admission_ready": False,
                "excluded_replies": self.excluded_replies,
                "replies": [
                    {
                        "page_record_index": reply.page_record_index,
                        "content_index": reply.content_index,
                        "native_tool_call_id": reply.native_tool_call_id,
                        "content_text": reply.content_text,
                        "end_turn": reply.end_turn,
                        "delivery": reply.delivery,
                        "conversation_id": reply.conversation_id,
                        **({"kind": reply.kind} if reply.kind != "reply_request" else {}),
                    }
                    for reply in self.replies
                ],
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


def inspect_transcript_page(data: bytes, *, expected_bot_id: str) -> TranscriptInspection:
    """Inspect the observed native framing in memory without retaining its private payloads."""
    return _read_page(data, expected_bot_id)[0]


def project_transcript_page(data: bytes, *, expected_bot_id: str) -> TranscriptProjection:
    """Exclude private internals before producing a bounded reply-only projection."""
    inspection, records = _read_page(data, expected_bot_id)
    try:
        canonical_id = str(UUID(expected_bot_id))
    except ValueError:
        raise ValueError("Grok Bot projection target identifier is unsupported") from None
    if canonical_id != expected_bot_id:
        raise ValueError("Grok Bot projection target identifier is unsupported")
    replies: list[ReplyRequest] = []
    seen: dict[str, tuple[str, str, bool | None]] = {}
    excluded = 0
    for index, item in enumerate(records):
        if item["role"] != "assistant":
            continue
        message = cast(dict[str, object], item["message"])
        for content_index, value in enumerate(cast(list[object], message["content"])):
            block = cast(dict[str, object], value)
            if block["type"] != "tool_use" or block.get("name") != "SendToUser":
                continue
            arguments = cast(dict[str, object], block["input"])
            kind: Literal["reply_request", "question_request", "attachment_reference"]
            if arguments.keys() in ({"content"}, {"content", "end_turn"}):
                kind = "reply_request"
                end_turn = arguments.get("end_turn")
                if "end_turn" in arguments and type(end_turn) is not bool:
                    raise ValueError("Grok Bot reply request turn marker is unsupported")
                content = arguments["content"]
            else:
                kind, content = canonical_outward_request(arguments)
                end_turn = None
            call_id = cast(str, block["id"])
            if (
                not isinstance(content, str)
                or not content.strip()
                or not valid_native_tool_call_id(call_id)
            ):
                raise ValueError("Grok Bot reply request fields are unsupported")
            identity = (kind, content, cast(bool | None, end_turn))
            if call_id in seen and seen[call_id] != identity:
                raise ValueError("Grok Bot reply request has a duplicate tool call id")
            if call_id in seen:
                continue
            seen[call_id] = identity
            raw = json.dumps(
                {"native_tool_call_id": call_id, "content_text": content}, ensure_ascii=False
            ).encode("utf-8")
            decision = classify_record(None, content, raw, max_record_bytes=64 * 1024)
            if not decision.accepted:
                excluded += 1
                continue
            replies.append(
                ReplyRequest(
                    index, content_index, call_id, content, cast(bool | None, end_turn), kind=kind
                )
            )
    return TranscriptProjection(
        expected_bot_id,
        hashlib.sha256(data).hexdigest(),
        len(data),
        inspection,
        tuple(replies),
        excluded,
    )


def project_user_texts(data: bytes, *, expected_bot_id: str) -> tuple[tuple[str, ...], int]:
    """Keep native user-role text verbatim, without treating embedded markup as identity."""
    _, records = _read_page(data, expected_bot_id)
    texts: list[str] = []
    excluded = 0
    for item in records:
        if item["role"] != "user":
            continue
        message = cast(dict[str, object], item["message"])
        blocks = cast(list[dict[str, object]], message["content"])
        if any(block["type"] != "text" for block in blocks):
            excluded += 1
            continue
        for block in blocks:
            text = cast(str, block["text"])
            decision = classify_record(None, text, text.encode("utf-8"), max_record_bytes=64 * 1024)
            if not text.strip() or not decision.accepted:
                excluded += 1
                continue
            texts.append(text)
    return tuple(texts), excluded


def _read_page(
    data: bytes, expected_bot_id: str
) -> tuple[TranscriptInspection, tuple[dict[str, object], ...]]:
    if type(data) is not bytes or not 0 < len(data) <= MAX_PAGE_BYTES:
        raise ValueError("Grok Bot transcript exceeds its byte limit")
    if type(expected_bot_id) is not str or not 1 <= len(expected_bot_id) <= 256:
        raise ValueError("Grok Bot transcript target identity is invalid")
    try:
        return _inspect(data, expected_bot_id)
    except (UnicodeError, RecursionError, OverflowError, json.JSONDecodeError):
        raise ValueError("Grok Bot transcript encoding or structure is invalid") from None


def _inspect(
    data: bytes, expected_bot_id: str
) -> tuple[TranscriptInspection, tuple[dict[str, object], ...]]:
    lines = data.decode("utf-8").splitlines()
    if len(lines) < 6:
        raise ValueError("Grok Bot transcript framing is incomplete")
    opening = _OPEN.fullmatch(lines[0])
    if opening is None or lines[1] != "" or lines[-2] != "" or lines[-1] != f"</{opening['tag']}>":
        raise ValueError("Grok Bot transcript framing is unsupported")
    header = _HEADER.fullmatch(lines[2])
    if header is None or header["bot"] != expected_bot_id:
        raise ValueError("Grok Bot transcript target identity is unverified")
    start, end, total = (int(header[key]) for key in ("start", "end", "total"))
    if not 0 <= start <= end < total:
        raise ValueError("Grok Bot transcript page range is invalid")
    rows = lines[3:-2]
    before: int | None = None
    if rows and (footer := _FOOTER.fullmatch(rows[-1])) is not None:
        before = int(footer["before"])
        if before != start or start == 0:
            raise ValueError("Grok Bot transcript page cursor is inconsistent")
        rows = rows[:-1]
    elif start != 0:
        raise ValueError("Grok Bot transcript page cursor is missing")
    if not 1 <= len(rows) <= min(MAX_PAGE_RECORDS, end - start + 1):
        raise ValueError("Grok Bot transcript record count is invalid")
    counts: Counter[str] = Counter()
    records: list[dict[str, object]] = []
    for row in rows:
        record: object = json.loads(
            row, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        item = _object(record, {"role", "message"})
        if item["role"] not in ("user", "assistant", "tool"):
            raise ValueError("Grok Bot transcript record role is unsupported")
        message = _object(item["message"], {"content"})
        content = message["content"]
        if not isinstance(content, list) or not content:
            raise ValueError("Grok Bot transcript content structure is invalid")
        for value in cast(list[object], content):
            if not isinstance(value, dict):
                raise ValueError("Grok Bot transcript content structure is invalid")
            block = cast(dict[str, object], value)
            kind = block.get("type")
            if not isinstance(kind, str) or kind not in _BLOCK_FIELDS:
                raise ValueError("Grok Bot transcript content kind is unsupported")
            _object(block, _BLOCK_FIELDS[kind])
            if (
                kind == "tool_use"
                and block.get("name") == "SendToUser"
                and isinstance(block.get("input"), str)
            ):
                # Native history can retain serialized arguments, not only decoded objects.
                block["input"] = json.loads(
                    cast(str, block["input"]),
                    object_pairs_hook=_unique_object,
                    parse_constant=_reject_constant,
                )
            for key, field in block.items():
                valid = isinstance(field, dict) if key == "input" else isinstance(field, str)
                if not valid:
                    raise ValueError("Grok Bot transcript content field type is invalid")
            counts[kind] += 1
        records.append(item)
    # A page's local row index is not a provider message position or identity.
    return (
        TranscriptInspection(start, end, total, before, len(rows), tuple(sorted(counts.items()))),
        tuple(records),
    )


def _object(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or value.keys() != fields:
        raise ValueError("Grok Bot transcript object fields are unsupported")
    return cast(dict[str, object], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Grok Bot transcript contains duplicate object fields")
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("Grok Bot transcript contains a non-JSON numeric constant")
