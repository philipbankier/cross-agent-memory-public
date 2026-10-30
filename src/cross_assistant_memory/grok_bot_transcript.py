from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import NoReturn, cast

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


def inspect_transcript_page(data: bytes, *, expected_bot_id: str) -> TranscriptInspection:
    """Inspect the observed native framing in memory without retaining its private payloads."""
    if type(data) is not bytes or not 0 < len(data) <= MAX_PAGE_BYTES:
        raise ValueError("Grok Bot transcript exceeds its byte limit")
    if type(expected_bot_id) is not str or not 1 <= len(expected_bot_id) <= 256:
        raise ValueError("Grok Bot transcript target identity is invalid")
    try:
        return _inspect(data, expected_bot_id)
    except (UnicodeError, RecursionError, OverflowError, json.JSONDecodeError):
        raise ValueError("Grok Bot transcript encoding or structure is invalid") from None


def _inspect(data: bytes, expected_bot_id: str) -> TranscriptInspection:
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
            for key, field in block.items():
                valid = isinstance(field, dict) if key == "input" else isinstance(field, str)
                if not valid:
                    raise ValueError("Grok Bot transcript content field type is invalid")
            counts[kind] += 1
    # A page's local row index is not a provider message position or identity.
    return TranscriptInspection(start, end, total, before, len(rows), tuple(sorted(counts.items())))


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
