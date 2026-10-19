from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TypeAlias

ByteView: TypeAlias = bytes | memoryview

_WHITESPACE = frozenset(b" \t\r\n")
_VALUE_DELIMITERS = frozenset(b" \t\r\n,]}")
_STRING_SPECIAL = re.compile(rb'["\\\x00-\x1f]')


@dataclass(frozen=True)
class JsonSpan:
    start: int
    end: int

    def bytes(self, data: ByteView) -> bytes:
        return bytes(data[self.start : self.end])


class JsonValueCountLimitError(ValueError):
    pass


def top_level_array_value_spans(
    data: ByteView,
    *,
    max_values: int | None = None,
) -> tuple[JsonSpan, ...]:
    start = _skip_whitespace(data, 0, len(data))
    spans, end = _array_value_spans(data, start, len(data), max_values=max_values)
    _require_document_end(data, end)
    return spans


def object_array_value_spans(
    data: ByteView,
    key: str,
    *,
    container: JsonSpan | None = None,
    max_values: int | None = None,
) -> tuple[JsonSpan, ...]:
    field = object_field_span(data, key, container=container)
    spans, end = _array_value_spans(
        data,
        field.start,
        field.end,
        max_values=max_values,
    )
    if _skip_whitespace(data, end, field.end) != field.end:
        raise ValueError(f"JSON field {key!r} contains trailing data")
    return spans


def object_value_spans(
    data: ByteView,
    key: str,
    *,
    container: JsonSpan | None = None,
    max_values: int | None = None,
) -> tuple[JsonSpan, ...]:
    return tuple(
        value
        for _, value in object_item_spans(
            data,
            key,
            container=container,
            max_values=max_values,
        )
    )


def object_item_spans(
    data: ByteView,
    key: str,
    *,
    container: JsonSpan | None = None,
    max_values: int | None = None,
) -> tuple[tuple[str, JsonSpan], ...]:
    field = object_field_span(data, key, container=container)
    fields, end = _object_fields(
        data,
        field.start,
        field.end,
        max_fields=max_values,
    )
    if _skip_whitespace(data, end, field.end) != field.end:
        raise ValueError(f"JSON field {key!r} contains trailing data")
    return fields


def object_field_span(
    data: ByteView,
    key: str,
    *,
    container: JsonSpan | None = None,
) -> JsonSpan:
    bounds = container or JsonSpan(0, len(data))
    fields, end = _object_fields(data, bounds.start, bounds.end)
    if _skip_whitespace(data, end, bounds.end) != bounds.end:
        raise ValueError("JSON object contains trailing data")
    matches = [value for name, value in fields if name == key]
    if not matches:
        raise ValueError(f"JSON object is missing field {key!r}")
    if len(matches) != 1:
        raise ValueError(f"JSON object contains duplicate field {key!r}")
    return matches[0]


def _array_value_spans(
    data: ByteView,
    start: int,
    limit: int,
    *,
    max_values: int | None = None,
) -> tuple[tuple[JsonSpan, ...], int]:
    if max_values is not None and max_values <= 0:
        raise ValueError("JSON value limit must be positive")
    position = _skip_whitespace(data, start, limit)
    if position >= limit or data[position] != ord("["):
        raise ValueError("expected a JSON array")
    position = _skip_whitespace(data, position + 1, limit)
    values: list[JsonSpan] = []
    if position < limit and data[position] == ord("]"):
        return tuple(values), position + 1
    while position < limit:
        if max_values is not None and len(values) >= max_values:
            raise JsonValueCountLimitError("JSON array value-count budget exceeded")
        value_start = position
        value_end = _scan_value_end(data, value_start, limit)
        values.append(JsonSpan(value_start, value_end))
        position = _skip_whitespace(data, value_end, limit)
        if position >= limit:
            break
        token = data[position]
        if token == ord("]"):
            return tuple(values), position + 1
        if token != ord(","):
            raise ValueError("expected a comma or array terminator")
        position = _skip_whitespace(data, position + 1, limit)
    raise ValueError("unterminated JSON array")


def _object_fields(
    data: ByteView,
    start: int,
    limit: int,
    *,
    max_fields: int | None = None,
) -> tuple[tuple[tuple[str, JsonSpan], ...], int]:
    if max_fields is not None and max_fields <= 0:
        raise ValueError("JSON value limit must be positive")
    position = _skip_whitespace(data, start, limit)
    if position >= limit or data[position] != ord("{"):
        raise ValueError("expected a JSON object")
    position = _skip_whitespace(data, position + 1, limit)
    fields: list[tuple[str, JsonSpan]] = []
    if position < limit and data[position] == ord("}"):
        return tuple(fields), position + 1
    while position < limit:
        if max_fields is not None and len(fields) >= max_fields:
            raise JsonValueCountLimitError("JSON object field-count budget exceeded")
        if data[position] != ord('"'):
            raise ValueError("expected a JSON object key")
        key_start = position
        key_end = _scan_string_end(data, key_start, limit)
        try:
            loaded_key: object = json.loads(bytes(data[key_start:key_end]))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("invalid JSON object key") from exc
        if not isinstance(loaded_key, str):
            raise ValueError("JSON object key is not text")
        position = _skip_whitespace(data, key_end, limit)
        if position >= limit or data[position] != ord(":"):
            raise ValueError("expected a colon after a JSON object key")
        value_start = _skip_whitespace(data, position + 1, limit)
        value_end = _scan_value_end(data, value_start, limit)
        fields.append((loaded_key, JsonSpan(value_start, value_end)))
        position = _skip_whitespace(data, value_end, limit)
        if position >= limit:
            break
        token = data[position]
        if token == ord("}"):
            return tuple(fields), position + 1
        if token != ord(","):
            raise ValueError("expected a comma or object terminator")
        position = _skip_whitespace(data, position + 1, limit)
    raise ValueError("unterminated JSON object")


def _scan_value_end(data: ByteView, start: int, limit: int) -> int:
    position = _skip_whitespace(data, start, limit)
    if position >= limit:
        raise ValueError("missing JSON value")
    token = data[position]
    if token == ord('"'):
        return _scan_string_end(data, position, limit)
    if token in (ord("["), ord("{")):
        return _scan_container_end(data, position, limit)
    for literal in (b"true", b"false", b"null"):
        literal_end = position + len(literal)
        if bytes(data[position:literal_end]) == literal:
            if literal_end < limit and data[literal_end] not in _VALUE_DELIMITERS:
                break
            return literal_end
    end = position
    while end < limit and data[end] not in _VALUE_DELIMITERS:
        end += 1
    if end == position:
        raise ValueError("invalid JSON value")
    raw = bytes(data[position:end])
    try:
        loaded: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("invalid JSON scalar") from exc
    if isinstance(loaded, bool) or not isinstance(loaded, (int, float)):
        raise ValueError("invalid JSON scalar")
    return end


def _scan_container_end(data: ByteView, start: int, limit: int) -> int:
    opening = data[start]
    if opening not in (ord("["), ord("{")):
        raise ValueError("expected a JSON array or object")
    closers = [ord("]") if opening == ord("[") else ord("}")]
    position = start + 1
    while position < limit:
        token = data[position]
        if token == ord('"'):
            position = _scan_string_end(data, position, limit)
            continue
        if token == ord("["):
            closers.append(ord("]"))
        elif token == ord("{"):
            closers.append(ord("}"))
        elif token in (ord("]"), ord("}")):
            if token != closers[-1]:
                raise ValueError("JSON container closes with the wrong delimiter")
            closers.pop()
            if not closers:
                return position + 1
        position += 1
    raise ValueError("unterminated JSON container")


def _scan_string_end(data: ByteView, start: int, limit: int) -> int:
    position = start + 1
    if isinstance(data, bytes) or (data.ndim == 1 and data.format == "B" and data.c_contiguous):
        # Search the original buffer without copying it or crossing the caller's limit.
        while match := _STRING_SPECIAL.search(data, position, limit):
            token = data[match.start()]
            if token == ord('"'):
                return match.end()
            if token == ord("\\"):
                position = match.end() + 1
                continue
            raise ValueError("unescaped control character in JSON string")
        raise ValueError("unterminated JSON string")

    while position < limit:
        token = data[position]
        if token == ord('"'):
            return position + 1
        if token == ord("\\"):
            position += 2
            continue
        if token < 0x20:
            raise ValueError("unescaped control character in JSON string")
        position += 1
    raise ValueError("unterminated JSON string")


def _skip_whitespace(data: ByteView, start: int, limit: int) -> int:
    position = start
    while position < limit and data[position] in _WHITESPACE:
        position += 1
    return position


def _require_document_end(data: ByteView, end: int) -> None:
    if _skip_whitespace(data, end, len(data)) != len(data):
        raise ValueError("JSON document contains trailing data")
