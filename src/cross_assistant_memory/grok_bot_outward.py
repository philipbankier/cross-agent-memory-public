from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Literal, cast
from urllib.parse import unquote, urlsplit

StructuredRequestKind = Literal["question_request", "attachment_reference"]
MAX_WIDGET_STEPS = 32
MAX_WIDGET_OPTIONS = 64


def canonical_outward_request(value: object) -> tuple[StructuredRequestKind, str]:
    if not isinstance(value, dict):
        raise ValueError("Grok Bot outward request is unsupported")
    arguments = cast(dict[str, object], value)
    if "end_turn" in arguments and type(arguments["end_turn"]) is not bool:
        raise ValueError("Grok Bot outward request turn marker is unsupported")
    kind: StructuredRequestKind
    if arguments.get("type") == "attachment":
        _fields(arguments, {"type", "url"}, {"alt", "end_turn"})
        if "alt" in arguments:
            _text(arguments["alt"])
        url = _text(arguments["url"])
        try:
            parsed = urlsplit(url)
            path = PurePosixPath(unquote(parsed.path, errors="strict"))
        except (ValueError, UnicodeError):
            raise ValueError("Grok Bot attachment reference is unsupported") from None
        if (
            not url.startswith("file:///")
            or parsed.scheme != "file"
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or "?" in url
            or "#" in url
            or "\x00" in str(path)
            or len(path.parts) < 3
            or path.parts[:2] != ("/", "workspace")
            or ".." in path.parts
        ):
            raise ValueError("Grok Bot attachment reference is unsupported")
        kind = "attachment_reference"
    elif arguments.get("type") == "widget":
        _fields(arguments, {"type", "widget"}, {"end_turn"})
        widget = _fields(
            arguments["widget"],
            {"prompt"},
            {"steps", "options", "allowCustom", "multiSelect", "dismissOnMoveOn", "helpText"},
        )
        _text(widget["prompt"])
        _question_flags(widget)
        if "helpText" in widget:
            _text(widget["helpText"])
        if "steps" in widget:
            if "options" in widget:
                raise ValueError("Grok Bot question layout is ambiguous")
            for value in _items(widget["steps"], MAX_WIDGET_STEPS):
                step = _fields(value, {"prompt", "options"}, {"allowCustom", "multiSelect"})
                _text(step["prompt"])
                _question_flags(step)
                _question_options(_items(step["options"], MAX_WIDGET_OPTIONS))
        elif "options" in widget:
            _question_options(_items(widget["options"], MAX_WIDGET_OPTIONS, minimum=0))
        kind = "question_request"
    else:
        raise ValueError("Grok Bot outward request type is unsupported")
    try:
        content = json.dumps(
            arguments, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
        content.encode("utf-8")
    except (ValueError, UnicodeError):
        raise ValueError("Grok Bot outward request encoding is invalid") from None
    return kind, content


def _fields(
    value: object, keys: set[str], optional: set[str] | frozenset[str] = frozenset()
) -> dict[str, object]:
    if not isinstance(value, dict) or not keys <= value.keys() <= keys | optional:
        raise ValueError("Grok Bot outward request fields are unsupported")
    return cast(dict[str, object], value)


def _question_flags(value: dict[str, object]) -> None:
    for key in ("allowCustom", "multiSelect", "dismissOnMoveOn"):
        if key in value and type(value[key]) is not bool:
            raise ValueError("Grok Bot question flag is unsupported")


def _question_options(options: list[object]) -> None:
    for option in options:
        fields = _fields(option, {"label"}, {"value", "style", "description"})
        for key in ("label", "value", "description"):
            if key in fields:
                _text(fields[key])
        if "style" in fields and fields["style"] not in ("default", "primary", "danger"):
            raise ValueError("Grok Bot question option style is unsupported")


def _text(value: object) -> str:
    if type(value) is not str:
        raise ValueError("Grok Bot outward request text type is unsupported")
    return value


def _items(value: object, maximum: int, *, minimum: int = 1) -> list[object]:
    if type(value) is not list or not minimum <= len(cast(list[object], value)) <= maximum:
        raise ValueError("Grok Bot question list exceeds the capture bound")
    return cast(list[object], value)
