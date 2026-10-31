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
    kind: StructuredRequestKind
    if arguments.get("type") == "attachment":
        _fields(arguments, {"type", "url"})
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
        _fields(arguments, {"type", "widget"})
        widget = _fields(arguments["widget"], {"prompt", "steps"})
        _text(widget["prompt"])
        for value in _items(widget["steps"], MAX_WIDGET_STEPS):
            if not isinstance(value, dict):
                raise ValueError("Grok Bot question step is unsupported")
            step = cast(dict[str, object], value)
            if step.keys() not in ({"prompt", "options"}, {"prompt", "options", "allowCustom"}):
                raise ValueError("Grok Bot question step is unsupported")
            if "allowCustom" in step and type(step["allowCustom"]) is not bool:
                raise ValueError("Grok Bot question custom-answer flag is unsupported")
            _text(step["prompt"])
            for option in _items(step["options"], MAX_WIDGET_OPTIONS):
                fields = _fields(option, {"label", "value"})
                _text(fields["label"])
                _text(fields["value"])
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


def _fields(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or value.keys() != keys:
        raise ValueError("Grok Bot outward request fields are unsupported")
    return cast(dict[str, object], value)


def _text(value: object) -> str:
    if type(value) is not str:
        raise ValueError("Grok Bot outward request text type is unsupported")
    return value


def _items(value: object, maximum: int) -> list[object]:
    if type(value) is not list or not 1 <= len(cast(list[object], value)) <= maximum:
        raise ValueError("Grok Bot question list exceeds the capture bound")
    return cast(list[object], value)
