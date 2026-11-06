from __future__ import annotations

import re

_UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
_COMPOUND_CALL = re.compile(rf"call-{_UUID}-(?:0|[1-9][0-9]*)\nfc_{_UUID}_(?:0|[1-9][0-9]*)")


def valid_native_tool_call_id(value: object) -> bool:
    """Keep observed compound IDs opaque; neither component proves delivery."""
    return (
        type(value) is str
        and 1 <= len(value) <= 256
        and (
            re.fullmatch(r"[A-Za-z0-9_:-]+", value) is not None
            or _COMPOUND_CALL.fullmatch(value) is not None
        )
    )
