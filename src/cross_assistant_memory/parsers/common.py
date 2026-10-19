from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

SCHEMA_DISCRIMINATOR_KEYS = frozenset(
    {
        "entrypoint",
        "method",
        "role",
        "sessionUpdate",
        "type",
    }
)


def source_branch_path(
    prefix: str,
    item_id: str | None,
    parent_by_id: dict[str, str | None],
) -> str | None:
    if item_id is None:
        return None
    path: list[str] = []
    seen: set[str] = set()
    current: str | None = item_id
    while current is not None:
        if current in seen:
            raise ValueError("source branch path contains a cycle")
        seen.add(current)
        path.append(current)
        current = parent_by_id.get(current)
    digest = hashlib.sha256("\0".join(reversed(path)).encode()).hexdigest()
    return f"{prefix}:{digest}"


def content_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    parts: list[str] = []
    for item in cast(list[object], value):
        if isinstance(item, str):
            parts.append(item)
            continue
        if not isinstance(item, dict):
            continue
        typed_item = cast(dict[str, object], item)
        item_type = typed_item.get("type")
        if item_type not in ("text", "input_text", "output_text"):
            continue
        text = typed_item.get("text")
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(part for part in parts if part)


def optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def timestamp_text(value: Any) -> str | None:
    if isinstance(value, dict):
        typed = cast(dict[str, Any], value)
        nested = typed.get("$date")
        if isinstance(nested, dict):
            nested = cast(dict[str, Any], nested).get("$numberLong")
        return timestamp_text(nested)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
    elif isinstance(value, str):
        if not value:
            return None
        try:
            seconds = float(value)
        except ValueError:
            return value
    else:
        return None
    if abs(seconds) >= 100_000_000_000:
        seconds /= 1000
    try:
        return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError):
        return None


def native_jsonl_schema_fingerprint(data: bytes) -> str:
    shapes: set[str] = set()
    for raw in data.splitlines():
        if not raw.strip():
            continue
        try:
            loaded: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            shape: object = {"invalid_json": True}
        else:
            shape = _schema_shape(loaded)
        shapes.add(json.dumps(shape, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    canonical = json.dumps(sorted(shapes), ensure_ascii=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def json_schema_fingerprint(
    data: bytes,
    *,
    dynamic_map_paths: frozenset[tuple[str, ...]] = frozenset(),
    checkpoint: Callable[[], None] | None = None,
) -> str:
    descriptors = json_schema_descriptors(
        data,
        dynamic_map_paths=dynamic_map_paths,
        checkpoint=checkpoint,
    )
    return schema_fingerprint_from_descriptors(descriptors)


def json_schema_descriptors(
    data: bytes,
    *,
    dynamic_map_paths: frozenset[tuple[str, ...]] = frozenset(),
    checkpoint: Callable[[], None] | None = None,
) -> tuple[str, ...]:
    if checkpoint is not None:
        checkpoint()
    try:
        loaded: object = json.loads(data, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("schema fingerprint input is not valid JSON") from exc
    if checkpoint is not None:
        checkpoint()
    descriptors: set[str] = set()
    _collect_schema_descriptors(
        loaded,
        path=(),
        dynamic_map_paths=dynamic_map_paths,
        descriptors=descriptors,
        checkpoint=checkpoint,
        node_count=[0],
    )
    if checkpoint is not None:
        checkpoint()
    return tuple(sorted(descriptors))


def schema_fingerprint_from_descriptors(descriptors: tuple[str, ...] | set[str]) -> str:
    canonical = json.dumps(sorted(descriptors), ensure_ascii=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    loaded: dict[str, object] = {}
    for key, value in pairs:
        if key in loaded:
            raise ValueError("schema fingerprint input contains a duplicate object key")
        loaded[key] = value
    return loaded


def _collect_schema_descriptors(
    value: object,
    *,
    path: tuple[str, ...],
    dynamic_map_paths: frozenset[tuple[str, ...]],
    descriptors: set[str],
    checkpoint: Callable[[], None] | None,
    node_count: list[int],
) -> None:
    node_count[0] += 1
    if checkpoint is not None and node_count[0] % 1024 == 0:
        checkpoint()
    marker: str
    if value is None:
        marker = "null"
    elif isinstance(value, bool):
        marker = "boolean"
    elif isinstance(value, int):
        marker = "integer"
    elif isinstance(value, float):
        marker = "number"
    elif isinstance(value, str):
        if path and path[-1] in SCHEMA_DISCRIMINATOR_KEYS and len(value.encode()) <= 128:
            marker = f"string:{value}"
        else:
            marker = "string"
    elif isinstance(value, list):
        marker = "array"
        for item in cast(list[object], value):
            _collect_schema_descriptors(
                item,
                path=(*path, "[]"),
                dynamic_map_paths=dynamic_map_paths,
                descriptors=descriptors,
                checkpoint=checkpoint,
                node_count=node_count,
            )
    elif isinstance(value, dict):
        typed = cast(dict[str, object], value)
        if path in dynamic_map_paths:
            marker = "dynamic_object"
            for item in typed.values():
                _collect_schema_descriptors(
                    item,
                    path=(*path, "*"),
                    dynamic_map_paths=dynamic_map_paths,
                    descriptors=descriptors,
                    checkpoint=checkpoint,
                    node_count=node_count,
                )
        else:
            marker = "object"
            for key in sorted(typed):
                _collect_schema_descriptors(
                    typed[key],
                    path=(*path, key),
                    dynamic_map_paths=dynamic_map_paths,
                    descriptors=descriptors,
                    checkpoint=checkpoint,
                    node_count=node_count,
                )
    else:  # pragma: no cover - json.loads returns JSON-compatible values
        marker = f"unsupported:{type(value).__name__}"
    descriptors.add(json.dumps([*path, marker], ensure_ascii=True, separators=(",", ":")))


def _schema_shape(
    value: object,
    *,
    field_name: str | None = None,
    checkpoint: Callable[[], None] | None = None,
    node_count: list[int] | None = None,
) -> object:
    if node_count is not None:
        node_count[0] += 1
        if checkpoint is not None and node_count[0] % 4096 == 0:
            checkpoint()
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        if field_name in SCHEMA_DISCRIMINATOR_KEYS and len(value.encode()) <= 128:
            return {"string_discriminator": value}
        return "string"
    if isinstance(value, list):
        item_shapes = {
            json.dumps(
                _schema_shape(item, checkpoint=checkpoint, node_count=node_count),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            for item in cast(list[object], value)
        }
        return {"array": [json.loads(item) for item in sorted(item_shapes)]}
    if isinstance(value, dict):
        typed = cast(dict[object, object], value)
        fields: list[tuple[str, object]] = []
        for key in sorted(typed, key=str):
            if not isinstance(key, str):
                fields.append(("<non-string-key>", "invalid"))
                continue
            fields.append(
                (
                    key,
                    _schema_shape(
                        typed[key],
                        field_name=key,
                        checkpoint=checkpoint,
                        node_count=node_count,
                    ),
                )
            )
        return {"object": fields}
    return {"unsupported": type(value).__name__}
