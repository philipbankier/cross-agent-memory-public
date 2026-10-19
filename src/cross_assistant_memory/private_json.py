from __future__ import annotations

import json
import os
import stat
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
    publish_file_no_replace_at,
)


def load_owner_only_json(path: Path, *, label: str, max_bytes: int) -> dict[str, Any]:
    descriptor, normalized = open_regular_file_no_symlinks(path, label)
    try:
        before = os.fstat(descriptor)
        if (
            before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
        ):
            raise ValueError(f"{label} must be an owner-only 0400 single-link file")
        if before.st_size > max_bytes:
            raise ValueError(f"{label} exceeds its byte limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(max_bytes + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _stat_identity(before) != _stat_identity(after) or len(raw) != before.st_size:
        raise RuntimeError(f"{label} changed while reading: {normalized}")
    try:
        value: object = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} must contain valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain an object")
    return cast(dict[str, Any], value)


def write_owner_only_json(
    path: Path,
    value: dict[str, Any],
    *,
    label: str,
    max_bytes: int,
) -> None:
    target = Path(os.path.abspath(path.expanduser()))
    if target.exists() or target.is_symlink():
        raise ValueError(f"{label} output already exists: {target}")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    if len(raw) > max_bytes:
        raise ValueError(f"{label} exceeds its byte limit")
    parent_descriptor = open_directory_no_symlinks(target.parent, f"{label} parent")
    parent_metadata = os.fstat(parent_descriptor)
    if parent_metadata.st_uid != os.geteuid() or stat.S_IMODE(parent_metadata.st_mode) != 0o700:
        os.close(parent_descriptor)
        raise ValueError(f"{label} parent must be owned by the current user with mode 0700")
    temporary_name = f".{target.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    published = False
    try:
        descriptor = os.open(temporary_name, flags, 0o400, dir_fd=parent_descriptor)
        try:
            os.fchmod(descriptor, 0o400)
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            raise
        publish_file_no_replace_at(
            parent_descriptor,
            temporary_name,
            target.name,
            required_mode=0o400,
            label=label,
            expected_source_descriptor=descriptor,
        )
        published = True
        if os.pread(descriptor, len(raw) + 1, 0) != raw:
            _remove_published_file(parent_descriptor, target.name)
            published = False
            raise RuntimeError(f"published {label} bytes changed")
        try:
            current_parent_descriptor = open_directory_no_symlinks(
                target.parent,
                f"{label} parent",
            )
        except ValueError as error:
            _remove_published_file(parent_descriptor, target.name)
            published = False
            raise RuntimeError(f"{label} parent changed during publication") from error
        try:
            if _directory_identity(os.fstat(current_parent_descriptor)) != _directory_identity(
                parent_metadata
            ):
                _remove_published_file(parent_descriptor, target.name)
                published = False
                raise RuntimeError(f"{label} parent changed during publication")
        finally:
            os.close(current_parent_descriptor)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            try:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                if not published:
                    os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _remove_published_file(parent_descriptor: int, target_name: str) -> None:
    with suppress(FileNotFoundError):
        os.unlink(target_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
