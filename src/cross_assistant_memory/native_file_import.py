from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.ingest import NativeFilePrefix
from cross_assistant_memory.object_writes import ObjectWriteScope
from cross_assistant_memory.private_json import load_owner_only_json, write_owner_only_json
from cross_assistant_memory.safe_files import open_directory_no_symlinks

ATTEMPT_NAME = ".native-file-import.json"
MAX_ATTEMPT_BYTES = 4096
_LABEL = "retained native file import"


def load_attempt(root: Path, request_sha256: str) -> dict[str, Any] | None:
    path = root / ATTEMPT_NAME
    if not path.exists() and not path.is_symlink():
        return None
    value = load_owner_only_json(path, label=_LABEL, max_bytes=MAX_ATTEMPT_BYTES)
    prefix = cast(dict[str, Any], value.get("prefix"))
    start = cast(list[Any], value.get("start"))
    if (
        set(value) != {"version", "request_sha256", "prefix", "start", "write_scope"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["request_sha256"] != request_sha256
        or type(prefix) is not dict
        or set(prefix) != {"size", "sha256", "mtime_ns", "device", "inode"}
        or type(start) is not list
        or len(start) != 3
        or any(type(item) is not int or item < 0 for item in start[:2])
        or not isinstance(start[2], str)
    ):
        raise RuntimeError("retained native file import differs from this request")
    return value


def retain_attempt(
    root: Path,
    request_sha256: str,
    prefix: NativeFilePrefix,
    scope: ObjectWriteScope,
    start: tuple[int, int, str],
) -> dict[str, Any]:
    value = {
        "version": 1,
        "request_sha256": request_sha256,
        "prefix": asdict(prefix),
        "start": list(start),
        "write_scope": scope.header(),
    }
    existing = load_attempt(root, request_sha256)
    if existing is not None:
        if existing != value:
            raise RuntimeError("retained native file parser or publication configuration changed")
    else:
        write_owner_only_json(root / ATTEMPT_NAME, value, label=_LABEL, max_bytes=MAX_ATTEMPT_BYTES)
    return value


def finish_attempt(root: Path, value: dict[str, Any]) -> None:
    parent = open_directory_no_symlinks(root, _LABEL)
    try:
        before = os.stat(ATTEMPT_NAME, dir_fd=parent, follow_symlinks=False)
        if load_attempt(root, value["request_sha256"]) != value:
            raise RuntimeError("retained native file import changed before retirement")
        after = os.stat(ATTEMPT_NAME, dir_fd=parent, follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_ctime_ns,
        ):
            raise RuntimeError("retained native file import identity changed before retirement")
        os.unlink(ATTEMPT_NAME, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
