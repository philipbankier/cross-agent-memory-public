from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.publication_work import EvidencePublicationPending
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
)

JOURNAL_NAME = ".object-write-attempt.jsonl"
MAX_LINE_BYTES = 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ObjectWriteScope:
    operation_sha256: str
    binding_sha256: str
    max_objects: int
    max_bytes: int

    def header(self) -> dict[str, Any]:
        if not _DIGEST.fullmatch(self.operation_sha256) or not _DIGEST.fullmatch(
            self.binding_sha256
        ):
            raise ValueError("object write scope requires SHA-256 identities")
        if any(
            type(value) is not int or value <= 0 for value in (self.max_objects, self.max_bytes)
        ):
            raise ValueError("object write limits must be positive integers")
        return {"version": 1, **self.__dict__}


@dataclass
class _Entry:
    size: int
    identity: tuple[int, int, int, int] | None = None


def _line(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def _identity(value: os.stat_result) -> tuple[int, int, int, int]:
    # A rename changes ctime, but must preserve these fields. Retirement records fresh ctime.
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def check_object_write_access(root: Path, scope: ObjectWriteScope | None) -> None:
    path = root / JOURNAL_NAME
    if not path.exists() and not path.is_symlink():
        return
    if scope is None:
        raise RuntimeError("an unfinished object write attempt requires its exact import retry")
    parent = open_directory_no_symlinks(root, "object write journal parent")
    try:
        descriptor = os.open(
            JOURNAL_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        try:
            _require_private_file(os.fstat(descriptor))
            raw = os.pread(descriptor, MAX_LINE_BYTES + 1, 0)
            header, separator, _rest = raw.partition(b"\n")
            expected = _line(scope.header())
            matches = header + separator == expected if separator else expected.startswith(header)
            if not matches:
                raise RuntimeError(
                    "object write attempt belongs to another operation or configuration"
                )
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _require_private_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("object write journal must be an owned private single-link file")


class ObjectWriteJournal:
    """One bounded, text-free filesystem write intent, held under the ledger's exclusive writer."""

    def __init__(self, root: Path, scope: ObjectWriteScope):
        scope.header()
        self.root = root
        self.scope = scope
        self.entries: dict[str, _Entry] = {}
        self.reserved_bytes = 0
        self.aborting = False
        self.tail = b""
        self.removed = False
        self.parent = open_directory_no_symlinks(root, "object write journal parent")
        self.descriptor: int | None = None
        try:
            parent = os.fstat(self.parent)
            if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
                raise RuntimeError("object write journal parent must be owned and private")
            self.descriptor = os.open(
                JOURNAL_NAME,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=self.parent,
            )
            self.stamp = os.fstat(self.descriptor)
            _require_private_file(self.stamp)
            if self.stamp.st_size > (scope.max_objects * 2 + 2) * MAX_LINE_BYTES:
                raise RuntimeError("object write journal exceeds its byte bound")
            with os.fdopen(os.dup(self.descriptor), "rb") as stream:
                header = stream.readline(MAX_LINE_BYTES + 1)
                if header.endswith(b"\n"):
                    if header != _line(scope.header()):
                        raise RuntimeError(
                            "object write attempt belongs to another operation or configuration"
                        )
                    while raw := stream.readline(MAX_LINE_BYTES + 1):
                        if len(raw) > MAX_LINE_BYTES:
                            raise RuntimeError("object write journal entry exceeds its bound")
                        if not raw.endswith(b"\n"):
                            self.tail = raw
                            break
                        self._load_entry(raw)
                else:
                    self.tail = header
            self._assert_unchanged()
            if not header.endswith(b"\n"):
                self._append(scope.header())
            os.fsync(self.descriptor)
            os.fsync(self.parent)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        os.close(self.parent)

    def _assert_unchanged(self) -> None:
        assert self.descriptor is not None
        current = os.stat(JOURNAL_NAME, dir_fd=self.parent, follow_symlinks=False)
        opened = os.fstat(self.descriptor)
        for value in (current, opened):
            _require_private_file(value)
            if (_identity(value), value.st_ctime_ns) != (
                _identity(self.stamp),
                self.stamp.st_ctime_ns,
            ):
                raise RuntimeError("object write journal changed")

    def _append(self, value: dict[str, Any]) -> None:
        assert self.descriptor is not None
        raw = _line(value)
        if len(raw) > MAX_LINE_BYTES or not raw.startswith(self.tail):
            raise RuntimeError("unfinished object write journal entry does not match this retry")
        self._assert_unchanged()
        offset = self.stamp.st_size
        remaining = raw[len(self.tail) :]
        while remaining:
            written = os.pwrite(self.descriptor, remaining, offset)
            if written <= 0:
                raise OSError("object write journal made no write progress")
            offset += written
            remaining = remaining[written:]
        os.fsync(self.descriptor)
        self.stamp = os.fstat(self.descriptor)
        self.tail = b""

    def _load_entry(self, raw: bytes) -> None:
        parsed: Any = json.loads(raw)
        if not isinstance(parsed, dict):
            raise RuntimeError("invalid object write journal entry")
        value = cast(dict[str, Any], parsed)
        if _line(value) != raw or self.aborting:
            raise RuntimeError("invalid object write journal entry")
        if value == {"kind": "abort"}:
            self.aborting = True
            return
        digest = value.get("digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise RuntimeError("invalid object write identity")
        if set(value) == {"kind", "digest", "size"} and value["kind"] == "reserve":
            size = value["size"]
            self._check_reservation(digest, size)
            if digest in self.entries:
                raise RuntimeError("duplicate object write reservation")
            self.entries[digest] = _Entry(size)
            self.reserved_bytes += size
        elif set(value) == {"kind", "digest", "identity"} and value["kind"] == "ready":
            identity: Any = value["identity"]
            entry = self.entries.get(digest)
            if (
                entry is None
                or entry.identity is not None
                or not isinstance(identity, list)
                or len(cast(list[Any], identity)) != 4
                or any(type(item) is not int or item < 0 for item in cast(list[Any], identity))
                or identity[2] != entry.size
            ):
                raise RuntimeError("invalid object write ownership")
            entry.identity = cast(tuple[int, int, int, int], tuple(cast(list[Any], identity)))
        else:
            raise RuntimeError("unknown object write journal entry")

    def _check_reservation(self, digest: str, size: int) -> None:
        if not _DIGEST.fullmatch(digest) or type(size) is not int or size < 0:
            raise ValueError("invalid object write reservation")
        existing = self.entries.get(digest)
        if existing is not None:
            if size != existing.size:
                raise RuntimeError("object write reservation size changed")
        elif (
            len(self.entries) >= self.scope.max_objects
            or self.reserved_bytes + size > self.scope.max_bytes
        ):
            raise EvidencePublicationPending("object write staging budget exceeded")

    def reserve(self, digest: str, size: int) -> None:
        if self.aborting:
            raise RuntimeError("object write rollback is incomplete")
        self._check_reservation(digest, size)
        if digest not in self.entries:
            self._append({"kind": "reserve", "digest": digest, "size": size})
            self.entries[digest] = _Entry(size)
            self.reserved_bytes += size

    def ready(self, digest: str, metadata: os.stat_result) -> None:
        _require_private_file(metadata)
        entry = self.entries[digest]
        identity = _identity(metadata)
        if entry.size != metadata.st_size:
            raise RuntimeError("prepared object size changed")
        if entry.identity is None:
            self._append({"kind": "ready", "digest": digest, "identity": identity})
            entry.identity = identity
        elif entry.identity != identity:
            raise RuntimeError("prepared object ownership changed")

    def owns(self, path: Path) -> bool:
        entry = self.entries.get(path.name)
        if entry is None:
            return False
        metadata = path.lstat()
        _require_private_file(metadata)
        if entry.identity != _identity(metadata):
            raise RuntimeError("prepared object ownership changed")
        return True

    def _paths(
        self, registered: Callable[[str, int], bool], *, committed: bool
    ) -> list[tuple[Path, os.stat_result]]:
        paths: list[tuple[Path, os.stat_result]] = []
        for digest, entry in self.entries.items():
            if registered(digest, entry.size) != committed:
                raise RuntimeError("object write outcome differs from the ledger")
            canonical = self.root / "objects" / "sha256" / digest[:2] / digest
            pending = canonical.with_name(f".{digest}.pending")
            if committed and (entry.identity is None or pending.exists() or pending.is_symlink()):
                raise RuntimeError("committed object write has unfinished preparation")
            for path in (canonical, pending):
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    if committed and path == canonical:
                        raise RuntimeError("committed object write is missing its file") from None
                    continue
                _require_private_file(metadata)
                if entry.identity != _identity(metadata):
                    raise RuntimeError("prepared object ownership changed")
                descriptor, _resolved = open_regular_file_no_symlinks(path, "prepared object")
                try:
                    opened = os.fstat(descriptor)
                    if (_identity(opened), opened.st_ctime_ns) != (
                        _identity(metadata),
                        metadata.st_ctime_ns,
                    ) or opened.st_size != entry.size:
                        raise RuntimeError("prepared object changed or remains partial")
                    digest_check = hashlib.sha256()
                    offset = 0
                    while offset < entry.size:
                        chunk = os.pread(descriptor, min(1024 * 1024, entry.size - offset), offset)
                        if not chunk:
                            raise RuntimeError("prepared object changed or remains partial")
                        digest_check.update(chunk)
                        offset += len(chunk)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                if digest_check.hexdigest() != digest or (
                    _identity(metadata),
                    metadata.st_ctime_ns,
                ) != (_identity(after), after.st_ctime_ns):
                    raise RuntimeError("prepared object changed or remains partial")
                paths.append((path, metadata))
        return paths

    def abort(self, registered: Callable[[str, int], bool]) -> bool:
        if self.tail and not _line({"kind": "abort"}).startswith(self.tail):
            return False
        try:
            paths = self._paths(registered, committed=False)
        except (OSError, ValueError, RuntimeError):
            return False
        if not self.aborting:
            self._append({"kind": "abort"})
            self.aborting = True
        for path, metadata in paths:
            parent = open_directory_no_symlinks(path.parent, "prepared object parent")
            try:
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if (_identity(current), current.st_ctime_ns) != (
                    _identity(metadata),
                    metadata.st_ctime_ns,
                ):
                    raise RuntimeError("prepared object changed before rollback")
                os.unlink(path.name, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        self._remove()
        return True

    @property
    def rollback_pending(self) -> bool:
        return self.aborting or bool(self.tail and _line({"kind": "abort"}).startswith(self.tail))

    def finish(self, registered: Callable[[str, int], bool]) -> None:
        if self.aborting or self.tail:
            raise RuntimeError("object write attempt is not complete")
        self._paths(registered, committed=True)
        self._remove()

    def _remove(self) -> None:
        self._assert_unchanged()
        os.unlink(JOURNAL_NAME, dir_fd=self.parent)
        os.fsync(self.parent)
        self.removed = True
