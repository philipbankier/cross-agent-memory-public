from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal
from uuid import uuid4

from cross_assistant_memory.browser_observation import (
    MAX_ENVELOPE_BYTES,
    BrowserObservation,
    parse_browser_observation,
)
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    publish_file_no_replace_at,
)
from cross_assistant_memory.tink_crypto import AeadPrimitive, Keyset

DEFAULT_MAX_BYTES = 32 * 1024 * 1024
_MAX_KEY_BYTES = 64 * 1024
_MAX_CIPHERTEXT_BYTES = MAX_ENVELOPE_BYTES + 1024
_LOCK_NAME = ".browser-capture.lock"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FILE_NAME = re.compile(r"observation\.([0-9a-f]{64})")


class BrowserCaptureSpoolError(RuntimeError):
    pass


class BrowserCaptureSpoolFull(BrowserCaptureSpoolError):
    pass


class BrowserCaptureSpool:
    def __init__(self, root: Path, key_file: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        try:
            if type(max_bytes) is not int or max_bytes < 1:
                raise BrowserCaptureSpoolError("browser capture spool byte limit is invalid")
            self._root = _absolute_path(root)
            self._key_file = _absolute_path(key_file)
            self._max_bytes = max_bytes
            descriptor = open_directory_no_symlinks(self._root, "browser capture spool")
            try:
                self._root_identity = _directory_identity(descriptor)
            finally:
                os.close(descriptor)
            _, self._key_identity = self._load_key()
        except BrowserCaptureSpoolError:
            raise
        except Exception:
            raise BrowserCaptureSpoolError(
                "browser capture spool configuration is invalid"
            ) from None

    def put(self, observation: BrowserObservation) -> Literal["queued", "already_queued"]:
        with self._locked() as (directory, primitive):
            if type(observation) is not BrowserObservation:
                raise BrowserCaptureSpoolError("browser capture spool observation is invalid")
            plaintext = observation.canonical_bytes()
            validated = parse_browser_observation(plaintext)
            digest = validated.content_digest
            inventory = self._inventory(directory, primitive)
            if digest in inventory:
                # Retain the original ciphertext and observation time, even after a new poll.
                return "already_queued"
            ciphertext = primitive.encrypt(plaintext, _associated_data(digest))
            if not 0 < len(ciphertext) <= _MAX_CIPHERTEXT_BYTES:
                raise BrowserCaptureSpoolError("browser capture spool ciphertext size is invalid")
            if sum(inventory.values()) + len(ciphertext) > self._max_bytes:
                raise BrowserCaptureSpoolFull("browser capture spool is full")
            self._publish(directory, digest, ciphertext)
            return "queued"

    def read(self, digest: str) -> BrowserObservation:
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise BrowserCaptureSpoolError("browser capture spool digest is invalid")
        with self._locked() as (directory, primitive):
            inventory = self._inventory(directory, primitive)
            if digest not in inventory:
                raise BrowserCaptureSpoolError("browser capture spool observation was not found")
            ciphertext, _ = _read_private_file(
                directory, f"observation.{digest}", {0o400}, _MAX_CIPHERTEXT_BYTES
            )
            return _decode(primitive, digest, ciphertext)

    def status(self) -> dict[str, int]:
        with self._locked() as (directory, primitive):
            inventory = self._inventory(directory, primitive)
            used = sum(inventory.values())
            return {
                "queued_observations": len(inventory),
                "ciphertext_bytes": used,
                "max_bytes": self._max_bytes,
                "available_bytes": max(0, self._max_bytes - used),
            }

    def pending(self, limit: int = 2) -> tuple[str, ...]:
        if type(limit) is not int or not 1 <= limit <= 10:
            raise BrowserCaptureSpoolError("browser capture pending limit is invalid")
        with self._locked() as (directory, primitive):
            return tuple(sorted(self._inventory(directory, primitive)))[:limit]

    @property
    def root(self) -> Path:
        return self._root

    def acknowledge(self, digest: str, receipt: dict[str, object], status_code: int) -> None:
        from cross_assistant_memory.browser_capture_upload import browser_observation_uploads
        from cross_assistant_memory.models import UploadReceipt
        from cross_assistant_memory.uploads import validate_upload_receipt

        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise BrowserCaptureSpoolError("browser capture spool digest is invalid")
        with self._locked() as (directory, primitive):
            ciphertext, _ = _read_private_file(
                directory, f"observation.{digest}", {0o400}, _MAX_CIPHERTEXT_BYTES
            )
            observation = _decode(primitive, digest, ciphertext)
            if len(observation.messages) != 1:
                raise BrowserCaptureSpoolError(
                    "browser capture acknowledgement requires one message"
                )
            batch = browser_observation_uploads(observation)[0]
            validate_upload_receipt(
                batch, UploadReceipt.from_dict(receipt), status_code=status_code
            )
            # Only this authenticated, exact node receipt permits retiring the queued copy.
            os.unlink(f"observation.{digest}", dir_fd=directory)
            os.fsync(directory)

    @contextmanager
    def _locked(self) -> Generator[tuple[int, AeadPrimitive], None, None]:
        directory: int | None = None
        lock: int | None = None
        try:
            directory = open_directory_no_symlinks(self._root, "browser capture spool")
            if _directory_identity(directory) != self._root_identity:
                raise BrowserCaptureSpoolError("browser capture spool directory changed")
            primitive, key_identity = self._load_key()
            if key_identity != self._key_identity:
                raise BrowserCaptureSpoolError("browser capture spool key changed")
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            try:
                lock = os.open(_LOCK_NAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            except FileExistsError:
                lock = os.open(_LOCK_NAME, flags, dir_fd=directory)
            _validate_file(os.fstat(lock), {0o600}, allow_empty=True)
            if os.fstat(lock).st_size != 0:
                raise BrowserCaptureSpoolError("browser capture spool lock is invalid")
            fcntl.flock(lock, fcntl.LOCK_EX)
            self._check_locked_paths(directory, lock)
            yield directory, primitive
            self._check_locked_paths(directory, lock)
        except BrowserCaptureSpoolError:
            raise
        except Exception:
            raise BrowserCaptureSpoolError("browser capture spool operation failed") from None
        finally:
            if lock is not None:
                os.close(lock)
            if directory is not None:
                os.close(directory)

    def _check_locked_paths(self, directory: int, lock: int) -> None:
        current = open_directory_no_symlinks(self._root, "browser capture spool")
        try:
            if _directory_identity(current) != self._root_identity:
                raise BrowserCaptureSpoolError("browser capture spool directory changed")
        finally:
            os.close(current)
        metadata = os.fstat(lock)
        _validate_file(metadata, {0o600}, allow_empty=True)
        linked = os.stat(_LOCK_NAME, dir_fd=directory, follow_symlinks=False)
        if metadata.st_size != 0 or _file_identity(metadata) != _file_identity(linked):
            raise BrowserCaptureSpoolError("browser capture spool lock changed")

    def _load_key(self) -> tuple[AeadPrimitive, tuple[object, ...]]:
        parent = open_directory_no_symlinks(self._key_file.parent, "browser capture key directory")
        try:
            parent_identity = _directory_identity(parent)
            serialized, identity = _read_private_file(
                parent, self._key_file.name, {0o400, 0o600}, _MAX_KEY_BYTES
            )
        finally:
            os.close(parent)
        primitive = Keyset.read_cleartext(serialized).aead()
        return primitive, (parent_identity, identity, hashlib.sha256(serialized).digest())

    def _inventory(self, directory: int, primitive: AeadPrimitive) -> dict[str, int]:
        inventory: dict[str, int] = {}
        for name in os.listdir(directory):
            if name == _LOCK_NAME:
                continue
            if self._key_file.parent == self._root and name == self._key_file.name:
                continue
            match = _FILE_NAME.fullmatch(name)
            if match is None:
                raise BrowserCaptureSpoolError("browser capture spool contains an unexpected entry")
            ciphertext, _ = _read_private_file(directory, name, {0o400}, _MAX_CIPHERTEXT_BYTES)
            digest = match.group(1)
            _decode(primitive, digest, ciphertext)
            inventory[digest] = len(ciphertext)
        return inventory

    def _publish(self, directory: int, digest: str, ciphertext: bytes) -> None:
        temporary = f".observation.{digest}.{uuid4().hex}.pending"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(ciphertext)
                handle.flush()
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
            publish_file_no_replace_at(
                directory,
                temporary,
                f"observation.{digest}",
                required_mode=0o400,
                label="browser capture ciphertext",
                expected_source_descriptor=descriptor,
                retain_on_failure=True,
            )
        finally:
            # Interrupted ciphertext stays in place and blocks later writes; never evict it.
            os.close(descriptor)


def _absolute_path(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise BrowserCaptureSpoolError("browser capture spool requires absolute paths")
    return path


def _directory_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise BrowserCaptureSpoolError("browser capture spool requires owner-only directories")
    return metadata.st_dev, metadata.st_ino


def _validate_file(metadata: os.stat_result, modes: set[int], *, allow_empty: bool = False) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) not in modes
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or (not allow_empty and metadata.st_size == 0)
    ):
        raise BrowserCaptureSpoolError("browser capture spool requires owner-only regular files")


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_private_file(
    directory: int, name: str, modes: set[int], max_bytes: int
) -> tuple[bytes, tuple[int, ...]]:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory
    )
    try:
        before = os.fstat(descriptor)
        _validate_file(before, modes)
        if before.st_size > max_bytes:
            raise BrowserCaptureSpoolError("browser capture spool file exceeds its byte limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
        after = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory, follow_symlinks=False)
        identity = _file_identity(before)
        if (
            identity != _file_identity(after)
            or identity != _file_identity(linked)
            or len(data) != before.st_size
        ):
            raise BrowserCaptureSpoolError("browser capture spool file changed while reading")
        return data, identity
    finally:
        os.close(descriptor)


def _associated_data(digest: str) -> bytes:
    return json.dumps(
        {"format_version": 1, "kind": "browser_capture_spool", "content_digest": digest},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _decode(primitive: AeadPrimitive, digest: str, ciphertext: bytes) -> BrowserObservation:
    plaintext = primitive.decrypt(ciphertext, _associated_data(digest))
    observation = parse_browser_observation(plaintext)
    if observation.content_digest != digest or observation.canonical_bytes() != plaintext:
        raise BrowserCaptureSpoolError("browser capture spool observation binding is invalid")
    return observation
