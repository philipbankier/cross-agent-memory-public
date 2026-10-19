from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import re
import stat
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

from cross_assistant_memory.object_store import (
    MAX_OBJECT_PURGE_ENTRIES,
    BackendObjectStat,
    IncompleteCleanupReport,
    ObjectBackend,
    ObjectPurgeInventory,
    ObjectVersion,
)
from cross_assistant_memory.private_json import load_owner_only_json, write_owner_only_json
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
)
from cross_assistant_memory.tink_crypto import (
    AeadPrimitive,
    Keyset,
    StreamingAeadPrimitive,
)

ENVELOPE_FORMAT_VERSION = 1
RECOVERY_KIT_FORMAT_VERSION = 1
ENCRYPTION_PROFILE = "tink-streaming-aead:aes256-gcm-hkdf-1mb:v1"
ROOT_KEY_PROFILE = "tink-aead:aes256-gcm:v1"
CHUNK_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RECOVERY_SECRET_BYTES = 64 * 1024
MAX_RECOVERY_KIT_BYTES = 1024 * 1024

_OBJECT_AAD_PREFIX = b"cross-agent-memory:object:v1\0"
_KEYSET_AAD_PREFIX = b"cross-agent-memory:object-keyset:v1\0"
_MANIFEST_AAD_PREFIX = b"cross-agent-memory:manifest:v1\0"
_RECOVERY_KEYSET_AAD_PREFIX = b"cross-agent-memory:recovery-keyset:v1\0"
_RECOVERY_CANARY_AAD_PREFIX = b"cross-agent-memory:recovery-canary:v1\0"
_RECOVERY_CANARY = b"cross-agent-memory recovery canary v1"
_OPERATIONAL_KEY_AAD = b"cross-agent-memory:operational-key:v1\0"
MAX_OPERATIONAL_KEY_BYTES = 2 * MAX_RECOVERY_KIT_BYTES
DEFAULT_FILESYSTEM_PURGE_READ_BYTES = 16 * 1024 * 1024 * 1024

_SOURCE_OBJECT_ID = re.compile(r"source_[0-9a-f]{32}")
_STORAGE_OBJECT_ID = re.compile(r"storage_[0-9a-f]{32}")
_ROOT_KEY_ID = re.compile(r"root_[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ObjectState(str):
    PENDING = "pending"
    UPLOADED = "uploaded"
    VERIFIED = "verified"


@dataclass(frozen=True)
class EncryptedObjectManifest:
    format_version: int
    source_object_id: str
    storage_object_id: str
    legacy_source_object_id: str | None
    backend_profile: str
    state: str
    encryption_profile: str
    root_key_id: str
    media_type: str
    plaintext_sha256: str
    plaintext_byte_length: int
    ciphertext_sha256: str
    ciphertext_byte_length: int
    wrapped_data_key: str
    object_aad_sha256: str
    created_at: str
    updated_at: str
    authentication_tag: str

    def as_dict(self, *, include_authentication: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "format_version": self.format_version,
            "source_object_id": self.source_object_id,
            "storage_object_id": self.storage_object_id,
            "legacy_source_object_id": self.legacy_source_object_id,
            "backend_profile": self.backend_profile,
            "state": self.state,
            "encryption_profile": self.encryption_profile,
            "root_key_id": self.root_key_id,
            "media_type": self.media_type,
            "plaintext_sha256": self.plaintext_sha256,
            "plaintext_byte_length": self.plaintext_byte_length,
            "ciphertext_sha256": self.ciphertext_sha256,
            "ciphertext_byte_length": self.ciphertext_byte_length,
            "wrapped_data_key": self.wrapped_data_key,
            "object_aad_sha256": self.object_aad_sha256,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if include_authentication:
            value["authentication_tag"] = self.authentication_tag
        return value

    @classmethod
    def from_dict(cls, value: object) -> EncryptedObjectManifest:
        if not isinstance(value, dict):
            raise ValueError("encrypted object manifest must be an object")
        fields = cast(dict[object, object], value)
        expected = {
            "format_version",
            "source_object_id",
            "storage_object_id",
            "legacy_source_object_id",
            "backend_profile",
            "state",
            "encryption_profile",
            "root_key_id",
            "media_type",
            "plaintext_sha256",
            "plaintext_byte_length",
            "ciphertext_sha256",
            "ciphertext_byte_length",
            "wrapped_data_key",
            "object_aad_sha256",
            "created_at",
            "updated_at",
            "authentication_tag",
        }
        if set(fields) != expected:
            raise ValueError("encrypted object manifest fields are invalid")
        manifest = cls(
            format_version=_required_int(fields, "format_version"),
            source_object_id=_required_str(fields, "source_object_id"),
            storage_object_id=_required_str(fields, "storage_object_id"),
            legacy_source_object_id=_optional_str(fields, "legacy_source_object_id"),
            backend_profile=_required_str(fields, "backend_profile"),
            state=_required_str(fields, "state"),
            encryption_profile=_required_str(fields, "encryption_profile"),
            root_key_id=_required_str(fields, "root_key_id"),
            media_type=_required_str(fields, "media_type"),
            plaintext_sha256=_required_str(fields, "plaintext_sha256"),
            plaintext_byte_length=_required_int(fields, "plaintext_byte_length"),
            ciphertext_sha256=_required_str(fields, "ciphertext_sha256"),
            ciphertext_byte_length=_required_int(fields, "ciphertext_byte_length"),
            wrapped_data_key=_required_str(fields, "wrapped_data_key"),
            object_aad_sha256=_required_str(fields, "object_aad_sha256"),
            created_at=_required_str(fields, "created_at"),
            updated_at=_required_str(fields, "updated_at"),
            authentication_tag=_required_str(fields, "authentication_tag"),
        )
        manifest.validate()
        return manifest

    def validate(self, *, require_authentication: bool = True) -> None:
        if self.format_version != ENVELOPE_FORMAT_VERSION:
            raise ValueError("unsupported encrypted object format")
        _validate_identifier(self.source_object_id, _SOURCE_OBJECT_ID, "source object")
        _validate_identifier(self.storage_object_id, _STORAGE_OBJECT_ID, "storage object")
        _validate_identifier(self.root_key_id, _ROOT_KEY_ID, "root key")
        if self.legacy_source_object_id is not None and not self.legacy_source_object_id:
            raise ValueError("legacy source object id must not be empty")
        if not self.backend_profile or len(self.backend_profile) > 128:
            raise ValueError("backend profile is invalid")
        if self.state not in {
            ObjectState.PENDING,
            ObjectState.UPLOADED,
            ObjectState.VERIFIED,
        }:
            raise ValueError("encrypted object state is invalid")
        if self.encryption_profile != ENCRYPTION_PROFILE:
            raise ValueError("unsupported encryption profile")
        if not self.media_type or len(self.media_type) > 255:
            raise ValueError("media type is invalid")
        _validate_sha256(self.plaintext_sha256, "plaintext")
        _validate_sha256(self.ciphertext_sha256, "ciphertext")
        _validate_sha256(self.object_aad_sha256, "object AAD")
        if self.plaintext_byte_length < 0 or self.ciphertext_byte_length <= 0:
            raise ValueError("encrypted object byte lengths are invalid")
        _decode_base64(self.wrapped_data_key, "wrapped data key")
        if require_authentication:
            _decode_base64(self.authentication_tag, "manifest authentication tag")
        elif self.authentication_tag:
            raise ValueError("unsigned manifest must not have an authentication tag")
        _validate_timestamp(self.created_at)
        _validate_timestamp(self.updated_at)


class RootKey:
    def __init__(self, key_id: str, keyset: Keyset) -> None:
        _validate_identifier(key_id, _ROOT_KEY_ID, "root key")
        self._key_id = key_id
        self._keyset = keyset

    @property
    def key_id(self) -> str:
        return self._key_id

    @classmethod
    def generate(cls) -> RootKey:
        return cls(f"root_{uuid.uuid4().hex}", Keyset.generate_aead())

    def primitive(self) -> AeadPrimitive:
        return self._keyset.aead()

    def write_encrypted_keyset(self, wrapping_aead: AeadPrimitive, associated_data: bytes) -> bytes:
        return self._keyset.write_encrypted(wrapping_aead, associated_data)

    def serialize_cleartext_keyset(self) -> bytes:
        return self._keyset.serialize_cleartext()


class RecoverySecret:
    def __init__(self, serialized_keyset: bytes) -> None:
        if not serialized_keyset or len(serialized_keyset) > MAX_RECOVERY_SECRET_BYTES:
            raise ValueError("recovery secret size is invalid")
        try:
            Keyset.read_cleartext(serialized_keyset).aead()
        except Exception as error:
            raise ValueError("recovery secret is invalid") from error
        self._serialized_keyset = bytes(serialized_keyset)

    def __repr__(self) -> str:
        return "RecoverySecret(<redacted>)"

    @classmethod
    def generate(cls) -> RecoverySecret:
        return cls(Keyset.generate_aead().serialize_cleartext())

    @classmethod
    def load(cls, path: Path) -> RecoverySecret:
        descriptor, _ = open_regular_file_no_symlinks(path, "recovery secret")
        try:
            before = os.fstat(descriptor)
            if (
                before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_size > MAX_RECOVERY_SECRET_BYTES
            ):
                raise ValueError("recovery secret must be an owner-only single-link bounded file")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                raw = handle.read(MAX_RECOVERY_SECRET_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            _stat_identity(before) != _stat_identity(after)
            or before.st_ctime_ns != after.st_ctime_ns
            or len(raw) != before.st_size
        ):
            raise ValueError("recovery secret changed while reading")
        return cls(raw)

    def write(self, path: Path) -> None:
        _write_new_private_file(path, self._serialized_keyset, mode=0o400)

    def primitive(self) -> AeadPrimitive:
        return Keyset.read_cleartext(self._serialized_keyset).aead()


class OperationalKey:
    """An owner-only mounted key bound to one previously verified recovery kit."""

    def __init__(self, root_key: RootKey, recovery_kit: bytes, authentication_tag: bytes) -> None:
        self._root_key = root_key
        self._recovery_kit = recovery_kit
        self._authentication_tag = authentication_tag
        self.recovery_kit(root_key)

    def __repr__(self) -> str:
        return "OperationalKey(<redacted>)"

    @property
    def root_key(self) -> RootKey:
        return self._root_key

    @classmethod
    def from_recovery_kit(cls, raw: bytes, secret: RecoverySecret) -> OperationalKey:
        root_key = restore_root_key_from_bytes(raw, secret)
        tag = root_key.primitive().encrypt(b"", cls._binding(root_key, raw))
        return cls(root_key, raw, tag)

    @classmethod
    def load(cls, path: Path) -> OperationalKey:
        try:
            fields = cast(
                dict[object, object],
                load_owner_only_json(
                    path, max_bytes=MAX_OPERATIONAL_KEY_BYTES, label="operational key"
                ),
            )
            if set(fields) != {
                "format_version",
                "root_key_profile",
                "root_key_id",
                "root_keyset",
                "root_recovery_kit",
                "authentication_tag",
            }:
                raise ValueError("operational key fields are invalid")
            if (
                _required_int(fields, "format_version") != 1
                or fields["root_key_profile"] != ROOT_KEY_PROFILE
            ):
                raise ValueError("unsupported operational key format")
            keyset = _decode_base64(_required_str(fields, "root_keyset"), "root keyset")
            if len(keyset) > MAX_RECOVERY_SECRET_BYTES:
                raise ValueError("operational keyset exceeds its size limit")
            root_key = RootKey(_required_str(fields, "root_key_id"), Keyset.read_cleartext(keyset))
            kit = _decode_base64(_required_str(fields, "root_recovery_kit"), "root recovery kit")
            tag = _decode_base64(_required_str(fields, "authentication_tag"), "key authentication")
            return cls(root_key, kit, tag)
        except Exception as error:
            raise ValueError(
                f"operational key is invalid or unavailable ({type(error).__name__})"
            ) from None

    def write(self, path: Path) -> None:
        self.recovery_kit(self._root_key)
        write_owner_only_json(
            path,
            {
                "format_version": 1,
                "root_key_profile": ROOT_KEY_PROFILE,
                "root_key_id": self._root_key.key_id,
                "root_keyset": _encode_base64(self._root_key.serialize_cleartext_keyset()),
                "root_recovery_kit": _encode_base64(self._recovery_kit),
                "authentication_tag": _encode_base64(self._authentication_tag),
            },
            label="operational key",
            max_bytes=MAX_OPERATIONAL_KEY_BYTES,
        )

    def recovery_kit(self, root_key: RootKey) -> bytes:
        if root_key.key_id != self._root_key.key_id:
            raise ValueError("operational root key identity does not match")
        try:
            plaintext = root_key.primitive().decrypt(
                self._authentication_tag, self._binding(root_key, self._recovery_kit)
            )
        except Exception:
            raise ValueError("operational recovery kit authentication failed") from None
        if plaintext != b"":
            raise ValueError("operational recovery kit authentication failed")
        return self._recovery_kit

    def restore_root_key(self, raw: bytes) -> RootKey:
        if raw != self.recovery_kit(self._root_key):
            raise ValueError("package does not contain the operational key's verified recovery kit")
        return self._root_key

    @staticmethod
    def _binding(root_key: RootKey, recovery_kit: bytes) -> bytes:
        if not 0 < len(recovery_kit) <= MAX_RECOVERY_KIT_BYTES:
            raise ValueError("operational recovery kit size is invalid")
        keyset_digest = hashlib.sha256(root_key.serialize_cleartext_keyset()).digest()
        return (
            _OPERATIONAL_KEY_AAD + root_key.key_id.encode() + b"\0" + keyset_digest + recovery_kit
        )


RecoveryKeyAccess = RecoverySecret | OperationalKey


class FilesystemObjectBackend:
    def __init__(
        self,
        root: Path,
        *,
        purge_max_bytes: int = DEFAULT_FILESYSTEM_PURGE_READ_BYTES,
        create: bool = True,
    ) -> None:
        if type(purge_max_bytes) is not int or not 0 < purge_max_bytes < 2**63:
            raise ValueError("filesystem purge read budget must be a positive byte count")
        self._purge_max_bytes = purge_max_bytes
        self._root = root.expanduser()
        prepare = _ensure_private_directory if create else _require_existing_private_directory
        prepare(self._root)
        self._root = self._root.resolve(strict=True)
        self._objects = self._root / "objects"
        self._incomplete = self._root / "incomplete"
        prepare(self._objects)
        prepare(self._incomplete)

    @property
    def profile(self) -> str:
        return "filesystem-v1"

    @property
    def identity_sha256(self) -> str:
        root = self._root.resolve(strict=True)
        value = root.stat()
        if not stat.S_ISDIR(value.st_mode):
            raise ValueError("encrypted backend root must be a directory")
        # Directory timestamps change on writes and must not identify the store.
        identity = _canonical_json([self.profile, str(root), value.st_dev, value.st_ino])
        return hashlib.sha256(identity.encode()).hexdigest()

    def exists(self, storage_object_id: str) -> bool:
        path = self._object_path(storage_object_id)
        if path.is_symlink():
            raise RuntimeError("encrypted backend object must not be a symlink")
        return path.is_file()

    def put_file(self, storage_object_id: str, source: Path) -> None:
        destination = self._object_path(storage_object_id)
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file():
                raise RuntimeError("encrypted backend destination is not a regular file")
            return
        partial = self._incomplete / f"{storage_object_id}.{uuid.uuid4().hex}.partial"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with _open_regular_file(source) as source_handle:
            destination_descriptor = os.open(partial, flags, 0o600)
            try:
                output = os.fdopen(destination_descriptor, "wb")
            except Exception:
                os.close(destination_descriptor)
                raise
            with output:
                _copy_stream(source_handle, output)
                output.flush()
                os.fsync(output.fileno())
        try:
            os.link(partial, destination)
        except FileExistsError as error:
            if destination.is_symlink() or not destination.is_file():
                raise RuntimeError("encrypted backend destination is not a regular file") from error
        destination.chmod(0o600)
        _fsync_directory(destination.parent)
        partial.unlink(missing_ok=True)

    def open(self, storage_object_id: str) -> BinaryIO:
        return _open_regular_file(self._object_path(storage_object_id))

    def stat(self, storage_object_id: str) -> BackendObjectStat:
        path = self._object_path(storage_object_id)
        if path.is_symlink() or not path.is_file():
            raise KeyError(f"encrypted backend object is missing: {storage_object_id}")
        return BackendObjectStat(byte_length=path.stat().st_size)

    def inspect_object_purge(self, storage_object_id: str) -> ObjectPurgeInventory:
        first = self._object_purge_inventory(storage_object_id)
        if first != self._object_purge_inventory(storage_object_id):
            raise RuntimeError("filesystem object purge inventory changed")
        return first

    def _object_purge_inventory(self, storage_object_id: str) -> ObjectPurgeInventory:
        path = self._object_path(storage_object_id)
        scope = self._purge_scope(storage_object_id)
        target = _filesystem_purge_version(path, max_bytes=self._purge_max_bytes)
        remaining_bytes = self._purge_max_bytes - (0 if target is None else target[1].st_size)
        partials: list[tuple[str, ObjectVersion, os.stat_result]] = []
        uploads: list[str] = []
        pattern = re.compile(re.escape(storage_object_id) + r"\.([0-9a-f]{32})\.partial")
        descriptor = open_directory_no_symlinks(self._incomplete, "incomplete object directory")
        try:
            with os.scandir(descriptor) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > MAX_OBJECT_PURGE_ENTRIES:
                        raise RuntimeError("filesystem purge inventory exceeds its scan limit")
                    if not entry.name.startswith(storage_object_id + "."):
                        continue
                    match = pattern.fullmatch(entry.name)
                    if match is None:
                        raise RuntimeError("filesystem purge has an invalid incomplete identity")
                    partial = _filesystem_purge_version(
                        self._incomplete / entry.name, max_bytes=remaining_bytes
                    )
                    if partial is None:
                        raise RuntimeError("filesystem incomplete object changed during inspection")
                    partials.append((match[1], *partial))
                    remaining_bytes -= partial[1].st_size
        finally:
            os.close(descriptor)
        linked = [item for item in partials if item[2].st_nlink == 2]
        if ((target is not None and target[1].st_nlink == 2) or linked) and (
            target is None
            or target[1].st_nlink != 2
            or len(linked) != 1
            or linked[0][1] != target[0]
        ):
            raise RuntimeError("filesystem purge has an unowned hard link")
        for nonce, version, _details in partials:
            uploads.append(f"{nonce}:{version.version_id}")
        if self._purge_scope(storage_object_id) != scope:
            raise RuntimeError("filesystem object backend identity changed")
        return replace(
            scope,
            versions=() if target is None else (target[0],),
            incomplete_upload_ids=tuple(uploads),
        )

    def _purge_scope(self, storage_object_id: str) -> ObjectPurgeInventory:
        identities: list[tuple[str, int, int]] = []
        for role, directory in (
            ("root", self._root),
            ("objects", self._objects),
            ("incomplete", self._incomplete),
        ):
            descriptor = open_directory_no_symlinks(directory, "filesystem purge directory")
            try:
                details = os.fstat(descriptor)
                if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
                    raise RuntimeError("filesystem purge directories must be private and owned")
                identities.append((role, details.st_dev, details.st_ino))
            finally:
                os.close(descriptor)
        return ObjectPurgeInventory(
            self.identity_sha256,
            storage_object_id,
            namespace_identity_sha256=hashlib.sha256(
                _canonical_json(identities).encode()
            ).hexdigest(),
        )

    def purge_object(self, storage_object_id: str, expected: ObjectPurgeInventory) -> None:
        self._purge_scope(storage_object_id).require_subset_of(expected)
        current = self.inspect_object_purge(storage_object_id)
        current.require_subset_of(expected)
        for upload_id in current.incomplete_upload_ids:
            self._purge_scope(storage_object_id).require_subset_of(expected)
            nonce, version_id = upload_id.split(":", 1)
            _purge_filesystem_version(
                self._incomplete / f"{storage_object_id}.{nonce}.partial",
                version_id,
                max_bytes=self._purge_max_bytes,
                paired_path=self._object_path(storage_object_id) if current.versions else None,
            )
        current = self.inspect_object_purge(storage_object_id)
        current.require_subset_of(expected)
        for version in current.versions:
            self._purge_scope(storage_object_id).require_subset_of(expected)
            _purge_filesystem_version(
                self._object_path(storage_object_id),
                version.version_id,
                max_bytes=self._purge_max_bytes,
            )
        # A retry after unlink but before fsync must still make the observed absence durable.
        for directory in (self._objects, self._incomplete):
            descriptor = open_directory_no_symlinks(directory, "filesystem purge directory")
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        remaining = self.inspect_object_purge(storage_object_id)
        remaining.require_subset_of(expected)
        if remaining.versions or remaining.incomplete_upload_ids:
            raise RuntimeError("filesystem object purge is incomplete")

    def cleanup_incomplete(self, *, older_than_epoch: float) -> IncompleteCleanupReport:
        removed: list[str] = []
        scanned = 0
        for path in sorted(self._incomplete.iterdir()):
            scanned += 1
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"unsafe incomplete backend entry: {path}")
            if path.stat().st_mtime <= older_than_epoch:
                path.unlink()
                removed.append(path.name)
        if removed:
            _fsync_directory(self._incomplete)
        return IncompleteCleanupReport(
            removed_entries=tuple(removed),
            removed_count=len(removed),
            scanned_count=scanned,
            scan_truncated=False,
        )

    def _object_path(self, storage_object_id: str) -> Path:
        _validate_identifier(storage_object_id, _STORAGE_OBJECT_ID, "storage object")
        return self._objects / storage_object_id


def _filesystem_purge_stamp(details: os.stat_result) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink not in (1, 2)
    ):
        raise RuntimeError("filesystem purge target has unsafe ownership, type or hard links")
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
        details.st_nlink,
    )


def _filesystem_purge_version(
    path: Path, *, max_bytes: int
) -> tuple[ObjectVersion, os.stat_result] | None:
    parent = open_directory_no_symlinks(path.parent, "filesystem purge directory")
    try:
        return _filesystem_purge_version_at(parent, path.name, max_bytes=max_bytes)
    finally:
        os.close(parent)


def _filesystem_purge_version_at(
    parent: int, name: str, *, max_bytes: int
) -> tuple[ObjectVersion, os.stat_result] | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        return None
    except OSError:
        raise RuntimeError("filesystem purge target could not be opened safely") from None
    try:
        details = os.fstat(descriptor)
        stamp = _filesystem_purge_stamp(details)
        if details.st_size > max_bytes:
            raise RuntimeError("filesystem purge inventory exceeds its read budget")
        digest = hashlib.sha256()
        remaining = details.st_size
        while remaining:
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise RuntimeError("filesystem purge target changed while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if (
            os.read(descriptor, 1)
            or _filesystem_purge_stamp(os.fstat(descriptor)) != stamp
            or _filesystem_purge_stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) != stamp
        ):
            raise RuntimeError("filesystem purge target changed while hashing")
        # Own hard-link removal changes ctime/nlink. Bytes and inode remain bound across retries.
        identity = (*stamp[:4], digest.hexdigest())
        return (
            ObjectVersion(
                hashlib.sha256(_canonical_json(identity).encode()).hexdigest(), details.st_size
            ),
            details,
        )
    finally:
        os.close(descriptor)


def _purge_filesystem_version(
    path: Path, version_id: str, *, max_bytes: int, paired_path: Path | None = None
) -> None:
    parent = open_directory_no_symlinks(path.parent, "filesystem purge directory")
    try:
        current = _filesystem_purge_version_at(parent, path.name, max_bytes=max_bytes)
        if current is None:
            return
        version, details = current
        if version.version_id != version_id:
            raise RuntimeError("filesystem purge target changed beyond the retained plan")
        if details.st_nlink == 2:
            pair = (
                None
                if paired_path is None
                else _filesystem_purge_version(paired_path, max_bytes=max_bytes - details.st_size)
            )
            if pair is None or pair[0] != version or pair[1].st_nlink != 2:
                raise RuntimeError("filesystem purge hard-link pair changed")
        if _filesystem_purge_stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != (
            _filesystem_purge_stamp(details)
        ):
            raise RuntimeError("filesystem purge target changed before unlink")
        os.unlink(path.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


class InjectedBackendFailure(RuntimeError):
    pass


class DeterministicFakeBackend:
    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        self._incomplete: dict[str, tuple[bytes, float]] = {}
        self._fail_after_bytes: int | None = None
        self._identity_sha256 = hashlib.sha256(
            _canonical_json([self.profile, uuid.uuid4().hex]).encode()
        ).hexdigest()

    @property
    def profile(self) -> str:
        return "deterministic-fake-v1"

    @property
    def identity_sha256(self) -> str:
        return self._identity_sha256

    def fail_next_put_after_bytes(self, byte_count: int) -> None:
        if byte_count < 0:
            raise ValueError("failure byte count must not be negative")
        self._fail_after_bytes = byte_count

    def exists(self, storage_object_id: str) -> bool:
        _validate_identifier(storage_object_id, _STORAGE_OBJECT_ID, "storage object")
        return storage_object_id in self._objects

    def put_file(self, storage_object_id: str, source: Path) -> None:
        _validate_identifier(storage_object_id, _STORAGE_OBJECT_ID, "storage object")
        if storage_object_id in self._objects:
            return
        payload = bytearray()
        fail_after = self._fail_after_bytes
        self._fail_after_bytes = None
        with _open_regular_file(source) as handle:
            while True:
                chunk = handle.read(CHUNK_BYTES)
                if not chunk:
                    break
                if fail_after is not None and len(payload) + len(chunk) >= fail_after:
                    accepted = max(fail_after - len(payload), 0)
                    payload.extend(chunk[:accepted])
                    self._incomplete[storage_object_id] = (bytes(payload), time.time())
                    raise InjectedBackendFailure("injected backend interruption")
                payload.extend(chunk)
        self._objects[storage_object_id] = bytes(payload)
        self._incomplete.pop(storage_object_id, None)

    def open(self, storage_object_id: str) -> BinaryIO:
        _validate_identifier(storage_object_id, _STORAGE_OBJECT_ID, "storage object")
        try:
            return io.BytesIO(self._objects[storage_object_id])
        except KeyError as error:
            raise KeyError(f"encrypted backend object is missing: {storage_object_id}") from error

    def stat(self, storage_object_id: str) -> BackendObjectStat:
        _validate_identifier(storage_object_id, _STORAGE_OBJECT_ID, "storage object")
        try:
            return BackendObjectStat(byte_length=len(self._objects[storage_object_id]))
        except KeyError as error:
            raise KeyError(f"encrypted backend object is missing: {storage_object_id}") from error

    def cleanup_incomplete(self, *, older_than_epoch: float) -> IncompleteCleanupReport:
        scanned = len(self._incomplete)
        removed = tuple(
            sorted(
                storage_object_id
                for storage_object_id, (_, created_at) in self._incomplete.items()
                if created_at <= older_than_epoch
            )
        )
        for storage_object_id in removed:
            del self._incomplete[storage_object_id]
        return IncompleteCleanupReport(
            removed_entries=removed,
            removed_count=len(removed),
            scanned_count=scanned,
            scan_truncated=False,
        )

    def object_bytes(self, storage_object_id: str) -> bytes:
        return self._objects[storage_object_id]

    def inspect_object_purge(self, storage_object_id: str) -> ObjectPurgeInventory:
        _validate_identifier(storage_object_id, _STORAGE_OBJECT_ID, "storage object")
        payload = self._objects.get(storage_object_id)
        versions = (
            ()
            if payload is None
            else (ObjectVersion(hashlib.sha256(payload).hexdigest(), len(payload)),)
        )
        partial = self._incomplete.get(storage_object_id)
        uploads = (
            ()
            if partial is None
            else (
                hashlib.sha256(
                    _canonical_json([hashlib.sha256(partial[0]).hexdigest(), partial[1]]).encode()
                ).hexdigest(),
            )
        )
        return ObjectPurgeInventory(self.identity_sha256, storage_object_id, versions, uploads)

    def purge_object(self, storage_object_id: str, expected: ObjectPurgeInventory) -> None:
        ObjectPurgeInventory(self.identity_sha256, storage_object_id).require_subset_of(expected)
        current = self.inspect_object_purge(storage_object_id)
        current.require_subset_of(expected)
        self._incomplete.pop(storage_object_id, None)
        self._objects.pop(storage_object_id, None)

    def replace_object_for_test(self, storage_object_id: str, payload: bytes) -> None:
        if storage_object_id not in self._objects:
            raise KeyError(storage_object_id)
        self._objects[storage_object_id] = bytes(payload)


class EncryptedObjectStore:
    def __init__(self, metadata_root: Path, backend: ObjectBackend, root_key: RootKey) -> None:
        self._metadata_root = metadata_root.expanduser()
        self._manifests = self._metadata_root / "manifests"
        self._staging = self._metadata_root / "staging"
        self._backend = backend
        self._root_key = root_key
        _ensure_private_directory(self._metadata_root)
        _ensure_private_directory(self._manifests)
        _ensure_private_directory(self._staging)

    def put_file(
        self,
        source: Path,
        *,
        media_type: str,
        legacy_source_object_id: str | None = None,
    ) -> EncryptedObjectManifest:
        manifest = self.prepare_file(
            source, media_type=media_type, legacy_source_object_id=legacy_source_object_id
        )
        return self.resume(manifest.source_object_id)

    def prepare_file(
        self,
        source: Path,
        *,
        media_type: str,
        legacy_source_object_id: str | None = None,
        max_ciphertext_bytes: int | None = None,
        expected_plaintext_sha256: str | None = None,
        expected_plaintext_byte_length: int | None = None,
    ) -> EncryptedObjectManifest:
        """Persist authenticated pending metadata and ciphertext without backend operations."""
        if max_ciphertext_bytes is not None and (
            type(max_ciphertext_bytes) is not int or max_ciphertext_bytes <= 0
        ):
            raise ValueError("ciphertext staging byte budget must be a positive integer")
        if (expected_plaintext_sha256 is None) != (expected_plaintext_byte_length is None):
            raise ValueError("expected plaintext digest and length must be supplied together")
        if expected_plaintext_sha256 is not None:
            if type(expected_plaintext_sha256) is not str:
                raise ValueError("expected plaintext SHA-256 is invalid")
            _validate_sha256(expected_plaintext_sha256, "expected plaintext")
            if (
                type(expected_plaintext_byte_length) is not int
                or expected_plaintext_byte_length < 0
            ):
                raise ValueError("expected plaintext byte length must be a nonnegative integer")
        source = source.expanduser()
        plaintext_length, plaintext_digest, identity = _hash_regular_file(
            source, expected_byte_length=expected_plaintext_byte_length
        )
        if expected_plaintext_sha256 is not None and (
            plaintext_digest != expected_plaintext_sha256
            or plaintext_length != expected_plaintext_byte_length
        ):
            raise RuntimeError("source does not match expected plaintext digest and length")
        source_object_id = f"source_{uuid.uuid4().hex}"
        storage_object_id = f"storage_{uuid.uuid4().hex}"
        created_at = _now()
        object_aad = canonical_object_aad(
            source_object_id=source_object_id,
            storage_object_id=storage_object_id,
            media_type=media_type,
            plaintext_sha256=plaintext_digest,
            plaintext_byte_length=plaintext_length,
            legacy_source_object_id=legacy_source_object_id,
        )
        object_key = Keyset.generate_streaming_aead()
        wrapped_data_key = _write_encrypted_keyset(
            object_key,
            self._root_key.primitive(),
            _keyset_aad(object_aad, self._root_key.key_id),
        )
        staging_path = self._staging_path(storage_object_id)
        _encrypt_regular_file(
            source,
            staging_path,
            object_key.streaming_aead(),
            object_aad,
            expected_identity=identity,
            expected_sha256=plaintext_digest,
            max_ciphertext_bytes=max_ciphertext_bytes,
        )
        ciphertext_length, ciphertext_digest, _ = _hash_regular_file(staging_path)
        manifest = EncryptedObjectManifest(
            format_version=ENVELOPE_FORMAT_VERSION,
            source_object_id=source_object_id,
            storage_object_id=storage_object_id,
            legacy_source_object_id=legacy_source_object_id,
            backend_profile=self._backend.profile,
            state=ObjectState.PENDING,
            encryption_profile=ENCRYPTION_PROFILE,
            root_key_id=self._root_key.key_id,
            media_type=media_type,
            plaintext_sha256=plaintext_digest,
            plaintext_byte_length=plaintext_length,
            ciphertext_sha256=ciphertext_digest,
            ciphertext_byte_length=ciphertext_length,
            wrapped_data_key=_encode_base64(wrapped_data_key),
            object_aad_sha256=hashlib.sha256(object_aad).hexdigest(),
            created_at=created_at,
            updated_at=created_at,
            authentication_tag="",
        )
        signed = _sign_manifest(manifest, self._root_key)
        self._write_manifest(signed, self._root_key)
        return signed

    def resume(self, source_object_id: str) -> EncryptedObjectManifest:
        manifest = self.load_manifest(source_object_id)
        if manifest.backend_profile != self._backend.profile:
            raise RuntimeError("encrypted object backend profile does not match")
        if manifest.state == ObjectState.PENDING:
            if not self._backend.exists(manifest.storage_object_id):
                staging_path = self._staging_path(manifest.storage_object_id)
                _verify_regular_file(
                    staging_path,
                    expected_length=manifest.ciphertext_byte_length,
                    expected_sha256=manifest.ciphertext_sha256,
                )
                self._backend.put_file(manifest.storage_object_id, staging_path)
            manifest = self._transition(manifest, ObjectState.UPLOADED)
        if manifest.state == ObjectState.UPLOADED:
            self._verify_backend_object(manifest)
            manifest = self._transition(manifest, ObjectState.VERIFIED)
            self._staging_path(manifest.storage_object_id).unlink(missing_ok=True)
        elif manifest.state == ObjectState.VERIFIED:
            self._verify_backend_object(manifest)
        return manifest

    def load_manifest(self, source_object_id: str) -> EncryptedObjectManifest:
        path = self._manifest_path(source_object_id)
        raw = _read_private_file(path, MAX_MANIFEST_BYTES)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("encrypted object manifest is not valid JSON") from error
        manifest = EncryptedObjectManifest.from_dict(value)
        _verify_manifest(manifest, self._root_key)
        return manifest

    def register_manifest(self, manifest: EncryptedObjectManifest) -> EncryptedObjectManifest:
        manifest.validate()
        _verify_manifest(manifest, self._root_key)
        if manifest.backend_profile != self._backend.profile:
            raise RuntimeError("encrypted object backend profile does not match")
        if manifest.state != ObjectState.VERIFIED:
            raise RuntimeError("only verified encrypted object manifests can be registered")
        path = self._manifest_path(manifest.source_object_id)
        if path.exists() or path.is_symlink():
            existing = self.load_manifest(manifest.source_object_id)
            if existing != manifest:
                raise RuntimeError("encrypted object manifest already exists with different data")
            return existing
        self._write_manifest(manifest, self._root_key)
        return manifest

    def restore_file(self, source_object_id: str, output: Path) -> EncryptedObjectManifest:
        manifest = self.load_manifest(source_object_id)
        if manifest.state != ObjectState.VERIFIED:
            raise RuntimeError("encrypted object is not verified")
        self._verify_backend_object(manifest)
        object_aad = _object_aad_from_manifest(manifest)
        object_key = _read_encrypted_keyset(
            _decode_base64(manifest.wrapped_data_key, "wrapped data key"),
            self._root_key.primitive(),
            _keyset_aad(object_aad, manifest.root_key_id),
        )
        output = output.expanduser()
        if output.exists() or output.is_symlink():
            raise ValueError(f"restore output already exists: {output}")
        if output.parent.is_symlink() or not output.parent.is_dir():
            raise ValueError(f"restore output parent is invalid: {output.parent}")
        temporary = output.parent / f".{output.name}.{uuid.uuid4().hex}.partial"
        plaintext_digest = hashlib.sha256()
        plaintext_length = 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        source: BinaryIO | None = None
        reader: BinaryIO | None = None
        try:
            source = self._backend.open(manifest.storage_object_id)
            reader = object_key.streaming_aead().new_decrypting_stream(source, object_aad)
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = -1
                while True:
                    chunk = reader.read(CHUNK_BYTES)
                    if not chunk:
                        break
                    destination.write(chunk)
                    plaintext_digest.update(chunk)
                    plaintext_length += len(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            reader.close()
            if (
                plaintext_length != manifest.plaintext_byte_length
                or plaintext_digest.hexdigest() != manifest.plaintext_sha256
            ):
                raise RuntimeError("restored plaintext failed verification")
            os.link(temporary, output)
            output.chmod(0o600)
            _fsync_directory(output.parent)
            temporary.unlink()
            return manifest
        except BaseException as error:
            cleanup: list[Callable[[], object]] = []
            if descriptor >= 0:
                cleanup.append(lambda: os.close(descriptor))
            if reader is not None:
                cleanup.append(reader.close)
            if source is not None:
                cleanup.append(source.close)
            cleanup.append(lambda: temporary.unlink(missing_ok=True))
            for action in cleanup:
                try:
                    action()
                except BaseException:
                    error.add_note("encrypted restore cleanup did not complete")
            raise

    def rewrap_for_root(
        self, source_object_id: str, new_root_key: RootKey
    ) -> EncryptedObjectManifest:
        manifest = self.load_manifest(source_object_id)
        signed = rewrap_authenticated_manifest(
            manifest,
            self._root_key,
            new_root_key,
            backend_profile=manifest.backend_profile,
            max_plaintext_bytes=max(1, manifest.plaintext_byte_length),
            max_ciphertext_bytes=manifest.ciphertext_byte_length,
            allowed_states=(ObjectState.PENDING, ObjectState.UPLOADED, ObjectState.VERIFIED),
        )
        self._write_manifest(signed, new_root_key)
        return signed

    def cleanup_incomplete(self, *, older_than_epoch: float) -> IncompleteCleanupReport:
        return self._backend.cleanup_incomplete(older_than_epoch=older_than_epoch)

    def _verify_backend_object(self, manifest: EncryptedObjectManifest) -> None:
        before = self._backend.stat(manifest.storage_object_id)
        if before.byte_length != manifest.ciphertext_byte_length:
            raise RuntimeError("encrypted backend object length does not match manifest")
        digest = hashlib.sha256()
        length = 0
        with self._backend.open(manifest.storage_object_id) as source:
            while True:
                requested = min(CHUNK_BYTES, manifest.ciphertext_byte_length - length + 1)
                chunk = source.read(requested)
                if not chunk:
                    break
                length += len(chunk)
                if len(chunk) > requested or length > manifest.ciphertext_byte_length:
                    raise RuntimeError("encrypted backend object exceeds its declared length")
                digest.update(chunk)
        after = self._backend.stat(manifest.storage_object_id)
        if (
            before != after
            or length != manifest.ciphertext_byte_length
            or digest.hexdigest() != manifest.ciphertext_sha256
        ):
            raise RuntimeError("encrypted backend object failed verification")

    def _transition(
        self, manifest: EncryptedObjectManifest, new_state: str
    ) -> EncryptedObjectManifest:
        allowed = {
            ObjectState.PENDING: ObjectState.UPLOADED,
            ObjectState.UPLOADED: ObjectState.VERIFIED,
        }
        if allowed.get(manifest.state) != new_state:
            raise RuntimeError(
                f"invalid encrypted object transition: {manifest.state}->{new_state}"
            )
        updated = replace(
            manifest,
            state=new_state,
            updated_at=_now(),
            authentication_tag="",
        )
        signed = _sign_manifest(updated, self._root_key)
        self._write_manifest(signed, self._root_key)
        return signed

    def _write_manifest(self, manifest: EncryptedObjectManifest, root_key: RootKey) -> None:
        manifest.validate()
        _verify_manifest(manifest, root_key)
        path = self._manifest_path(manifest.source_object_id)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise RuntimeError("encrypted object manifest path is unsafe")
        payload = (_canonical_json(manifest.as_dict()) + "\n").encode()
        temporary = self._manifests / f".{manifest.source_object_id}.{uuid.uuid4().hex}.tmp"
        _write_new_private_file(temporary, payload, mode=0o600)
        try:
            os.replace(temporary, path)
            path.chmod(0o600)
            _fsync_directory(self._manifests)
        finally:
            temporary.unlink(missing_ok=True)

    def _manifest_path(self, source_object_id: str) -> Path:
        _validate_identifier(source_object_id, _SOURCE_OBJECT_ID, "source object")
        return self._manifests / f"{source_object_id}.json"

    def _staging_path(self, storage_object_id: str) -> Path:
        _validate_identifier(storage_object_id, _STORAGE_OBJECT_ID, "storage object")
        return self._staging / f"{storage_object_id}.ciphertext"


def validate_authenticated_manifest(
    root_key: RootKey,
    manifest: EncryptedObjectManifest,
    *,
    backend_profile: str,
    max_plaintext_bytes: int,
    max_ciphertext_bytes: int,
    allowed_states: tuple[str, ...] = (ObjectState.VERIFIED,),
) -> None:
    """Bound and authenticate metadata without reading or decrypting an evidence object."""
    if (
        type(max_plaintext_bytes) is not int
        or type(max_ciphertext_bytes) is not int
        or max_plaintext_bytes <= 0
        or max_ciphertext_bytes <= 0
    ):
        raise ValueError("encrypted evidence read requires positive integer byte limits")
    fields = manifest.as_dict()
    character_count = 0
    for name, value in fields.items():
        if name in {"format_version", "plaintext_byte_length", "ciphertext_byte_length"}:
            if type(value) is not int or value.bit_length() > 64:
                raise ValueError("encrypted evidence manifest integer is invalid")
        elif isinstance(value, str):
            character_count += len(value)
            if character_count > MAX_MANIFEST_BYTES:
                raise ValueError("encrypted evidence manifest exceeds its size limit")
        elif name != "legacy_source_object_id" or value is not None:
            raise ValueError("encrypted evidence manifest contains an invalid value")
    # Bound expansion before base64 decoding or authentication serializes the manifest again.
    if len(_canonical_json(fields).encode()) > MAX_MANIFEST_BYTES:
        raise ValueError("encrypted evidence manifest exceeds its size limit")
    manifest.validate()
    _verify_manifest(manifest, root_key)
    if manifest.state not in allowed_states or manifest.backend_profile != backend_profile:
        raise ValueError("encrypted evidence must be verified for the selected backend")
    if (
        manifest.plaintext_byte_length > max_plaintext_bytes
        or manifest.ciphertext_byte_length > max_ciphertext_bytes
    ):
        raise ValueError("encrypted evidence exceeds its read budget")


def rewrap_authenticated_manifest(
    manifest: EncryptedObjectManifest,
    old_root_key: RootKey,
    new_root_key: RootKey,
    *,
    backend_profile: str,
    max_plaintext_bytes: int,
    max_ciphertext_bytes: int,
    allowed_states: tuple[str, ...] = (ObjectState.VERIFIED,),
) -> EncryptedObjectManifest:
    """Return rewrapped metadata without changing stored manifests or evidence bytes."""
    try:
        validate_authenticated_manifest(
            old_root_key,
            manifest,
            backend_profile=backend_profile,
            max_plaintext_bytes=max_plaintext_bytes,
            max_ciphertext_bytes=max_ciphertext_bytes,
            allowed_states=allowed_states,
        )
        object_aad = _object_aad_from_manifest(manifest)
        object_key = _read_encrypted_keyset(
            _decode_base64(manifest.wrapped_data_key, "wrapped data key"),
            old_root_key.primitive(),
            _keyset_aad(object_aad, manifest.root_key_id),
        )
        wrapped = _write_encrypted_keyset(
            object_key,
            new_root_key.primitive(),
            _keyset_aad(object_aad, new_root_key.key_id),
        )
        result = _sign_manifest(
            replace(
                manifest,
                root_key_id=new_root_key.key_id,
                wrapped_data_key=_encode_base64(wrapped),
                updated_at=_now(),
                authentication_tag="",
            ),
            new_root_key,
        )
        validate_authenticated_manifest(
            new_root_key,
            result,
            backend_profile=backend_profile,
            max_plaintext_bytes=max_plaintext_bytes,
            max_ciphertext_bytes=max_ciphertext_bytes,
            allowed_states=allowed_states,
        )
        return result
    except Exception as error:
        raise RuntimeError(f"encrypted manifest rewrap failed ({type(error).__name__})") from None


def read_verified_object(
    backend: ObjectBackend,
    root_key: RootKey,
    manifest: EncryptedObjectManifest,
    *,
    max_plaintext_bytes: int,
    max_ciphertext_bytes: int,
) -> bytes:
    """Read exact evidence without disk writes; byte limits are not a total memory ceiling."""
    if (
        type(max_plaintext_bytes) is not int
        or type(max_ciphertext_bytes) is not int
        or max_plaintext_bytes <= 0
        or max_ciphertext_bytes <= 0
    ):
        raise ValueError("encrypted evidence read requires positive integer byte limits")
    try:
        validate_authenticated_manifest(
            root_key,
            manifest,
            backend_profile=backend.profile,
            max_plaintext_bytes=max_plaintext_bytes,
            max_ciphertext_bytes=max_ciphertext_bytes,
        )
        before = backend.stat(manifest.storage_object_id)
        if before.byte_length != manifest.ciphertext_byte_length:
            raise ValueError("encrypted evidence length differs from its manifest")
        with backend.open(manifest.storage_object_id) as source:
            ciphertext = _read_bounded_stream(source, manifest.ciphertext_byte_length)
        if (
            backend.stat(manifest.storage_object_id) != before
            or len(ciphertext) != manifest.ciphertext_byte_length
            or hashlib.sha256(ciphertext).hexdigest() != manifest.ciphertext_sha256
        ):
            raise ValueError("encrypted evidence failed ciphertext verification")
        # Decrypt the same bytes that passed readback, not a second provider GET.
        object_aad = _object_aad_from_manifest(manifest)
        object_key = _read_encrypted_keyset(
            _decode_base64(manifest.wrapped_data_key, "wrapped data key"),
            root_key.primitive(),
            _keyset_aad(object_aad, manifest.root_key_id),
        )
        with (
            io.BytesIO(ciphertext) as verified_source,
            object_key.streaming_aead().new_decrypting_stream(
                verified_source, object_aad
            ) as reader,
        ):
            plaintext = _read_bounded_stream(reader, manifest.plaintext_byte_length)
        if (
            len(plaintext) != manifest.plaintext_byte_length
            or hashlib.sha256(plaintext).hexdigest() != manifest.plaintext_sha256
        ):
            raise ValueError("encrypted evidence failed plaintext verification")
        return plaintext
    except Exception as error:
        raise RuntimeError(f"encrypted evidence read failed ({type(error).__name__})") from None


def _read_bounded_stream(source: BinaryIO, expected_length: int) -> bytes:
    payload = bytearray()
    while True:
        chunk = source.read(min(CHUNK_BYTES, expected_length - len(payload) + 1))
        if not chunk:
            return bytes(payload)
        if len(payload) + len(chunk) > expected_length:
            raise ValueError("encrypted evidence stream exceeds its declared length")
        payload.extend(chunk)


def create_recovery_kit(
    root_key: RootKey, recovery_secret: RecoverySecret, output: Path
) -> dict[str, object]:
    payload = build_recovery_kit(root_key, recovery_secret)
    _write_new_private_file(output.expanduser(), payload, mode=0o600)
    return {
        "format_version": RECOVERY_KIT_FORMAT_VERSION,
        "root_key_id": root_key.key_id,
        "recovery_kit_sha256": hashlib.sha256(payload).hexdigest(),
        "recovery_kit_path": str(output.expanduser()),
    }


def build_recovery_kit(root_key: RootKey, recovery_secret: RecoveryKeyAccess) -> bytes:
    if isinstance(recovery_secret, OperationalKey):
        return recovery_secret.recovery_kit(root_key)
    created_at = _now()
    header: dict[str, object] = {
        "format_version": RECOVERY_KIT_FORMAT_VERSION,
        "root_key_id": root_key.key_id,
        "root_key_profile": ROOT_KEY_PROFILE,
        "created_at": created_at,
    }
    header_bytes = _canonical_json(header).encode()
    wrapped_root = root_key.write_encrypted_keyset(
        recovery_secret.primitive(),
        _RECOVERY_KEYSET_AAD_PREFIX + header_bytes,
    )
    canary = root_key.primitive().encrypt(
        _RECOVERY_CANARY, _RECOVERY_CANARY_AAD_PREFIX + header_bytes
    )
    kit = {
        **header,
        "wrapped_root_keyset": _encode_base64(wrapped_root),
        "canary_ciphertext": _encode_base64(canary),
        "canary_sha256": hashlib.sha256(_RECOVERY_CANARY).hexdigest(),
    }
    payload = (_canonical_json(kit) + "\n").encode()
    if len(payload) > MAX_RECOVERY_KIT_BYTES:
        raise RuntimeError("recovery kit exceeds its size limit")
    return payload


def restore_root_key(recovery_kit: Path, recovery_secret: RecoverySecret) -> RootKey:
    raw = _read_private_file(recovery_kit.expanduser(), MAX_RECOVERY_KIT_BYTES)
    return restore_root_key_from_bytes(raw, recovery_secret)


def restore_root_key_from_bytes(raw: bytes, recovery_secret: RecoveryKeyAccess) -> RootKey:
    if isinstance(recovery_secret, OperationalKey):
        return recovery_secret.restore_root_key(raw)
    if not raw or len(raw) > MAX_RECOVERY_KIT_BYTES:
        raise ValueError("recovery kit size is invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("recovery kit is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("recovery kit must be an object")
    fields = cast(dict[object, object], value)
    expected = {
        "format_version",
        "root_key_id",
        "root_key_profile",
        "created_at",
        "wrapped_root_keyset",
        "canary_ciphertext",
        "canary_sha256",
    }
    if set(fields) != expected:
        raise ValueError("recovery kit fields are invalid")
    format_version = _required_int(fields, "format_version")
    root_key_id = _required_str(fields, "root_key_id")
    root_key_profile = _required_str(fields, "root_key_profile")
    created_at = _required_str(fields, "created_at")
    if format_version != RECOVERY_KIT_FORMAT_VERSION or root_key_profile != ROOT_KEY_PROFILE:
        raise ValueError("unsupported recovery kit format")
    _validate_identifier(root_key_id, _ROOT_KEY_ID, "root key")
    _validate_timestamp(created_at)
    canary_sha256 = _required_str(fields, "canary_sha256")
    if canary_sha256 != hashlib.sha256(_RECOVERY_CANARY).hexdigest():
        raise ValueError("recovery canary digest is invalid")
    header = {
        "format_version": format_version,
        "root_key_id": root_key_id,
        "root_key_profile": root_key_profile,
        "created_at": created_at,
    }
    header_bytes = _canonical_json(header).encode()
    root_handle = _read_encrypted_keyset(
        _decode_base64(_required_str(fields, "wrapped_root_keyset"), "wrapped root keyset"),
        recovery_secret.primitive(),
        _RECOVERY_KEYSET_AAD_PREFIX + header_bytes,
    )
    root_key = RootKey(root_key_id, root_handle)
    try:
        canary = root_key.primitive().decrypt(
            _decode_base64(
                _required_str(fields, "canary_ciphertext"),
                "recovery canary ciphertext",
            ),
            _RECOVERY_CANARY_AAD_PREFIX + header_bytes,
        )
    except Exception as error:
        raise ValueError("recovery canary verification failed") from error
    if canary != _RECOVERY_CANARY:
        raise ValueError("recovery canary verification failed")
    return root_key


def canonical_object_aad(
    *,
    source_object_id: str,
    storage_object_id: str,
    media_type: str,
    plaintext_sha256: str,
    plaintext_byte_length: int,
    legacy_source_object_id: str | None,
) -> bytes:
    _validate_identifier(source_object_id, _SOURCE_OBJECT_ID, "source object")
    _validate_identifier(storage_object_id, _STORAGE_OBJECT_ID, "storage object")
    _validate_sha256(plaintext_sha256, "plaintext")
    if plaintext_byte_length < 0:
        raise ValueError("plaintext byte length must not be negative")
    if not media_type or len(media_type) > 255:
        raise ValueError("media type is invalid")
    if legacy_source_object_id is not None and not legacy_source_object_id:
        raise ValueError("legacy source object id must not be empty")
    header: dict[str, object] = {
        "encryption_profile": ENCRYPTION_PROFILE,
        "format_version": ENVELOPE_FORMAT_VERSION,
        "legacy_source_object_id": legacy_source_object_id,
        "media_type": media_type,
        "plaintext_byte_length": plaintext_byte_length,
        "plaintext_sha256": plaintext_sha256,
        "source_object_id": source_object_id,
        "storage_object_id": storage_object_id,
    }
    return _OBJECT_AAD_PREFIX + _canonical_json(header).encode()


def _object_aad_from_manifest(manifest: EncryptedObjectManifest) -> bytes:
    object_aad = canonical_object_aad(
        source_object_id=manifest.source_object_id,
        storage_object_id=manifest.storage_object_id,
        media_type=manifest.media_type,
        plaintext_sha256=manifest.plaintext_sha256,
        plaintext_byte_length=manifest.plaintext_byte_length,
        legacy_source_object_id=manifest.legacy_source_object_id,
    )
    if hashlib.sha256(object_aad).hexdigest() != manifest.object_aad_sha256:
        raise ValueError("encrypted object AAD does not match manifest")
    return object_aad


def _keyset_aad(object_aad: bytes, root_key_id: str) -> bytes:
    _validate_identifier(root_key_id, _ROOT_KEY_ID, "root key")
    return _KEYSET_AAD_PREFIX + root_key_id.encode() + b"\0" + object_aad


def _sign_manifest(manifest: EncryptedObjectManifest, root_key: RootKey) -> EncryptedObjectManifest:
    if manifest.root_key_id != root_key.key_id:
        raise ValueError("manifest root key id does not match signing key")
    unsigned = replace(manifest, authentication_tag="")
    unsigned.validate(require_authentication=False)
    aad = (
        _MANIFEST_AAD_PREFIX
        + _canonical_json(unsigned.as_dict(include_authentication=False)).encode()
    )
    tag = root_key.primitive().encrypt(b"", aad)
    return replace(unsigned, authentication_tag=_encode_base64(tag))


def _verify_manifest(manifest: EncryptedObjectManifest, root_key: RootKey) -> None:
    if manifest.root_key_id != root_key.key_id:
        raise ValueError("manifest root key id does not match verification key")
    unsigned = replace(manifest, authentication_tag="")
    aad = (
        _MANIFEST_AAD_PREFIX
        + _canonical_json(unsigned.as_dict(include_authentication=False)).encode()
    )
    try:
        plaintext = root_key.primitive().decrypt(
            _decode_base64(manifest.authentication_tag, "manifest authentication tag"), aad
        )
    except Exception as error:
        raise ValueError("encrypted object manifest authentication failed") from error
    if plaintext != b"":
        raise ValueError("encrypted object manifest authentication failed")


def _write_encrypted_keyset(
    keyset: Keyset, wrapping_aead: AeadPrimitive, associated_data: bytes
) -> bytes:
    return keyset.write_encrypted(wrapping_aead, associated_data)


def _read_encrypted_keyset(
    serialized: bytes, wrapping_aead: AeadPrimitive, associated_data: bytes
) -> Keyset:
    try:
        return Keyset.read_encrypted(serialized, wrapping_aead, associated_data)
    except Exception as error:
        raise ValueError("wrapped keyset verification failed") from error


class _BoundedCiphertextWriter:
    def __init__(self, destination: BinaryIO, max_bytes: int) -> None:
        self._destination = destination
        self._remaining = max_bytes

    @property
    def closed(self) -> bool:
        return self._destination.closed

    def writable(self) -> bool:
        return self._destination.writable()

    def write(self, data: bytes) -> int:
        if len(data) > self._remaining:
            raise ValueError("ciphertext staging byte budget exceeded")
        self._remaining -= len(data)
        written = self._destination.write(data)
        self._remaining += len(data) - written
        return written

    def close(self) -> None:
        self._destination.close()


def _encrypt_regular_file(
    source: Path,
    destination: Path,
    primitive: StreamingAeadPrimitive,
    associated_data: bytes,
    *,
    expected_identity: tuple[int, int, int, int],
    expected_sha256: str,
    max_ciphertext_bytes: int | None = None,
) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"encrypted staging output already exists: {destination}")
    source_handle = _open_regular_file(source)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    raw_destination: BinaryIO | None = None
    encrypted_destination: BinaryIO | None = None
    try:
        source_identity = _stat_identity(os.fstat(source_handle.fileno()))
        if source_identity != expected_identity:
            raise RuntimeError("source changed before encryption")
        descriptor = os.open(destination, flags, 0o600)
        raw_destination = os.fdopen(descriptor, "wb")
        descriptor = -1
        ciphertext_destination = raw_destination
        if max_ciphertext_bytes is not None:
            ciphertext_destination = cast(
                BinaryIO, _BoundedCiphertextWriter(raw_destination, max_ciphertext_bytes)
            )
        encrypted_destination = primitive.new_encrypting_stream(
            ciphertext_destination, associated_data
        )
        plaintext_digest = hashlib.sha256()
        with source_handle:
            while True:
                chunk = source_handle.read(CHUNK_BYTES)
                if not chunk:
                    break
                encrypted_destination.write(chunk)
                plaintext_digest.update(chunk)
            final_identity = _stat_identity(os.fstat(source_handle.fileno()))
        if final_identity != expected_identity or plaintext_digest.hexdigest() != expected_sha256:
            raise RuntimeError("source changed while encrypting")
        encrypted_destination.close()
        destination.chmod(0o600)
        _fsync_file(destination)
        _fsync_directory(destination.parent)
    except BaseException:
        try:
            if encrypted_destination is not None:
                # Finalization can fail again; still close the underlying file and source.
                with suppress(BaseException):
                    encrypted_destination.close()
            if raw_destination is not None:
                raw_destination.close()
            elif descriptor >= 0:
                os.close(descriptor)
        finally:
            try:
                source_handle.close()
            finally:
                destination.unlink(missing_ok=True)
        raise


def _hash_regular_file(
    path: Path, *, expected_byte_length: int | None = None
) -> tuple[int, str, tuple[int, int, int, int]]:
    before = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"object source must be a regular file: {path}")
    if expected_byte_length is not None and before.st_size != expected_byte_length:
        raise RuntimeError("source does not match expected plaintext digest and length")
    digest = hashlib.sha256()
    size = 0
    with _open_regular_file(path) as handle:
        while True:
            requested = (
                CHUNK_BYTES
                if expected_byte_length is None
                else min(CHUNK_BYTES, expected_byte_length - size + 1)
            )
            chunk = handle.read(requested)
            if not chunk:
                break
            if expected_byte_length is not None and (
                len(chunk) > requested or size + len(chunk) > expected_byte_length
            ):
                raise RuntimeError("source exceeds expected plaintext byte length")
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(handle.fileno())
    before_identity = _stat_identity(before)
    if before_identity != _stat_identity(after) or size != before.st_size:
        raise RuntimeError(f"file changed while hashing: {path}")
    return size, digest.hexdigest(), before_identity


def _verify_regular_file(path: Path, *, expected_length: int, expected_sha256: str) -> None:
    try:
        length, digest, _ = _hash_regular_file(path, expected_byte_length=expected_length)
    except RuntimeError:
        raise RuntimeError("encrypted staging object failed verification") from None
    if length != expected_length or digest != expected_sha256:
        raise RuntimeError("encrypted staging object failed verification")


def _open_regular_file(path: Path) -> BinaryIO:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"file must be a regular file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.fdopen(os.open(path, flags), "rb")


def _copy_stream(source: BinaryIO, destination: BinaryIO) -> None:
    while True:
        chunk = source.read(CHUNK_BYTES)
        if not chunk:
            return
        destination.write(chunk)


def _write_new_private_file(path: Path, payload: bytes, *, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"private output already exists: {path}")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError(f"private output parent is invalid: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(mode)
        _fsync_directory(path.parent)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _read_private_file(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"private input must be a regular file: {path}")
    details = path.stat()
    if details.st_size > limit:
        raise ValueError(f"private input exceeds size limit: {path}")
    with _open_regular_file(path) as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"private input exceeds size limit: {path}")
    return raw


def _require_existing_private_directory(path: Path) -> None:
    descriptor = open_directory_no_symlinks(path, "encrypted backend directory")
    try:
        value = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        raise ValueError("encrypted backend requires existing owner-only directories")


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"private directory must not be a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"private path must be a directory: {path}")
    path.chmod(0o700)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def _required_str(value: dict[object, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError(f"{key} must be a string")
    return item


def _optional_str(value: dict[object, object], key: str) -> str | None:
    item = value.get(key)
    if item is not None and not isinstance(item, str):
        raise ValueError(f"{key} must be a string or null")
    return item


def _required_int(value: dict[object, object], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"{key} must be an integer")
    return item


def _validate_identifier(value: str, pattern: re.Pattern[str], label: str) -> None:
    if pattern.fullmatch(value) is None:
        raise ValueError(f"{label} id is invalid")


def _validate_sha256(value: str, label: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} SHA-256 is invalid")


def _validate_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: str, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"{label} is not valid base64") from error
    if not decoded:
        raise ValueError(f"{label} must not be empty")
    return decoded


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _now() -> str:
    return datetime.now(UTC).isoformat()
