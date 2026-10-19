from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Protocol


@dataclass(frozen=True)
class BackendObjectStat:
    byte_length: int
    etag: str | None = None
    version_id: str | None = None


@dataclass(frozen=True)
class IncompleteCleanupReport:
    removed_entries: tuple[str, ...]
    removed_count: int
    scanned_count: int
    scan_truncated: bool

    def __post_init__(self) -> None:
        if self.removed_count != len(self.removed_entries):
            raise ValueError("cleanup removal count does not match entries")
        if self.removed_count < 0 or self.scanned_count < self.removed_count:
            raise ValueError("cleanup counts are invalid")


class ObjectBackend(Protocol):
    @property
    def profile(self) -> str: ...

    def exists(self, storage_object_id: str) -> bool: ...

    def put_file(self, storage_object_id: str, source: Path) -> None: ...

    def open(self, storage_object_id: str) -> BinaryIO: ...

    def stat(self, storage_object_id: str) -> BackendObjectStat: ...

    def cleanup_incomplete(self, *, older_than_epoch: float) -> IncompleteCleanupReport: ...


class IdentifiedObjectBackend(ObjectBackend, Protocol):
    @property
    def identity_sha256(self) -> str: ...


MAX_OBJECT_PURGE_ENTRIES = 10_000


@dataclass(frozen=True)
class ObjectVersion:
    version_id: str
    byte_length: int | None
    delete_marker: bool = False

    def __post_init__(self) -> None:
        _validate_purge_identifier(self.version_id)
        if type(self.delete_marker) is not bool:
            raise ValueError("object version delete-marker flag is invalid")
        if self.delete_marker:
            if self.byte_length is not None:
                raise ValueError("delete markers cannot declare object bytes")
        elif type(self.byte_length) is not int or not 0 <= self.byte_length < 2**63:
            raise ValueError("object version byte length is invalid")


@dataclass(frozen=True)
class ObjectPurgeInventory:
    backend_identity_sha256: str
    storage_object_id: str
    versions: tuple[ObjectVersion, ...] = ()
    incomplete_upload_ids: tuple[str, ...] = ()
    namespace_identity_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.backend_identity_sha256) is not str
            or type(self.storage_object_id) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.backend_identity_sha256) is None
            or re.fullmatch(r"storage_[0-9a-f]{32}", self.storage_object_id) is None
            or (
                self.namespace_identity_sha256 is not None
                and (
                    type(self.namespace_identity_sha256) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", self.namespace_identity_sha256) is None
                )
            )
        ):
            raise ValueError("object purge inventory scope is invalid")
        if type(self.versions) is not tuple or type(self.incomplete_upload_ids) is not tuple:
            raise ValueError("object purge inventory must use immutable entries")
        if len(self.versions) + len(self.incomplete_upload_ids) > MAX_OBJECT_PURGE_ENTRIES:
            raise ValueError("object purge inventory exceeds its entry limit")
        if any(type(version) is not ObjectVersion for version in self.versions):
            raise ValueError("object purge inventory has an invalid version")
        version_ids = [version.version_id for version in self.versions]
        for upload_id in self.incomplete_upload_ids:
            _validate_purge_identifier(upload_id)
        if len(set(version_ids)) != len(version_ids) or len(set(self.incomplete_upload_ids)) != len(
            self.incomplete_upload_ids
        ):
            raise ValueError("object purge inventory contains duplicate identities")
        object.__setattr__(
            self, "versions", tuple(sorted(self.versions, key=lambda v: v.version_id))
        )
        object.__setattr__(self, "incomplete_upload_ids", tuple(sorted(self.incomplete_upload_ids)))

    def require_subset_of(self, expected: ObjectPurgeInventory) -> None:
        if (
            self.backend_identity_sha256 != expected.backend_identity_sha256
            or self.storage_object_id != expected.storage_object_id
            or self.namespace_identity_sha256 != expected.namespace_identity_sha256
            or not set(self.versions) <= set(expected.versions)
            or not set(self.incomplete_upload_ids) <= set(expected.incomplete_upload_ids)
        ):
            raise RuntimeError("object purge inventory changed beyond the retained plan")


class PurgeableObjectBackend(IdentifiedObjectBackend, Protocol):
    def inspect_object_purge(self, storage_object_id: str) -> ObjectPurgeInventory: ...

    def purge_object(self, storage_object_id: str, expected: ObjectPurgeInventory) -> None: ...


def _validate_purge_identifier(value: object) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1_024
        or len(value.encode()) > 1_024
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("object purge identifier is invalid")


class SettingState(StrEnum):
    KNOWN = "known"
    NOT_CONFIGURED = "not_configured"
    PERMISSION_DENIED = "permission_denied"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ProviderSetting:
    state: SettingState
    summary: str | None = None


@dataclass(frozen=True)
class ProviderSettingsReport:
    profile: str
    bucket_access: ProviderSetting
    versioning: ProviderSetting
    lifecycle: ProviderSetting
    replication: ProviderSetting
    object_lock: ProviderSetting
    default_retention: ProviderSetting
    deletion_consequences: tuple[str, ...]


class ProviderSettingsInspector(Protocol):
    @property
    def profile(self) -> str: ...

    def inspect(self) -> ProviderSettingsReport: ...
