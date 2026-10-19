from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import cast

from cross_assistant_memory.encrypted_objects import (
    CHUNK_BYTES,
    MAX_MANIFEST_BYTES,
    EncryptedObjectManifest,
    ObjectState,
    RootKey,
    canonical_object_aad,
    validate_authenticated_manifest,
)
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.evidence_publication import (
    PUBLICATION_DIRECTORY,
    same_encrypted_object,
)
from cross_assistant_memory.object_store import (
    MAX_OBJECT_PURGE_ENTRIES,
    ObjectPurgeInventory,
    ObjectVersion,
    PurgeableObjectBackend,
)
from cross_assistant_memory.safe_files import open_directory_no_symlinks

MAX_PUBLICATION_SCAN_ENTRIES = 64
MAX_PUBLICATION_ARTIFACTS = 3
_SHA256 = r"[0-9a-f]{64}"
_SOURCE_ID = r"source_[0-9a-f]{32}"
_TEMPORARY = re.compile(rf"\.({_SOURCE_ID})\.[0-9a-f]{{32}}\.tmp")


@dataclass(frozen=True)
class PreparationCleanup:
    """Transient scope for the reserved local slot, never authority to erase remote objects."""

    namespace_identities: tuple[str, str | None, str | None, str | None]
    artifacts: tuple[PublicationArtifact, ...]
    manifest_storage_object_id: str | None = None

    @property
    def source_object_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    item.name[1:].split(".")[0] if item.name.startswith(".") else item.name[:-5]
                    for item in self.artifacts
                    if item.directory == "manifests"
                }
            )
        )

    @property
    def storage_object_ids(self) -> tuple[str, ...]:
        identities = {
            item.name.removesuffix(".ciphertext")
            for item in self.artifacts
            if item.directory == "staging"
        }
        if self.manifest_storage_object_id is not None:
            identities.add(self.manifest_storage_object_id)
        return tuple(sorted(identities))

    @property
    def scope_sha256(self) -> str:
        return _digest([self.namespace_identities, [item.as_dict() for item in self.artifacts]])

    def discard(self, data_root: Path, *, max_ciphertext_bytes: int) -> None:
        """Require no registered/pending work under the coordinator's exclusive writer first."""
        with _open_stage(data_root) as stage:
            if stage.identities != self.namespace_identities:
                raise RuntimeError("publication preparation namespace changed")
            current = _preparation_artifacts(stage, max_ciphertext_bytes)
            if not set(current) <= set(self.artifacts):
                raise RuntimeError("publication preparation changed before cleanup")
            _unlink_artifacts(stage, current)
            if _preparation_artifacts(stage, max_ciphertext_bytes):
                raise RuntimeError("publication preparation cleanup is incomplete")


def inspect_preparation_cleanup(
    data_root: Path, reader: EncryptedEvidenceReader
) -> PreparationCleanup:
    """Inspect bounded local preparation bytes without provider access or plaintext recovery."""
    with _open_stage(data_root) as stage:
        artifacts = _preparation_artifacts(stage, reader.max_ciphertext_bytes)
        storage_object_id = None
        manifests = [
            item
            for item in artifacts
            if item.directory == "manifests" and not item.name.startswith(".")
        ]
        if len(manifests) > 1:
            raise RuntimeError("publication preparation has ambiguous manifests")
        known_manifest: EncryptedObjectManifest | None = None
        for item in artifacts:
            if item.directory != "manifests":
                continue
            current, raw = _read_artifact(
                stage.descriptors["manifests"], "manifests", item.name, MAX_MANIFEST_BYTES
            )
            if current != item or raw is None:
                raise RuntimeError("publication preparation changed during authentication")
            try:
                temporary = _TEMPORARY.fullmatch(item.name)
                try:
                    value = json.loads(raw, object_pairs_hook=_unique_object)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    if temporary is not None:
                        continue
                    raise
                manifest = EncryptedObjectManifest.from_dict(value)
                validate_authenticated_manifest(
                    reader.root_key,
                    manifest,
                    backend_profile=reader.backend.profile,
                    max_plaintext_bytes=reader.max_plaintext_bytes,
                    max_ciphertext_bytes=reader.max_ciphertext_bytes,
                    allowed_states=(ObjectState.PENDING,),
                )
                if (
                    (temporary[1] if temporary else item.name[:-5]) != manifest.source_object_id
                    or manifest.legacy_source_object_id != f"sha256:{manifest.plaintext_sha256}"
                ):
                    raise ValueError("preparation source identity")
                if known_manifest is not None and not same_encrypted_object(
                    known_manifest, manifest
                ):
                    raise ValueError("preparation manifests describe different objects")
                known_manifest = manifest
                storage_object_id = manifest.storage_object_id
                for artifact in artifacts:
                    if artifact.directory == "staging" and (
                        artifact.name != f"{manifest.storage_object_id}.ciphertext"
                        or (artifact.byte_length, artifact.sha256)
                        != (manifest.ciphertext_byte_length, manifest.ciphertext_sha256)
                    ):
                        raise ValueError("preparation ciphertext identity")
            except Exception:
                raise ValueError(
                    "unregistered preparation is not authenticated pending state"
                ) from None
        stage.require_current()
        if _preparation_artifacts(stage, reader.max_ciphertext_bytes) != artifacts:
            raise RuntimeError("publication preparation changed during inspection")
        return PreparationCleanup(stage.identities, artifacts, storage_object_id)


@dataclass(frozen=True)
class PublicationArtifact:
    directory: str
    name: str
    device: int
    inode: int
    byte_length: int
    mtime_ns: int
    ctime_ns: int
    sha256: str

    def __post_init__(self) -> None:
        if type(self.directory) is not str:
            raise ValueError("publication artifact directory is invalid")
        if self.directory == "manifests":
            valid = _matches(self.name, rf"{_SOURCE_ID}\.json") or (
                type(self.name) is str and _TEMPORARY.fullmatch(self.name) is not None
            )
        else:
            valid = self.directory == "staging" and _matches(
                self.name, r"storage_[0-9a-f]{32}\.ciphertext"
            )
        if not valid or not _matches(self.sha256, _SHA256):
            raise ValueError("publication artifact scope is invalid")
        for value in (self.device, self.inode, self.byte_length, self.mtime_ns, self.ctime_ns):
            _unsigned(value)
        if self.directory == "manifests" and self.byte_length > MAX_MANIFEST_BYTES:
            raise ValueError("publication manifest exceeds its byte limit")

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: object) -> PublicationArtifact:
        item = _fields(value, {field.name for field in fields(cls)})
        return cls(
            _string(item["directory"]),
            _string(item["name"]),
            _unsigned(item["device"]),
            _unsigned(item["inode"]),
            _unsigned(item["byte_length"]),
            _unsigned(item["mtime_ns"]),
            _unsigned(item["ctime_ns"]),
            _string(item["sha256"]),
        )


@dataclass(frozen=True)
class EncryptedDeletionTarget:
    object_id: str
    backend_profile: str
    manifest_sha256: str
    inventory: ObjectPurgeInventory
    publication_source_object_id: str
    data_root_identity_sha256: str
    publication_identity_sha256: str | None
    manifests_identity_sha256: str | None
    staging_identity_sha256: str | None
    publication_artifacts: tuple[PublicationArtifact, ...]

    def __post_init__(self) -> None:
        if (
            not _matches(self.object_id, rf"sha256:{_SHA256}")
            or not _matches(self.publication_source_object_id, _SOURCE_ID)
            or not _matches(self.manifest_sha256, _SHA256)
            or type(self.backend_profile) is not str
            or not 1 <= len(self.backend_profile.encode()) <= 128
            or any(
                ord(character) < 32 or ord(character) == 127 for character in self.backend_profile
            )
            or type(self.inventory) is not ObjectPurgeInventory
            or not _matches(self.data_root_identity_sha256, _SHA256)
        ):
            raise ValueError("encrypted deletion target scope is invalid")
        for identity in (
            self.publication_identity_sha256,
            self.manifests_identity_sha256,
            self.staging_identity_sha256,
        ):
            if identity is not None and not _matches(identity, _SHA256):
                raise ValueError("publication namespace identity is invalid")
        if self.publication_identity_sha256 is None and (
            self.manifests_identity_sha256 is not None or self.staging_identity_sha256 is not None
        ):
            raise ValueError("publication namespace hierarchy is invalid")
        if (
            type(self.publication_artifacts) is not tuple
            or len(self.publication_artifacts) > MAX_PUBLICATION_ARTIFACTS
            or any(type(item) is not PublicationArtifact for item in self.publication_artifacts)
        ):
            raise ValueError("publication artifact inventory is invalid")
        names: set[tuple[str, str]] = set()
        for item in self.publication_artifacts:
            if (item.directory, item.name) in names:
                raise ValueError("publication artifact inventory contains duplicate names")
            names.add((item.directory, item.name))
            if item.directory == "manifests":
                temporary = _TEMPORARY.fullmatch(item.name)
                if self.manifests_identity_sha256 is None or not (
                    item.name == f"{self.publication_source_object_id}.json"
                    or (temporary and temporary[1] == self.publication_source_object_id)
                ):
                    raise ValueError("publication manifest does not match the target")
            elif self.staging_identity_sha256 is None or item.name != (
                f"{self.inventory.storage_object_id}.ciphertext"
            ):
                raise ValueError("publication ciphertext does not match the target")
        if sum(item.directory == "manifests" for item in self.publication_artifacts) > 2:
            raise ValueError("publication manifest inventory exceeds its entry limit")
        object.__setattr__(
            self,
            "publication_artifacts",
            tuple(sorted(self.publication_artifacts, key=lambda item: (item.directory, item.name))),
        )

    def as_dict(self) -> dict[str, object]:
        value = cast(dict[str, object], asdict(self))
        value["inventory"] = {
            "backend_identity_sha256": self.inventory.backend_identity_sha256,
            "storage_object_id": self.inventory.storage_object_id,
            "namespace_identity_sha256": self.inventory.namespace_identity_sha256,
            "versions": [asdict(version) for version in self.inventory.versions],
            "incomplete_upload_ids": list(self.inventory.incomplete_upload_ids),
        }
        value["publication_artifacts"] = [item.as_dict() for item in self.publication_artifacts]
        return value

    @classmethod
    def from_dict(cls, value: object) -> EncryptedDeletionTarget:
        """Callers must reject duplicate JSON keys or require exact canonical re-encoding."""
        item = _fields(value, {field.name for field in fields(cls)})
        inventory = _fields(
            item["inventory"], {field.name for field in fields(ObjectPurgeInventory)}
        )
        versions: list[ObjectVersion] = []
        raw_versions = _array(inventory["versions"], MAX_OBJECT_PURGE_ENTRIES)
        uploads = _array(
            inventory["incomplete_upload_ids"], MAX_OBJECT_PURGE_ENTRIES - len(raw_versions)
        )
        for raw in raw_versions:
            version = _fields(raw, {field.name for field in fields(ObjectVersion)})
            marker = version["delete_marker"]
            if type(marker) is not bool:
                raise ValueError("object version delete-marker flag is invalid")
            length = version["byte_length"]
            versions.append(
                ObjectVersion(
                    _string(version["version_id"]),
                    None if length is None else _unsigned(length),
                    marker,
                )
            )
        return cls(
            object_id=_string(item["object_id"]),
            backend_profile=_string(item["backend_profile"]),
            manifest_sha256=_string(item["manifest_sha256"]),
            inventory=ObjectPurgeInventory(
                _string(inventory["backend_identity_sha256"]),
                _string(inventory["storage_object_id"]),
                tuple(versions),
                tuple(_string(upload) for upload in uploads),
                _optional_string(inventory["namespace_identity_sha256"]),
            ),
            publication_source_object_id=_string(item["publication_source_object_id"]),
            data_root_identity_sha256=_string(item["data_root_identity_sha256"]),
            publication_identity_sha256=_optional_string(item["publication_identity_sha256"]),
            manifests_identity_sha256=_optional_string(item["manifests_identity_sha256"]),
            staging_identity_sha256=_optional_string(item["staging_identity_sha256"]),
            publication_artifacts=tuple(
                PublicationArtifact.from_dict(artifact)
                for artifact in _array(item["publication_artifacts"], MAX_PUBLICATION_ARTIFACTS)
            ),
        )


@dataclass(frozen=True)
class EncryptedEvidencePurger:
    backend: PurgeableObjectBackend
    root_key: RootKey
    max_plaintext_bytes: int
    max_ciphertext_bytes: int

    def __post_init__(self) -> None:
        for value in (self.max_plaintext_bytes, self.max_ciphertext_bytes):
            if not 0 < _unsigned(value) < 2**63:
                raise ValueError("encrypted evidence purge requires positive integer byte limits")

    def plan(
        self,
        *,
        data_root: Path,
        object_id: str,
        byte_length: int,
        backend_identity_sha256: str,
        manifest: EncryptedObjectManifest,
    ) -> EncryptedDeletionTarget:
        digest = self._mapping(object_id, byte_length, backend_identity_sha256, manifest)
        with _open_stage(data_root) as stage:
            artifacts = self._artifacts(
                stage, manifest.source_object_id, manifest.storage_object_id
            )
            self._authenticate_artifacts(stage, artifacts, manifest)
            stage.require_current()
            inventory = self.backend.inspect_object_purge(manifest.storage_object_id)
            _require_inventory_scope(inventory, backend_identity_sha256, manifest.storage_object_id)
            target = EncryptedDeletionTarget(
                object_id,
                manifest.backend_profile,
                digest,
                inventory,
                manifest.source_object_id,
                stage.identities[0],
                *stage.identities[1:],
                artifacts,
            )
            self._require_backend(target)
            self._require_stage(target, stage, exact=True)
            return target

    def validate(
        self,
        target: EncryptedDeletionTarget,
        *,
        data_root: Path,
        object_id: str,
        byte_length: int,
        backend_identity_sha256: str,
        manifest: EncryptedObjectManifest,
    ) -> None:
        digest = self._mapping(object_id, byte_length, backend_identity_sha256, manifest)
        if (
            target.object_id != object_id
            or target.manifest_sha256 != digest
            or target.publication_source_object_id != manifest.source_object_id
            or target.inventory.storage_object_id != manifest.storage_object_id
        ):
            raise RuntimeError("encrypted deletion mapping changed beyond the retained plan")
        self._require_backend(target)
        with _open_stage(data_root) as stage:
            self._require_stage(target, stage)
            current = self.backend.inspect_object_purge(target.inventory.storage_object_id)
            current.require_subset_of(target.inventory)
            self._require_backend(target)
            self._require_stage(target, stage)

    def purge(self, target: EncryptedDeletionTarget, *, data_root: Path) -> None:
        """Use only a durably retained target while the coordinator holds its exclusive writer."""
        self._require_backend(target)
        with _open_stage(data_root) as stage:
            self._require_stage(target, stage)
            self.backend.purge_object(target.inventory.storage_object_id, target.inventory)
            self._require_backend(target)
            remaining = self._require_stage(target, stage)
            _unlink_artifacts(stage, remaining)
            if self._require_stage(target, stage):
                raise RuntimeError("encrypted evidence publication purge is incomplete")

    def _mapping(
        self,
        object_id: str,
        byte_length: int,
        backend_identity_sha256: str,
        manifest: EncryptedObjectManifest,
    ) -> str:
        if (
            not _matches(object_id, rf"sha256:{_SHA256}")
            or type(byte_length) is not int
            or not 0 <= byte_length <= self.max_plaintext_bytes
            or not _matches(backend_identity_sha256, _SHA256)
            or backend_identity_sha256 != self.backend.identity_sha256
        ):
            raise ValueError("encrypted deletion ledger or backend scope is invalid")
        self._authenticate(manifest, (ObjectState.PENDING, ObjectState.VERIFIED))
        if (
            manifest.legacy_source_object_id != object_id
            or object_id != f"sha256:{manifest.plaintext_sha256}"
            or byte_length != manifest.plaintext_byte_length
        ):
            raise ValueError("encrypted deletion manifest does not match the ledger")
        return _digest(manifest.as_dict())

    def _authenticate(self, manifest: EncryptedObjectManifest, states: tuple[str, ...]) -> None:
        validate_authenticated_manifest(
            self.root_key,
            manifest,
            backend_profile=self.backend.profile,
            max_plaintext_bytes=self.max_plaintext_bytes,
            max_ciphertext_bytes=self.max_ciphertext_bytes,
            allowed_states=states,
        )
        aad = canonical_object_aad(
            source_object_id=manifest.source_object_id,
            storage_object_id=manifest.storage_object_id,
            media_type=manifest.media_type,
            plaintext_sha256=manifest.plaintext_sha256,
            plaintext_byte_length=manifest.plaintext_byte_length,
            legacy_source_object_id=manifest.legacy_source_object_id,
        )
        if hashlib.sha256(aad).hexdigest() != manifest.object_aad_sha256:
            raise ValueError("encrypted deletion manifest AAD is invalid")

    def _require_backend(self, target: EncryptedDeletionTarget) -> None:
        if (
            target.backend_profile != self.backend.profile
            or target.inventory.backend_identity_sha256 != self.backend.identity_sha256
        ):
            raise RuntimeError("encrypted deletion backend does not match the retained plan")
        if any(
            item.directory == "staging" and item.byte_length > self.max_ciphertext_bytes
            for item in target.publication_artifacts
        ):
            raise ValueError("retained publication ciphertext exceeds the purge byte limit")

    def _artifacts(
        self, stage: _Stage, source_object_id: str, storage_object_id: str
    ) -> tuple[PublicationArtifact, ...]:
        names: list[tuple[str, str]] = []
        if "manifests" in stage.descriptors:
            with os.scandir(stage.descriptors["manifests"]) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > MAX_PUBLICATION_SCAN_ENTRIES:
                        raise RuntimeError("publication manifest scan exceeds its entry limit")
                    temporary = _TEMPORARY.fullmatch(entry.name)
                    if entry.name == f"{source_object_id}.json" or (
                        temporary and temporary[1] == source_object_id
                    ):
                        names.append(("manifests", entry.name))
            if len(names) > 2:
                raise RuntimeError("publication manifest inventory exceeds its entry limit")
        if "staging" in stage.descriptors:
            name = f"{storage_object_id}.ciphertext"
            if _stat_at(stage.descriptors["staging"], name) is not None:
                names.append(("staging", name))
        return tuple(
            _read_artifact(
                stage.descriptors[directory],
                directory,
                name,
                MAX_MANIFEST_BYTES if directory == "manifests" else self.max_ciphertext_bytes,
            )[0]
            for directory, name in sorted(names)
        )

    def _authenticate_artifacts(
        self,
        stage: _Stage,
        artifacts: tuple[PublicationArtifact, ...],
        manifest: EncryptedObjectManifest,
    ) -> None:
        for item in artifacts:
            if item.directory == "staging":
                if (item.byte_length, item.sha256) != (
                    manifest.ciphertext_byte_length,
                    manifest.ciphertext_sha256,
                ):
                    raise ValueError("publication ciphertext does not match the mapped manifest")
                continue
            # A killed manifest write can leave arbitrary partial JSON. The authenticated
            # mapping owns this exact source prefix; retain the fragment as opaque bytes.
            if _TEMPORARY.fullmatch(item.name):
                continue
            current, raw = _read_artifact(
                stage.descriptors[item.directory], item.directory, item.name, MAX_MANIFEST_BYTES
            )
            if current != item or raw is None:
                raise RuntimeError("publication manifest changed during authentication")
            try:
                saved = EncryptedObjectManifest.from_dict(
                    json.loads(raw, object_pairs_hook=_unique_object)
                )
                self._authenticate(
                    saved, (ObjectState.PENDING, ObjectState.UPLOADED, ObjectState.VERIFIED)
                )
                if not same_encrypted_object(saved, manifest):
                    raise ValueError("publication manifest identity")
            except Exception:
                raise ValueError(
                    "publication manifest is not authenticated for this target"
                ) from None

    def _require_stage(
        self, target: EncryptedDeletionTarget, stage: _Stage, *, exact: bool = False
    ) -> tuple[PublicationArtifact, ...]:
        expected = (
            target.data_root_identity_sha256,
            target.publication_identity_sha256,
            target.manifests_identity_sha256,
            target.staging_identity_sha256,
        )
        if stage.identities != expected:
            raise RuntimeError("publication namespace changed beyond the retained plan")
        stage.require_current()
        current = self._artifacts(
            stage, target.publication_source_object_id, target.inventory.storage_object_id
        )
        if not set(current) <= set(target.publication_artifacts) or (
            exact and current != target.publication_artifacts
        ):
            raise RuntimeError("publication artifacts changed beyond the retained plan")
        stage.require_current()
        return current


@dataclass(frozen=True)
class _Stage:
    data_root: Path
    descriptors: dict[str, int]
    identities: tuple[str, str | None, str | None, str | None]

    def require_current(self) -> None:
        with _open_stage(self.data_root) as current:
            if self.identities != current.identities:
                raise RuntimeError("publication namespace changed beyond the retained plan")


def _preparation_artifacts(stage: _Stage, ciphertext_limit: int) -> tuple[PublicationArtifact, ...]:
    if type(ciphertext_limit) is not int or not 0 < ciphertext_limit < 2**63:
        raise ValueError("preparation cleanup requires a positive ciphertext byte limit")
    if "publication" in stage.descriptors:
        with os.scandir(stage.descriptors["publication"]) as entries:
            for count, entry in enumerate(entries, 1):
                if count > 2 or entry.name not in {"manifests", "staging"}:
                    raise RuntimeError("unexpected publication preparation entry")
    result: list[PublicationArtifact] = []
    for directory, count_limit, byte_limit in (
        ("manifests", 2, MAX_MANIFEST_BYTES),
        ("staging", 1, ciphertext_limit),
    ):
        if directory not in stage.descriptors:
            continue
        with os.scandir(stage.descriptors[directory]) as entries:
            for count, entry in enumerate(entries, 1):
                valid = (
                    (
                        _matches(entry.name, rf"{_SOURCE_ID}\.json")
                        or _TEMPORARY.fullmatch(entry.name) is not None
                    )
                    if directory == "manifests"
                    else _matches(entry.name, r"storage_[0-9a-f]{32}\.ciphertext")
                )
                if count > count_limit or not valid:
                    raise RuntimeError("unrecognized or excessive publication preparation files")
                result.append(
                    _read_artifact(stage.descriptors[directory], directory, entry.name, byte_limit)[
                        0
                    ]
                )
    stage.require_current()
    return tuple(sorted(result, key=lambda item: (item.directory, item.name)))


def _unlink_artifacts(stage: _Stage, artifacts: tuple[PublicationArtifact, ...]) -> None:
    for item in sorted(artifacts, key=lambda item: (item.directory != "staging", item.name)):
        stage.require_current()
        descriptor = stage.descriptors[item.directory]
        current, _ = _read_artifact(descriptor, item.directory, item.name, item.byte_length)
        if current != item:
            raise RuntimeError("publication artifact changed before unlink")
        stage.require_current()
        details = os.stat(item.name, dir_fd=descriptor, follow_symlinks=False)
        if (
            details.st_dev,
            details.st_ino,
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
        ) != (item.device, item.inode, item.byte_length, item.mtime_ns, item.ctime_ns):
            raise RuntimeError("publication artifact changed before unlink")
        os.unlink(item.name, dir_fd=descriptor)
        os.fsync(descriptor)
    # Preserve namespace inodes and flush observed absence on interrupted-cleanup retries.
    for descriptor in stage.descriptors.values():
        os.fsync(descriptor)


@contextmanager
def _open_stage(data_root: Path) -> Generator[_Stage]:
    data_root = Path(os.path.abspath(data_root.expanduser()))
    descriptors: dict[str, int] = {}
    identities: list[str | None] = []
    try:
        for role, parent, name, path in (
            ("data_root", None, "", data_root),
            ("publication", "data_root", PUBLICATION_DIRECTORY, data_root / PUBLICATION_DIRECTORY),
            (
                "manifests",
                "publication",
                "manifests",
                data_root / PUBLICATION_DIRECTORY / "manifests",
            ),
            ("staging", "publication", "staging", data_root / PUBLICATION_DIRECTORY / "staging"),
        ):
            if parent is not None and (
                parent not in descriptors or _stat_at(descriptors[parent], name) is None
            ):
                identities.append(None)
                continue
            descriptor = open_directory_no_symlinks(path, "publication purge namespace")
            descriptors[role] = descriptor
            details = os.fstat(descriptor)
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
                raise ValueError("publication purge namespace must be private and owned")
            if parent is not None:
                attached = os.stat(name, dir_fd=descriptors[parent], follow_symlinks=False)
                if (attached.st_dev, attached.st_ino) != (details.st_dev, details.st_ino):
                    raise RuntimeError("publication purge namespace changed while opening")
            identities.append(_digest([str(path), details.st_dev, details.st_ino]))
        yield _Stage(
            data_root,
            descriptors,
            (cast(str, identities[0]), identities[1], identities[2], identities[3]),
        )
    finally:
        for descriptor in reversed(descriptors.values()):
            os.close(descriptor)


def _read_artifact(
    parent: int, directory: str, name: str, limit: int
) -> tuple[PublicationArtifact, bytes | None]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    descriptor = os.open(name, flags, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 <= before.st_size <= limit
        ):
            raise ValueError("publication artifact is unsafe or exceeds its byte limit")
        digest = hashlib.sha256()
        raw = bytearray() if directory == "manifests" else None
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise RuntimeError("publication artifact changed while reading")
            digest.update(chunk)
            remaining -= len(chunk)
            if raw is not None:
                raw.extend(chunk)
        if (
            os.read(descriptor, 1)
            or _stamp(before) != _stamp(os.fstat(descriptor))
            or _stamp(before) != _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
        ):
            raise RuntimeError("publication artifact changed while reading")
        return (
            PublicationArtifact(
                directory,
                name,
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
                digest.hexdigest(),
            ),
            None if raw is None else bytes(raw),
        )
    finally:
        os.close(descriptor)


def _stamp(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stat_at(parent: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _require_inventory_scope(
    inventory: ObjectPurgeInventory, backend_identity_sha256: str, storage_object_id: str
) -> None:
    if (
        type(inventory) is not ObjectPurgeInventory
        or inventory.backend_identity_sha256 != backend_identity_sha256
        or inventory.storage_object_id != storage_object_id
    ):
        raise RuntimeError("provider returned a different encrypted deletion scope")


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def _matches(value: object, pattern: str) -> bool:
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _unsigned(value: object) -> int:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("encrypted deletion inventory integer is invalid")
    return value


def _string(value: object) -> str:
    if type(value) is not str:
        raise ValueError("encrypted deletion inventory string is invalid")
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else _string(value)


def _array(value: object, limit: int) -> list[object]:
    if type(value) is not list:
        raise ValueError("encrypted deletion inventory array is invalid")
    items = cast(list[object], value)
    if len(items) > limit:
        raise ValueError("encrypted deletion inventory array is invalid or exceeds its limit")
    return items


def _fields(value: object, expected: set[str]) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError("encrypted deletion inventory fields are invalid")
    items = cast(dict[str, object], value)
    if set(items) != expected:
        raise ValueError("encrypted deletion inventory fields are invalid")
    return items


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("publication manifest contains duplicate JSON keys")
        result[key] = value
    return result
