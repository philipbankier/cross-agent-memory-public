from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from cross_assistant_memory.b2_object_store import B2S3ObjectBackend
from cross_assistant_memory.encrypted_objects import (
    MAX_MANIFEST_BYTES,
    EncryptedObjectManifest,
    EncryptedObjectStore,
    ObjectState,
)
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.safe_files import open_directory_no_symlinks

PUBLICATION_DIRECTORY = ".encrypted-evidence-publication"
_MANIFEST = re.compile(r"source_[0-9a-f]{32}\.json")
_TEMPORARY = re.compile(r"\.source_[0-9a-f]{32}\.[0-9a-f]{32}\.tmp")
_CIPHERTEXT = re.compile(r"storage_[0-9a-f]{32}\.ciphertext")


def same_encrypted_object(left: EncryptedObjectManifest, right: EncryptedObjectManifest) -> bool:
    def identity(manifest: EncryptedObjectManifest) -> dict[str, object]:
        fields = manifest.as_dict(include_authentication=False)
        del fields["state"], fields["updated_at"]
        return fields

    return identity(left) == identity(right)


def require_mapping_state(kind: str, location: tuple[str, EncryptedObjectManifest] | None) -> None:
    if kind == "local" and (location is None or location[1].state == ObjectState.PENDING):
        return
    if kind == "encrypted" and location is not None and location[1].state == ObjectState.VERIFIED:
        return
    raise RuntimeError("evidence object storage mapping is missing or inconsistent")


@dataclass(frozen=True)
class EvidencePublication:
    root: Path
    reader: EncryptedEvidenceReader
    store: EncryptedObjectStore
    manifest: EncryptedObjectManifest

    @classmethod
    def prepare(
        cls,
        data_root: Path,
        reader: EncryptedEvidenceReader,
        source: Path,
        *,
        object_id: str,
        byte_length: int,
        media_type: str,
        pending: EncryptedObjectManifest | None,
    ) -> EvidencePublication:
        root = data_root / PUBLICATION_DIRECTORY
        _private_directory(data_root)
        root.mkdir(mode=0o700, exist_ok=True)
        _sync(data_root)
        files = _inventory(root, reader.max_ciphertext_bytes)
        store = EncryptedObjectStore(root, reader.backend, reader.root_key)
        manifests = [path for path in files if _MANIFEST.fullmatch(path.name)]
        if pending is not None:
            if len(manifests) != 1 or manifests[0].stem != pending.source_object_id:
                raise RuntimeError("pending evidence publication metadata is missing")
            manifest = store.load_manifest(pending.source_object_id)
            if not same_encrypted_object(manifest, pending):
                raise RuntimeError("pending evidence publication identity changed")
        elif manifests:
            if len(manifests) != 1:
                raise RuntimeError("evidence publication has ambiguous preparation metadata")
            manifest = store.load_manifest(manifests[0].stem)
            if manifest.state != ObjectState.PENDING:
                raise RuntimeError("unregistered evidence publication has uncertain remote state")
        else:
            # With no registered intent or completed manifest, no provider write was possible.
            for path in files:
                path.unlink()
            for directory in (root / "manifests", root / "staging"):
                _sync(directory)
            reserve = reader.max_ciphertext_bytes + 2 * MAX_MANIFEST_BYTES
            if shutil.disk_usage(root).free < reserve * 2:
                raise RuntimeError("insufficient free space for bounded evidence preparation")
            try:
                manifest = store.prepare_file(
                    source,
                    media_type=media_type,
                    legacy_source_object_id=object_id,
                    max_ciphertext_bytes=reader.max_ciphertext_bytes,
                    expected_plaintext_sha256=object_id.removeprefix("sha256:"),
                    expected_plaintext_byte_length=byte_length,
                )
            except Exception as error:
                raise RuntimeError(
                    f"encrypted evidence preparation failed ({type(error).__name__})"
                ) from None
        if (
            manifest.legacy_source_object_id != object_id
            or object_id != f"sha256:{manifest.plaintext_sha256}"
            or manifest.plaintext_byte_length != byte_length
            or manifest.media_type != media_type
            or manifest.backend_profile != reader.backend.profile
            or manifest.plaintext_byte_length > reader.max_plaintext_bytes
            or manifest.ciphertext_byte_length > reader.max_ciphertext_bytes
        ):
            raise RuntimeError("retained evidence publication does not match the selected object")
        files = _inventory(root, reader.max_ciphertext_bytes)
        for path in files:
            if path.parent.name == "staging" and path.stem != manifest.storage_object_id:
                raise RuntimeError("evidence publication has an unexpected ciphertext object")
        for directory in (root / "manifests", root / "staging", root):
            _sync(directory)
        return cls(root, reader, store, manifest)

    def upload(self) -> EncryptedObjectManifest:
        # Only the ledger coordinator calls this, after committing the pending identity.
        backend = self.reader.backend
        try:
            if isinstance(backend, B2S3ObjectBackend):
                backend.reconcile_multipart(self.manifest.storage_object_id)
            result = self.store.resume(self.manifest.source_object_id)
            if isinstance(backend, B2S3ObjectBackend):
                backend.reconcile_multipart(self.manifest.storage_object_id)
            return result
        except Exception as error:
            raise RuntimeError(
                f"encrypted evidence publication failed ({type(error).__name__})"
            ) from None

    def finish(self, verified: EncryptedObjectManifest) -> None:
        if verified.state != ObjectState.VERIFIED or not same_encrypted_object(
            self.manifest, verified
        ):
            raise RuntimeError("evidence publication cleanup identity does not match")
        files = _inventory(self.root, self.reader.max_ciphertext_bytes)
        for path in files:
            if path.parent.name == "manifests" and _MANIFEST.fullmatch(path.name):
                if path.stem != verified.source_object_id:
                    raise RuntimeError("evidence publication cleanup has another manifest")
            elif path.parent.name == "staging" and path.stem != verified.storage_object_id:
                raise RuntimeError("evidence publication cleanup has another ciphertext")
        for path in files:
            path.unlink()
        for directory in (self.root / "manifests", self.root / "staging"):
            _sync(directory)
        _sync(self.root)

    @classmethod
    def finish_existing(
        cls, data_root: Path, reader: EncryptedEvidenceReader, verified: EncryptedObjectManifest
    ) -> None:
        root = data_root / PUBLICATION_DIRECTORY
        if not root.exists() and not root.is_symlink():
            return
        _inventory(root, reader.max_ciphertext_bytes)
        store = EncryptedObjectStore(root, reader.backend, reader.root_key)
        cls(root, reader, store, verified).finish(verified)


def _private_directory(path: Path) -> None:
    descriptor = open_directory_no_symlinks(path, "evidence publication directory")
    try:
        value = os.fstat(descriptor)
        if value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
            raise RuntimeError("evidence publication directory ownership or permissions changed")
    finally:
        os.close(descriptor)


def _inventory(root: Path, ciphertext_limit: int) -> list[Path]:
    _private_directory(root)
    files: list[Path] = []
    for directory in root.iterdir():
        if directory.name not in {"manifests", "staging"}:
            raise RuntimeError("unexpected evidence publication directory entry")
        _private_directory(directory)
        for count, path in enumerate(directory.iterdir(), 1):
            value = path.lstat()
            allowed = (
                _MANIFEST.fullmatch(path.name) or _TEMPORARY.fullmatch(path.name)
                if directory.name == "manifests"
                else _CIPHERTEXT.fullmatch(path.name)
            )
            limit = MAX_MANIFEST_BYTES if directory.name == "manifests" else ciphertext_limit
            if (
                count > (2 if directory.name == "manifests" else 1)
                or not allowed
                or not stat.S_ISREG(value.st_mode)
                or value.st_nlink != 1
                or value.st_uid != os.geteuid()
                or stat.S_IMODE(value.st_mode) != 0o600
                or value.st_size > limit
            ):
                raise RuntimeError("unsafe or oversized evidence publication artifact")
            files.append(path)
    return files


def _sync(path: Path) -> None:
    descriptor = open_directory_no_symlinks(path, "evidence publication directory")
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
