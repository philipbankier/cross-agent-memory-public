from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import tempfile
import threading
import uuid
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import ExitStack, closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import FrameType
from typing import Any, cast

from cross_assistant_memory.b2_object_store import (
    B2_S3_PROFILE,
    B2S3ObjectBackend,
    B2S3Profile,
    create_b2_s3_bindings,
)
from cross_assistant_memory.backup import (
    OFFLINE_CLONE_MARKER,
    SNAPSHOT_MANIFEST,
    create_offline_clone,
    create_snapshot,
    load_snapshot_manifest,
    publish_restored_node,
    require_snapshot_privacy,
    snapshot_source_generation,
    staged_offline_clone,
    verify_snapshot,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import (
    EncryptedObjectManifest,
    EncryptedObjectStore,
    FilesystemObjectBackend,
    ObjectState,
    OperationalKey,
    RecoveryKeyAccess,
    RecoverySecret,
    RootKey,
    build_recovery_kit,
    create_recovery_kit,
    restore_root_key,
    restore_root_key_from_bytes,
)
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.models import Authority, QueryMode, Scope, SearchResult
from cross_assistant_memory.object_store import ObjectBackend
from cross_assistant_memory.recovery_status import (
    BACKUP_RECEIPT_ROOT,
    RESTORE_RECEIPT_ROOT,
    record_successful_backup,
    record_verified_restore,
)
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    publish_file_no_replace,
)
from cross_assistant_memory.snapshot_materialization import (
    MATERIALIZATION_RECEIPT_ROOT,
    StorageMaterialization,
    verify_storage_materialization_receipt,
)
from cross_assistant_memory.storage import (
    Ledger,
    exclusive_ledger_writer,
    open_maintenance_inspection,
)

RECOVERY_PACKAGE_FORMAT_VERSION = 1
RECOVERY_PACKAGE_KIT_FORMAT_VERSION = 1
RECOVERY_QUERY_SUITE_FORMAT_VERSION = 1
RECOVERY_PACKAGE_INDEX_MEDIA_TYPE = (
    "application/vnd.cross-assistant-memory.recovery-package-index+json"
)
RECOVERY_RESTORE_ROOT = RESTORE_RECEIPT_ROOT
MAX_PACKAGE_KIT_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_INDEX_BYTES = 128 * 1024 * 1024
MAX_QUERY_SUITE_BYTES = 1024 * 1024
MAX_PACKAGE_FILES = 100_000
MAX_KNOWN_QUERIES = 100
MAX_QUERY_RESULTS = 20
B2_BACKUP_STAGING_DIRECTORY = ".cross-agent-memory-backup-staging"
DEFAULT_B2_BACKUP_STAGING_BYTES = 16 * 1024 * 1024 * 1024
_B2_IO_WORKERS = 4
_B2_IO_BYTES = 64 * 1024 * 1024
_B2_STAGE_AAD = b"cross-agent-memory:b2-backup-stage:v1"

_PACKAGE_ID = re.compile(r"package_[0-9a-f]{32}")
_QUERY_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class RecoveryQuery:
    name: str
    query: str
    mode: QueryMode = QueryMode.FIND_EVIDENCE
    scopes: tuple[Scope, ...] = (Scope.USER_GLOBAL,)
    project_id: str | None = None
    authorities: tuple[Authority, ...] | None = None
    limit: int = 5

    def __post_init__(self) -> None:
        if not _QUERY_NAME.fullmatch(self.name):
            raise ValueError("recovery query name is invalid")
        if self.mode is not QueryMode.WHERE_DID_I_LEAVE_OFF and not self.query.strip():
            raise ValueError("recovery query must not be empty")
        if not self.scopes or len(set(self.scopes)) != len(self.scopes):
            raise ValueError("recovery query scopes are invalid")
        has_project_scope = Scope.PROJECT in self.scopes
        if has_project_scope != (self.project_id is not None):
            raise ValueError(
                "recovery query project scope and project id must be configured together"
            )
        if self.project_id is not None and not self.project_id:
            raise ValueError("recovery query project id must not be empty")
        if self.authorities is not None and (
            not self.authorities or len(set(self.authorities)) != len(self.authorities)
        ):
            raise ValueError("recovery query authorities are invalid")
        if not 1 <= self.limit <= MAX_QUERY_RESULTS:
            raise ValueError("recovery query limit is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "query": self.query,
            "mode": self.mode.value,
            "scopes": [item.value for item in self.scopes],
            "project_id": self.project_id,
            "authorities": (
                [item.value for item in self.authorities] if self.authorities is not None else None
            ),
            "limit": self.limit,
        }

    @classmethod
    def from_dict(cls, value: object) -> RecoveryQuery:
        if not isinstance(value, dict):
            raise ValueError("recovery query must be an object")
        fields = cast(dict[object, object], value)
        expected = {
            "name",
            "query",
            "mode",
            "scopes",
            "project_id",
            "authorities",
            "limit",
        }
        if set(fields) != expected:
            raise ValueError("recovery query fields are invalid")
        name = _required_str(fields, "name")
        query = _required_str(fields, "query", allow_empty=True)
        try:
            mode = QueryMode(_required_str(fields, "mode"))
        except ValueError as error:
            raise ValueError("recovery query mode is invalid") from error
        scopes_value = fields.get("scopes")
        if not isinstance(scopes_value, list):
            raise ValueError("recovery query scopes are invalid")
        try:
            scopes = tuple(
                Scope(_list_str(item, "scope")) for item in cast(list[object], scopes_value)
            )
        except ValueError as error:
            raise ValueError("recovery query scopes are invalid") from error
        project_value = fields.get("project_id")
        if project_value is not None and not isinstance(project_value, str):
            raise ValueError("recovery query project id is invalid")
        authorities_value = fields.get("authorities")
        authorities: tuple[Authority, ...] | None
        if authorities_value is None:
            authorities = None
        elif isinstance(authorities_value, list):
            try:
                authorities = tuple(
                    Authority(_list_str(item, "authority"))
                    for item in cast(list[object], authorities_value)
                )
            except ValueError as error:
                raise ValueError("recovery query authorities are invalid") from error
        else:
            raise ValueError("recovery query authorities are invalid")
        return cls(
            name=name,
            query=query,
            mode=mode,
            scopes=scopes,
            project_id=project_value,
            authorities=authorities,
            limit=_required_int(fields, "limit"),
        )


def load_recovery_queries(path: Path) -> tuple[RecoveryQuery, ...]:
    raw = _read_regular_file(path.expanduser(), MAX_QUERY_SUITE_BYTES)
    try:
        value: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("recovery query suite is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("recovery query suite must be an object")
    fields = cast(dict[object, object], value)
    if set(fields) != {"format_version", "queries"}:
        raise ValueError("recovery query suite fields are invalid")
    if fields.get("format_version") != RECOVERY_QUERY_SUITE_FORMAT_VERSION:
        raise ValueError("unsupported recovery query suite format")
    queries_value = fields.get("queries")
    if not isinstance(queries_value, list):
        raise ValueError("recovery query suite queries are invalid")
    queries = tuple(RecoveryQuery.from_dict(item) for item in cast(list[object], queries_value))
    _validate_queries(queries)
    return queries


def initialize_recovery_material(secret_output: Path, root_kit_output: Path) -> dict[str, Any]:
    secret_path = secret_output.expanduser()
    root_kit_path = root_kit_output.expanduser()
    if secret_path.resolve() == root_kit_path.resolve():
        raise ValueError("recovery secret and root kit must use different paths")
    _require_absent(secret_path, "recovery secret")
    _require_absent(root_kit_path, "root recovery kit")
    _ensure_private_directory(secret_path.parent)
    _ensure_private_directory(root_kit_path.parent)
    recovery_secret = RecoverySecret.generate()
    root_key = RootKey.generate()
    secret_created = False
    root_kit_created = False
    try:
        recovery_secret.write(secret_path)
        secret_created = True
        root_receipt = create_recovery_kit(root_key, recovery_secret, root_kit_path)
        root_kit_created = True
    except BaseException:
        if secret_created:
            secret_path.unlink(missing_ok=True)
        if root_kit_created:
            root_kit_path.unlink(missing_ok=True)
        raise
    return {
        "status": "created",
        "root_key_id": root_key.key_id,
        "recovery_secret_path": str(secret_path),
        "root_recovery_kit_path": str(root_kit_path),
        "root_recovery_kit_sha256": root_receipt["recovery_kit_sha256"],
        "separate_offline_storage_required": True,
    }


def install_operational_key(
    settings: Settings,
    *,
    root_kit: Path,
    recovery_secret_path: Path,
    output: Path,
) -> dict[str, object]:
    try:
        destination = Path(os.path.abspath(output.expanduser()))
        _require_external_key(settings, destination)
        raw = _read_private_package_kit(root_kit)
        material = OperationalKey.from_recovery_kit(raw, RecoverySecret.load(recovery_secret_path))
        if destination.exists() or destination.is_symlink():
            installed = OperationalKey.load(destination)
            if (
                installed.root_key.serialize_cleartext_keyset()
                != material.root_key.serialize_cleartext_keyset()
                or installed.recovery_kit(material.root_key) != raw
            ):
                raise ValueError("existing operational key belongs to a different recovery kit")
            status = "already_installed"
        else:
            material.write(destination)
            installed = OperationalKey.load(destination)
            if (
                installed.root_key.serialize_cleartext_keyset()
                != material.root_key.serialize_cleartext_keyset()
                or installed.recovery_kit(material.root_key) != raw
            ):
                raise RuntimeError("installed operational key verification failed")
            status = "installed"
        return {
            "status": status,
            "operational_key_path": str(destination),
            "root_key_id": installed.root_key.key_id,
            "root_recovery_kit_sha256": hashlib.sha256(raw).hexdigest(),
            "independent_recovery_copy_verified": False,
        }
    except Exception as error:
        raise RuntimeError(
            f"operational key installation failed ({type(error).__name__})"
        ) from None


def _require_external_key(settings: Settings, path: Path) -> None:
    source = Path(os.path.abspath(settings.data_root.expanduser()))
    if path.is_relative_to(source) or path.resolve().is_relative_to(source.resolve()):
        raise ValueError("operational key must be outside the node data root")
    try:
        source_stat = source.stat()
    except FileNotFoundError:
        return
    # String comparisons alone miss case aliases on case-insensitive filesystems.
    for ancestor in path.parents:
        try:
            ancestor_stat = ancestor.stat()
        except FileNotFoundError:
            continue
        if (ancestor_stat.st_dev, ancestor_stat.st_ino) == (
            source_stat.st_dev,
            source_stat.st_ino,
        ):
            raise ValueError("operational key must be outside the node data root")


def _load_backup_key(
    settings: Settings,
    *,
    root_kit: Path | None,
    recovery_secret_path: Path | None,
    operational_key_path: Path | None,
) -> tuple[RootKey, RecoveryKeyAccess]:
    if operational_key_path is not None:
        if root_kit is not None or recovery_secret_path is not None:
            raise ValueError(
                "choose an operational key or a root kit and recovery secret, not both"
            )
        _require_external_key(settings, Path(os.path.abspath(operational_key_path.expanduser())))
        material = OperationalKey.load(operational_key_path)
        return material.root_key, material
    if root_kit is None or recovery_secret_path is None:
        raise ValueError("backup requires an operational key or both root kit and recovery secret")
    recovery_secret = RecoverySecret.load(recovery_secret_path.expanduser())
    return restore_root_key(root_kit.expanduser(), recovery_secret), recovery_secret


def create_filesystem_recovery_package(
    settings: Settings,
    *,
    backend_root: Path,
    root_kit: Path | None = None,
    recovery_secret_path: Path | None = None,
    operational_key_path: Path | None = None,
    package_kit: Path,
    query_suite: Path,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    snapshot_byte_limit: int | None = None,
) -> dict[str, Any]:
    root_key, recovery_secret = _load_backup_key(
        settings,
        root_kit=root_kit,
        recovery_secret_path=recovery_secret_path,
        operational_key_path=operational_key_path,
    )
    return create_recovery_package(
        settings,
        _filesystem_backend(backend_root),
        root_key,
        recovery_secret,
        package_kit,
        load_recovery_queries(query_suite),
        encrypted_evidence_reader=encrypted_evidence_reader,
        snapshot_byte_limit=snapshot_byte_limit,
    )


def restore_filesystem_recovery_package(
    *,
    backend_root: Path,
    package_kit: Path,
    recovery_secret_path: Path,
    output: Path,
) -> dict[str, Any]:
    recovery_secret = RecoverySecret.load(recovery_secret_path.expanduser())
    return restore_recovery_package(
        _filesystem_backend(backend_root),
        package_kit,
        recovery_secret,
        output,
    )


def create_b2_recovery_package(
    settings: Settings,
    *,
    root_kit: Path | None = None,
    recovery_secret_path: Path | None = None,
    operational_key_path: Path | None = None,
    package_kit: Path,
    query_suite: Path,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    snapshot_byte_limit: int | None = None,
    resume_source_generation: str | None = None,
) -> dict[str, Any]:
    try:
        if resume_source_generation is not None and not _SHA256.fullmatch(resume_source_generation):
            raise ValueError("capture resume generation must be a SHA-256 digest")
        root_key, recovery_secret = _load_backup_key(
            settings,
            root_kit=root_kit,
            recovery_secret_path=recovery_secret_path,
            operational_key_path=operational_key_path,
        )
        queries = load_recovery_queries(query_suite)
        profile = B2S3Profile.from_environment()
        maximum = int(
            os.environ.get("CAM_B2_BACKUP_MAX_STAGING_BYTES", DEFAULT_B2_BACKUP_STAGING_BYTES)
        )
        if maximum < 8:
            raise ValueError("B2 backup staging budget must be at least 8 bytes")
        if settings.database_path.is_symlink() or not settings.database_path.is_file():
            raise ValueError("B2 backup source must be an existing regular database")
        bindings = create_b2_s3_bindings(profile)
        with exclusive_ledger_writer(settings):
            return _create_b2_package_locked(
                settings,
                bindings.backend,
                profile,
                root_key,
                recovery_secret,
                package_kit,
                queries,
                maximum,
                encrypted_evidence_reader=encrypted_evidence_reader,
                snapshot_byte_limit=snapshot_byte_limit,
                resume_source_generation=resume_source_generation,
            )
    except Exception as error:
        # Provider exception messages can contain signed requests or credentials.
        raise RuntimeError(
            f"B2 backup failed ({type(error).__name__}); success is unconfirmed. "
            "Check local inputs, snapshot privacy eligibility, and provider access."
        ) from None


class _B2RecoverySpool(FilesystemObjectBackend):
    """Local ciphertext prepared for B2, never evidence of remote durability."""

    def __init__(self, root: Path, maximum: int) -> None:
        super().__init__(root)
        self.root = root
        self.maximum = maximum
        self.stored_bytes = sum(path.stat().st_size for path in (root / "objects").iterdir())

    @property
    def profile(self) -> str:
        return B2_S3_PROFILE

    def put_file(self, storage_object_id: str, source: Path) -> None:
        size = source.stat().st_size
        if self.stored_bytes + size > self.maximum:
            raise RuntimeError("B2 ciphertext staging byte budget exceeded")
        super().put_file(storage_object_id, source)
        self.stored_bytes += size


def b2_backup_staging_path(settings: Settings) -> Path:
    source = Path(os.path.abspath(settings.data_root.expanduser()))
    identity = hashlib.sha256(str(source).encode()).hexdigest()
    return source.parent / B2_BACKUP_STAGING_DIRECTORY / identity


def _b2_final_binding_path(destination: Path) -> Path:
    identity = hashlib.sha256(str(destination).encode()).hexdigest()
    return destination.parent / f".b2-backup-{identity}.tink"


def _b2_final_binding(destination: Path, request: bytes, kit: bytes) -> tuple[Path, bytes]:
    return _b2_final_binding_path(destination), _canonical_json_bytes(
        {
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "package_kit_sha256": hashlib.sha256(kit).hexdigest(),
        }
    )


def _b2_backup_request(
    source_root: Path,
    destination: Path,
    profile: B2S3Profile,
    root_key: RootKey,
    queries: tuple[RecoveryQuery, ...],
    generation: str,
) -> bytes:
    return _canonical_json_bytes(
        {
            "format_version": 1,
            "source_root_sha256": hashlib.sha256(str(source_root).encode()).hexdigest(),
            "destination_sha256": hashlib.sha256(str(destination).encode()).hexdigest(),
            "provider_sha256": hashlib.sha256(
                _canonical_json_bytes(
                    {
                        "bucket": profile.bucket,
                        "endpoint": profile.endpoint_url,
                        "region": profile.region,
                    }
                )
            ).hexdigest(),
            "root_key_id": root_key.key_id,
            "source_generation": generation,
            "queries": [query.as_dict() for query in queries],
        }
    )


def discard_empty_b2_preparation(
    settings: Settings,
    *,
    root_kit: Path | None = None,
    recovery_secret_path: Path | None = None,
    operational_key_path: Path | None = None,
    package_kit: Path,
    query_suite: Path,
    execute: bool = False,
) -> dict[str, Any]:
    """Retire only an authenticated request with no prepared or published package."""
    return discard_b2_preparation(
        settings,
        root_kit=root_kit,
        recovery_secret_path=recovery_secret_path,
        operational_key_path=operational_key_path,
        package_kit=package_kit,
        query_suite=query_suite,
        execute=execute,
    )


def discard_b2_preparation(
    settings: Settings,
    *,
    root_kit: Path | None = None,
    recovery_secret_path: Path | None = None,
    operational_key_path: Path | None = None,
    package_kit: Path,
    query_suite: Path,
    execute: bool = False,
    empty_only: bool = True,
) -> dict[str, Any]:
    """Retire authenticated local preparation only before any package publication intent."""
    kind = "empty" if empty_only else "unpublished"
    try:
        root_key, _ = _load_backup_key(
            settings,
            root_kit=root_kit,
            recovery_secret_path=recovery_secret_path,
            operational_key_path=operational_key_path,
        )
        queries = load_recovery_queries(query_suite)
        profile = B2S3Profile.from_environment()
        maximum = (
            MAX_PACKAGE_KIT_BYTES
            if empty_only
            else int(
                os.environ.get("CAM_B2_BACKUP_MAX_STAGING_BYTES", DEFAULT_B2_BACKUP_STAGING_BYTES)
            )
        )
        source = Path(os.path.abspath(settings.data_root.expanduser()))
        destination = Path(os.path.abspath(package_kit.expanduser()))
        if destination.is_relative_to(source):
            raise ValueError("package kit must be outside the source")
        if settings.database_path.is_symlink() or not settings.database_path.is_file():
            raise ValueError("cleanup requires an existing database")
        descriptor = open_directory_no_symlinks(destination.parent, "package kit parent")
        os.close(descriptor)
        with exclusive_ledger_writer(settings):
            _require_absent(destination, "final package kit")
            _require_absent(_b2_final_binding_path(destination), "final package binding")
            stage = b2_backup_staging_path(settings)
            if not stage.exists() and not stage.is_symlink():
                return {"status": "no_preparation", "text_free": True}
            descriptor = open_directory_no_symlinks(stage, "B2 backup staging")
            try:
                identity = os.fstat(descriptor)
                _validate_b2_stage(stage, identity, maximum)
                inventory = _b2_preparation_inventory(stage, empty_only=empty_only)
                request_path = stage / "request.tink"
                if not request_path.exists():
                    if list(stage.iterdir()):
                        raise RuntimeError("unmarked preparation is not empty")
                    if execute:
                        _remove_empty_b2_stage(stage, identity)
                    return {"status": "no_preparation", "text_free": True}
                payload = _read_private_package_kit(request_path)
                plaintext = root_key.primitive().decrypt(payload, _B2_STAGE_AAD)
                raw: object = json.loads(plaintext)
                generation = (
                    cast(dict[str, object], raw).get("source_generation")
                    if isinstance(raw, dict)
                    else None
                )
                if not isinstance(generation, str) or not _SHA256.fullmatch(generation):
                    raise ValueError("invalid preparation generation")
                if plaintext != _b2_backup_request(
                    source, destination, profile, root_key, queries, generation
                ):
                    raise RuntimeError("preparation belongs to different inputs")
                result: dict[str, object] = {
                    "text_free": True,
                    "request_sha256": hashlib.sha256(payload).hexdigest(),
                }
                if not empty_only:
                    result.update(
                        ciphertext_files=len(inventory.files) - 1,
                        ciphertext_bytes=sum(
                            item[2]
                            for name, item in inventory.files.items()
                            if name != "request.tink"
                        ),
                    )
                if not execute:
                    return {"status": "preview", **result}
                _require_b2_stage_identity(stage, identity)
                _validate_b2_stage(stage, identity, maximum)
                if _b2_preparation_inventory(stage, empty_only=empty_only) != inventory:
                    raise RuntimeError("preparation changed during cleanup")
                if _read_private_package_kit(request_path) != payload:
                    raise RuntimeError("preparation request changed during cleanup")
                _require_absent(destination, "final package kit")
                _require_absent(_b2_final_binding_path(destination), "final package binding")
                if not empty_only:
                    # The authenticated marker survives partial removal so explicit retry
                    # can retire the remainder without adopting a different attempt.
                    _discard_preparation_ciphertext(stage, descriptor, inventory)
                # Empty directories first, authenticated marker last. A crash leaves either
                # a retryable marked subset or an empty stage ordinary backup already accepts.
                for name in ("ciphertext/objects", "ciphertext/incomplete", "ciphertext"):
                    path = stage / name
                    if path.exists():
                        child = open_directory_no_symlinks(path.parent, "empty spool parent")
                        try:
                            current = os.stat(path.name, dir_fd=child, follow_symlinks=False)
                            if (current.st_dev, current.st_ino) != inventory.directories[name]:
                                raise RuntimeError("preparation directory changed during cleanup")
                            os.rmdir(path.name, dir_fd=child)
                            os.fsync(child)
                        finally:
                            os.close(child)
                _validate_b2_stage(stage, identity, MAX_PACKAGE_KIT_BYTES)
                if set(os.listdir(descriptor)) != {"request.tink"}:
                    raise RuntimeError("preparation changed during cleanup")
                if _read_private_package_kit(request_path) != payload:
                    raise RuntimeError("preparation request changed during cleanup")
                _require_absent(destination, "final package kit")
                _require_absent(_b2_final_binding_path(destination), "final package binding")
                os.unlink("request.tink", dir_fd=descriptor)
                os.fsync(descriptor)
                _remove_empty_b2_stage(stage, identity)
                return {"status": "discarded", **result}
            finally:
                os.close(descriptor)
    except Exception:
        raise RuntimeError(
            f"B2 {kind} preparation cleanup refused; preserve the retained attempt "
            "and inspect its state."
        ) from None


@dataclass(frozen=True)
class _B2PreparationInventory:
    files: dict[str, tuple[int, int, int, int, int]]
    directories: dict[str, tuple[int, int]]


def _preparation_file_identity(details: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _b2_preparation_inventory(stage: Path, *, empty_only: bool) -> _B2PreparationInventory:
    allowed_directories = {"ciphertext", "ciphertext/objects", "ciphertext/incomplete"}
    inventory: dict[str, tuple[int, int, int, int, int]] = {}
    directory_ids: dict[str, tuple[int, int]] = {}
    for parent, directories, files in os.walk(stage, followlinks=False):
        for name in directories:
            path = Path(parent) / name
            relative = path.relative_to(stage).as_posix()
            if relative not in allowed_directories:
                raise RuntimeError("preparation contains unexpected directories")
            details = path.lstat()
            directory_ids[relative] = (details.st_dev, details.st_ino)
        for name in files:
            path = Path(parent) / name
            relative = path.relative_to(stage).as_posix()
            ciphertext = re.fullmatch(
                r"ciphertext/(?:objects/storage_[0-9a-f]{32}|incomplete/storage_[0-9a-f]{32}\.[0-9a-f]{32}\.partial)",
                relative,
            )
            if relative != "request.tink" and (empty_only or ciphertext is None):
                raise RuntimeError("preparation contains unexpected files")
            inventory[relative] = _preparation_file_identity(path.lstat())
    return _B2PreparationInventory(inventory, directory_ids)


def _discard_preparation_ciphertext(
    stage: Path, stage_descriptor: int, inventory: _B2PreparationInventory
) -> None:
    with ExitStack() as cleanup:
        handles: dict[str, int] = {}
        for name, identity in inventory.directories.items():
            descriptor = open_directory_no_symlinks(stage / name, "preparation ciphertext")
            cleanup.callback(os.close, descriptor)
            details = os.fstat(descriptor)
            if (details.st_dev, details.st_ino) != identity:
                raise RuntimeError("preparation directory changed during cleanup")
            expected = {
                Path(item).name
                for item in (*inventory.files, *inventory.directories)
                if str(Path(item).parent) == name
            }
            if set(os.listdir(descriptor)) != expected:
                raise RuntimeError("preparation directory contents changed during cleanup")
            handles[name] = descriptor
        for name, identity in inventory.files.items():
            if name == "request.tink":
                continue
            for directory, expected in inventory.directories.items():
                path = Path(directory)
                parent = stage_descriptor if str(path.parent) == "." else handles[str(path.parent)]
                details = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if (details.st_dev, details.st_ino) != expected:
                    raise RuntimeError("preparation directory changed during cleanup")
            path = Path(name)
            parent = handles[str(path.parent)]
            details = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if _preparation_file_identity(details) != identity:
                raise RuntimeError("preparation ciphertext changed during cleanup")
            os.unlink(path.name, dir_fd=parent)
        for descriptor in handles.values():
            os.fsync(descriptor)


def _remove_empty_b2_stage(stage: Path, identity: os.stat_result) -> None:
    parent = open_directory_no_symlinks(stage.parent, "B2 staging parent")
    try:
        _require_b2_stage_identity(stage, identity)
        os.rmdir(stage.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _create_b2_package_locked(
    settings: Settings,
    backend: B2S3ObjectBackend,
    profile: B2S3Profile,
    root_key: RootKey,
    recovery_secret: RecoveryKeyAccess,
    package_kit: Path,
    queries: tuple[RecoveryQuery, ...],
    maximum: int,
    *,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    snapshot_byte_limit: int | None = None,
    resume_source_generation: str | None = None,
) -> dict[str, Any]:
    destination = Path(os.path.abspath(package_kit.expanduser()))
    source_root = Path(os.path.abspath(settings.data_root.expanduser()))
    if destination.is_relative_to(source_root):
        raise ValueError("B2 package kit must be outside its source data root")
    _ensure_private_directory(destination.parent)
    descriptor = open_directory_no_symlinks(destination.parent, "B2 package kit parent")
    os.close(descriptor)
    stage = b2_backup_staging_path(settings)
    current_generation = snapshot_source_generation(settings)
    capture_generation = resume_source_generation or current_generation
    request = _b2_backup_request(
        source_root, destination, profile, root_key, queries, capture_generation
    )
    capture_status = (
        {
            "current_ledger_generation": current_generation,
            "capture_is_current": current_generation == capture_generation,
        }
        if resume_source_generation is not None
        else {}
    )
    payload_limit = (
        min(
            maximum,
            shutil.disk_usage(destination.parent).free // 2,
            shutil.disk_usage(source_root.parent).free // 2,
        )
        // 8
    )
    if snapshot_byte_limit is not None:
        if type(snapshot_byte_limit) is not int or snapshot_byte_limit <= 0:
            raise ValueError("snapshot byte limit must be positive")
        payload_limit = min(payload_limit, snapshot_byte_limit)
    if payload_limit < max(1, len(request)):
        raise RuntimeError("B2 backup has no available staging budget")
    if destination.exists() or destination.is_symlink():
        kit_payload = _read_private_package_kit(destination)
        binding_path, binding = _b2_final_binding(destination, request, kit_payload)
        _verify_b2_stage_binding(binding_path, binding, root_key)
        result = _resume_recovery_package_publication(
            settings,
            backend,
            root_key,
            recovery_secret,
            destination,
            queries,
            snapshot_byte_limit=payload_limit,
            encrypted_evidence_reader=encrypted_evidence_reader,
            capture_generation=resume_source_generation,
        )
        if stage.exists() or stage.is_symlink():
            descriptor = open_directory_no_symlinks(stage, "B2 backup staging")
            try:
                identity = os.fstat(descriptor)
                _validate_b2_stage(stage, identity, maximum, allow_disposable_links=True)
                if (stage / "request.tink").exists():
                    _verify_b2_stage_binding(stage / "request.tink", request, root_key)
                if (stage / "staged-kit.json").exists() and (
                    _read_private_package_kit(stage / "staged-kit.json") != kit_payload
                ):
                    raise RuntimeError("B2 final kit differs from the retained staging kit")
                _clear_b2_scratch(stage, descriptor)
                _remove_b2_stage(stage, identity, maximum)
            finally:
                os.close(descriptor)
        return {**result, **capture_status}
    if resume_source_generation is not None and not all(
        (stage / name).is_file()
        for name in ("request.tink", "staged-kit.json", "upload-intent.tink")
    ):
        raise RuntimeError("capture resume requires a complete retained B2 preparation")
    _ensure_private_directory(stage.parent)
    stage.mkdir(mode=0o700, exist_ok=True)
    _fsync_directory(stage.parent)
    stage_descriptor = open_directory_no_symlinks(stage, "B2 backup staging")
    try:
        stage_identity = os.fstat(stage_descriptor)
        _validate_b2_stage(stage, stage_identity, maximum, allow_disposable_links=True)
        request_path = stage / "request.tink"
        if request_path.exists():
            _verify_b2_stage_binding(request_path, request, root_key)
        else:
            _recover_b2_request_publication(stage, request_path, request, root_key)
        _clear_b2_scratch(stage, stage_descriptor)
        staged_kit = stage / "staged-kit.json"
        upload_intent = stage / "upload-intent.tink"
        resuming = staged_kit.exists()
        if not resuming:
            binding_path = _b2_final_binding_path(destination)
            if (
                upload_intent.exists()
                or destination.exists()
                or binding_path.exists()
                or binding_path.is_symlink()
            ):
                raise RuntimeError("B2 staging is missing a previously published package kit")
            # Nothing can reach B2 until both the complete kit and upload intent are durable.
            _clear_b2_preparation(stage, stage_descriptor)
            payload_limit = min(payload_limit, shutil.disk_usage(stage).free // 16)
            if payload_limit < 1:
                raise RuntimeError("B2 backup has no available staging budget")
            spool = _B2RecoverySpool(stage / "ciphertext", maximum // 4)
            _prepare_recovery_package(
                settings,
                spool,
                root_key,
                recovery_secret,
                staged_kit,
                queries,
                scratch_parent=stage,
                snapshot_byte_limit=payload_limit,
                encrypted_evidence_reader=encrypted_evidence_reader,
            )
        _validate_b2_stage(stage, stage_identity, maximum)
        spool = _B2RecoverySpool(stage / "ciphertext", maximum // 4)
        kit_payload = _read_private_package_kit(staged_kit)
        # All ciphertext and its directory entries precede the durable upload intent.
        for directory in (spool.root / "objects", spool.root / "incomplete", spool.root, stage):
            _fsync_directory(directory)
        intent = hashlib.sha256(kit_payload).digest()
        if upload_intent.exists():
            _verify_b2_stage_binding(upload_intent, intent, root_key)
        else:
            _write_new_private_file(
                upload_intent,
                root_key.primitive().encrypt(intent, _B2_STAGE_AAD),
                mode=0o600,
            )
        binding_path, binding = _b2_final_binding(destination, request, kit_payload)
        if binding_path.exists() or binding_path.is_symlink():
            _verify_b2_stage_binding(binding_path, binding, root_key)
        else:
            _write_new_private_file(
                binding_path,
                root_key.primitive().encrypt(binding, _B2_STAGE_AAD),
                mode=0o600,
            )
        _upload_b2_staged_package(
            spool,
            backend,
            staged_kit,
            root_key,
            recovery_secret,
            queries,
            capture_generation,
            stage,
            stage_identity,
            maximum,
            payload_limit,
            retained_source=settings if resume_source_generation is not None else None,
        )
        _validate_b2_stage(stage, stage_identity, maximum)
        _write_new_private_file(destination, kit_payload, mode=0o600)
        result = _resume_recovery_package_publication(
            settings,
            backend,
            root_key,
            recovery_secret,
            destination,
            queries,
            snapshot_byte_limit=payload_limit,
            encrypted_evidence_reader=encrypted_evidence_reader,
            capture_generation=resume_source_generation,
        )
        _remove_b2_stage(stage, stage_identity, maximum)
        return {**result, "status": "resumed" if resuming else "created", **capture_status}
    finally:
        os.close(stage_descriptor)


def _verify_b2_stage_binding(path: Path, expected: bytes, root_key: RootKey) -> None:
    payload = _read_private_package_kit(path)
    if root_key.primitive().decrypt(payload, _B2_STAGE_AAD) != expected:
        raise RuntimeError("B2 staging belongs to different inputs or a stale source generation")


def _recover_b2_request_publication(
    stage: Path,
    target: Path,
    request: bytes,
    root_key: RootKey,
) -> None:
    entries = list(stage.iterdir())
    for entry in entries:
        if not re.fullmatch(r"\.request\.tink\.[0-9a-f]{32}\.partial", entry.name):
            raise RuntimeError("unmarked B2 staging contains unrecognized files")
        _read_private_package_kit(entry)
    # An unmarked directory containing only request partials has never reached preparation
    # or cloud writes. Truncated first writes can be discarded without adopting their inputs.
    for entry in entries:
        entry.unlink()
    _fsync_directory(stage)
    _write_new_private_file(
        target,
        root_key.primitive().encrypt(request, _B2_STAGE_AAD),
        mode=0o600,
    )


def _validate_b2_stage(
    stage: Path,
    identity: os.stat_result,
    maximum: int,
    *,
    allow_disposable_links: bool = False,
) -> None:
    _require_b2_stage_identity(stage, identity)
    for entry in stage.iterdir():
        if entry.name not in {
            "request.tink",
            "staged-kit.json",
            "upload-intent.tink",
            "ciphertext",
        } and not re.fullmatch(
            r"\.(?:build|inspect)-[a-z0-9_]+|\.(?:request\.tink|staged-kit\.json|upload-intent\.tink)\.[0-9a-f]{32}\.partial",
            entry.name,
        ):
            raise RuntimeError("B2 staging contains an unrecognized entry")
    total = 0
    count = 0
    linked: dict[tuple[int, int], tuple[int, list[Path]]] = {}
    for parent, directories, files in os.walk(stage, followlinks=False):
        for name in [".", *directories, *files]:
            path = Path(parent) / name
            details = path.lstat()
            if (
                not (stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode))
                or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) & 0o077
            ):
                raise RuntimeError("B2 staging contains an unsafe entry")
            if stat.S_ISREG(details.st_mode):
                total += details.st_size
                if details.st_nlink != 1:
                    if not allow_disposable_links:
                        raise RuntimeError("B2 staging contains a multiply linked file")
                    key = (details.st_dev, details.st_ino)
                    linked.setdefault(key, (details.st_nlink, []))[1].append(
                        path.relative_to(stage)
                    )
            count += 1
            if total > maximum or count > MAX_PACKAGE_FILES * 10:
                raise RuntimeError("B2 staging resource budget exceeded")
    for link_count, paths in linked.values():
        roots = {path.parts[0] for path in paths}
        if link_count != 2 or len(paths) != 2 or len(roots) != 1:
            raise RuntimeError("B2 staging contains links outside disposable scratch")
        root = next(iter(roots))
        is_scratch = re.fullmatch(r"\.(?:build|inspect)-[a-z0-9_]+", root) is not None
        is_unpublished = (
            root == "ciphertext"
            and not (stage / "staged-kit.json").exists()
            and not (stage / "upload-intent.tink").exists()
        )
        if not (is_scratch or is_unpublished):
            raise RuntimeError("B2 staging contains links outside disposable scratch")


def _require_b2_stage_identity(stage: Path, identity: os.stat_result) -> None:
    descriptor = open_directory_no_symlinks(stage, "B2 backup staging")
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise RuntimeError("B2 staging directory was replaced")
    finally:
        os.close(descriptor)


def _remove_b2_stage(stage: Path, identity: os.stat_result, maximum: int) -> None:
    _validate_b2_stage(stage, identity, maximum)
    parent = open_directory_no_symlinks(stage.parent, "B2 staging parent")
    try:
        _require_b2_stage_identity(stage, identity)
        shutil.rmtree(stage.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _clear_b2_scratch(stage: Path, descriptor: int) -> None:
    for entry in stage.iterdir():
        if re.fullmatch(r"\.(?:build|inspect)-[a-z0-9_]+", entry.name):
            if not entry.is_dir():
                raise RuntimeError("B2 scratch path is not a directory")
            shutil.rmtree(entry.name, dir_fd=descriptor)
    os.fsync(descriptor)


def _clear_b2_preparation(stage: Path, descriptor: int) -> None:
    for entry in stage.iterdir():
        if entry.name == "request.tink":
            continue
        if re.fullmatch(r"\.staged-kit\.json\.[0-9a-f]{32}\.partial", entry.name):
            entry.unlink()
            continue
        if entry.name == "ciphertext" or entry.name.startswith(".build-"):
            if not entry.is_dir():
                raise RuntimeError("B2 preparation contains an unexpected entry")
            shutil.rmtree(entry.name, dir_fd=descriptor)
        else:
            raise RuntimeError("B2 preparation contains an unexpected entry")
    os.fsync(descriptor)


def _upload_b2_staged_package(
    spool: _B2RecoverySpool,
    backend: B2S3ObjectBackend,
    staged_kit: Path,
    root_key: RootKey,
    recovery_secret: RecoveryKeyAccess,
    queries: tuple[RecoveryQuery, ...],
    generation: str,
    stage: Path,
    stage_identity: os.stat_result,
    maximum: int,
    payload_limit: int,
    *,
    retained_source: Settings | None = None,
) -> None:
    with tempfile.TemporaryDirectory(prefix=".inspect-", dir=stage) as temporary:
        workspace = Path(temporary)
        _, recovered_key, _, index_manifest, index = _load_package_material(
            spool,
            _read_private_package_kit(staged_kit),
            recovery_secret,
            workspace,
        )
        if (
            recovered_key.key_id != root_key.key_id
            or index["source_ledger_generation"] != generation
        ):
            raise RuntimeError("B2 staging is not bound to the current source and root key")
        query_keys = set(queries[0].as_dict())
        if [{key: item[key] for key in query_keys} for item in index["known_queries"]] != [
            query.as_dict() for query in queries
        ]:
            raise RuntimeError("B2 staging query suite changed")
        manifests = [
            EncryptedObjectManifest.from_dict(item["encrypted_manifest"]) for item in index["files"]
        ] + [index_manifest]
        if sum(item.plaintext_byte_length for item in manifests[:-1]) > payload_limit:
            raise RuntimeError("B2 staged package exceeds the restore payload budget")
        expected_objects = {item.storage_object_id for item in manifests}
        if {path.name for path in (spool.root / "objects").iterdir()} != expected_objects:
            raise RuntimeError("B2 staging ciphertext inventory differs from its package")
        remote_store = EncryptedObjectStore(workspace / "remote-verification", backend, root_key)
        # Authenticate every manifest with the supplied key, not just the key ID in the kit.
        for manifest in manifests:
            remote_store.register_manifest(manifest)
        verified_node = workspace / "verified-node"
        restore_recovery_package(spool, staged_kit, recovery_secret, verified_node)
        require_snapshot_privacy(Settings(verified_node).database_path)
        if retained_source is not None:
            _require_current_capture_content(retained_source, Settings(verified_node))
        _validate_b2_stage(stage, stage_identity, maximum)

        def before_upload(manifest: EncryptedObjectManifest) -> None:
            _require_b2_stage_identity(stage, stage_identity)
            if backend.exists(manifest.storage_object_id):
                remote_store.resume(manifest.source_object_id)

        def upload(manifest: EncryptedObjectManifest) -> None:
            backend.put_recoverable_file(
                manifest.storage_object_id, spool.root / "objects" / manifest.storage_object_id
            )

        def after_upload(manifest: EncryptedObjectManifest) -> None:
            remote_store.resume(manifest.source_object_id)

        _run_b2_object_io(manifests, upload, before=before_upload, after=after_upload)


def _run_b2_object_io(
    manifests: Sequence[EncryptedObjectManifest],
    operation: Callable[[EncryptedObjectManifest], None],
    *,
    before: Callable[[EncryptedObjectManifest], None] | None = None,
    after: Callable[[EncryptedObjectManifest], None] | None = None,
) -> None:
    on_main_thread = threading.current_thread() is threading.main_thread()
    original_handler = signal.getsignal(signal.SIGINT) if on_main_thread else None
    if on_main_thread and original_handler not in (signal.default_int_handler, signal.SIG_IGN):
        # An embedding caller owns its signal policy; do not change it or leave work behind.
        for manifest in manifests:
            if before is not None:
                before(manifest)
            operation(manifest)
            if after is not None:
                after(manifest)
        return

    interrupted = False

    def defer_interrupt(_signum: int, _frame: FrameType | None) -> None:
        nonlocal interrupted
        interrupted = True

    pending: dict[Future[None], EncryptedObjectManifest] = {}
    remaining = iter(manifests)
    next_manifest = next(remaining, None)
    pending_bytes = 0
    manages_interrupt = on_main_thread and original_handler == signal.default_int_handler
    if manages_interrupt:
        signal.signal(signal.SIGINT, defer_interrupt)
    try:
        # Workers own independent objects; shared guards stay on the caller.
        with ThreadPoolExecutor(max_workers=_B2_IO_WORKERS, thread_name_prefix="cam-b2-io") as pool:
            try:
                while next_manifest is not None or pending:
                    if interrupted:
                        raise KeyboardInterrupt
                    for future in pending:
                        if future.done():
                            future.result()
                    while (
                        next_manifest is not None
                        and len(pending) < _B2_IO_WORKERS
                        and (
                            not pending
                            or pending_bytes + next_manifest.ciphertext_byte_length <= _B2_IO_BYTES
                        )
                    ):
                        if before is not None:
                            before(next_manifest)
                        if interrupted:
                            raise KeyboardInterrupt
                        pending[pool.submit(operation, next_manifest)] = next_manifest
                        pending_bytes += next_manifest.ciphertext_byte_length
                        next_manifest = next(remaining, None)
                    completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                    if interrupted:
                        raise KeyboardInterrupt
                    for future in completed:
                        future.result()
                    for future in completed:
                        manifest = pending.pop(future)
                        pending_bytes -= manifest.ciphertext_byte_length
                        if after is not None:
                            after(manifest)
            finally:
                for future in pending:
                    future.cancel()
    finally:
        # Repeated Ctrl-C must not interrupt shutdown and release the writer with live uploads.
        if manages_interrupt:
            signal.signal(signal.SIGINT, signal.default_int_handler)
        if interrupted:
            raise KeyboardInterrupt


def restore_b2_recovery_package(
    *,
    package_kit: Path,
    recovery_secret_path: Path,
    output: Path,
) -> dict[str, Any]:
    try:
        recovery_secret = RecoverySecret.load(recovery_secret_path.expanduser())
        bindings = create_b2_s3_bindings(B2S3Profile.from_environment())
        return restore_recovery_package(bindings.backend, package_kit, recovery_secret, output)
    except Exception as error:
        raise RuntimeError(
            f"B2 restore failed ({type(error).__name__}); success is unconfirmed. "
            "Check local inputs, package integrity, and provider access."
        ) from None


def create_recovery_package(
    settings: Settings,
    backend: ObjectBackend,
    root_key: RootKey,
    recovery_secret: RecoveryKeyAccess,
    package_kit: Path,
    queries: Sequence[RecoveryQuery],
    *,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    snapshot_byte_limit: int | None = None,
) -> dict[str, Any]:
    query_tuple = tuple(queries)
    _validate_queries(query_tuple)
    destination = package_kit.expanduser()
    _ensure_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        return _resume_recovery_package_publication(
            settings,
            backend,
            root_key,
            recovery_secret,
            destination,
            query_tuple,
            encrypted_evidence_reader=encrypted_evidence_reader,
            snapshot_byte_limit=snapshot_byte_limit,
        )
    prepared = _prepare_recovery_package(
        settings,
        backend,
        root_key,
        recovery_secret,
        destination,
        query_tuple,
        encrypted_evidence_reader=encrypted_evidence_reader,
        snapshot_byte_limit=snapshot_byte_limit,
    )
    try:
        backup_receipt = record_successful_backup(
            settings,
            created_at=prepared["created_at"],
            package_id=prepared["package_id"],
            package_kit_sha256=prepared["package_kit_sha256"],
            snapshot_manifest_sha256=prepared["snapshot_manifest_sha256"],
            source_ledger_generation=prepared["source_ledger_generation"],
            backend_profile=backend.profile,
        )
    except (OSError, RuntimeError):
        return _resume_recovery_package_publication(
            settings,
            backend,
            root_key,
            recovery_secret,
            destination,
            query_tuple,
            encrypted_evidence_reader=encrypted_evidence_reader,
            snapshot_byte_limit=snapshot_byte_limit,
        )
    prepared.pop("created_at")
    return {
        **prepared,
        "status": "created",
        "status_receipt_sha256": backup_receipt["receipt_sha256"],
    }


def _prepare_recovery_package(
    settings: Settings,
    backend: ObjectBackend,
    root_key: RootKey,
    recovery_secret: RecoveryKeyAccess,
    destination: Path,
    query_tuple: tuple[RecoveryQuery, ...],
    *,
    scratch_parent: Path | None = None,
    snapshot_byte_limit: int | None = None,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
) -> dict[str, Any]:
    package_id = f"package_{uuid.uuid4().hex}"
    created_at = _now()

    with tempfile.TemporaryDirectory(prefix=".build-", dir=scratch_parent) as temporary_name:
        workspace = Path(os.path.realpath(temporary_name))
        workspace.chmod(0o700)
        snapshot = workspace / "snapshot"
        snapshot_result = create_snapshot(
            settings,
            snapshot,
            max_bytes=snapshot_byte_limit,
            encrypted_evidence_reader=encrypted_evidence_reader,
        )
        snapshot_manifest = load_snapshot_manifest(snapshot)
        if len(snapshot_manifest["files"]) + 1 > MAX_PACKAGE_FILES:
            raise ValueError("recovery package exceeds its file-count limit")

        query_clone = workspace / "query-clone"
        clone = create_offline_clone(snapshot, query_clone)
        query_ledger = Ledger(Settings(query_clone), read_only=True, require_checkpointed=False)
        source_generation = cast(str, clone["snapshot_ledger_generation"])
        expected_queries = _freeze_queries(query_ledger, query_tuple)
        materialization = cast(StorageMaterialization | None, clone["storage_materialization"])
        if materialization is not None:
            verify_storage_materialization_receipt(Settings(query_clone), materialization)

        encrypted_store = EncryptedObjectStore(workspace / "encrypted-metadata", backend, root_key)
        package_files: list[dict[str, object]] = []
        snapshot_manifest_path = snapshot / SNAPSHOT_MANIFEST
        package_files.append(
            _encrypt_package_file(
                encrypted_store,
                snapshot_manifest_path,
                path=SNAPSHOT_MANIFEST,
                role="snapshot_manifest",
            )
        )
        for item in snapshot_manifest["files"]:
            relative = _validated_relative_path(item["path"])
            package_files.append(
                _encrypt_package_file(
                    encrypted_store,
                    snapshot.joinpath(*relative.parts),
                    path=item["path"],
                    role=item["role"],
                )
            )

        package_index = {
            "format_version": RECOVERY_PACKAGE_FORMAT_VERSION,
            "package_id": package_id,
            "created_at": created_at,
            "backend_profile": backend.profile,
            "root_key_id": root_key.key_id,
            "snapshot_manifest_sha256": snapshot_result["snapshot_manifest_sha256"],
            "source_ledger_generation": source_generation,
            "files": package_files,
            "known_queries": expected_queries,
        }
        index_payload = _canonical_json_bytes(package_index)
        if len(index_payload) > MAX_PACKAGE_INDEX_BYTES:
            raise ValueError("recovery package index exceeds its size limit")
        index_path = workspace / "package-index.json"
        _write_new_private_file(index_path, index_payload, mode=0o600)
        index_manifest = encrypted_store.put_file(
            index_path,
            media_type=RECOVERY_PACKAGE_INDEX_MEDIA_TYPE,
        )
        root_recovery_kit = build_recovery_kit(root_key, recovery_secret)
        kit = {
            "format_version": RECOVERY_PACKAGE_KIT_FORMAT_VERSION,
            "package_id": package_id,
            "created_at": created_at,
            "backend_profile": backend.profile,
            "root_recovery_kit": _encode_base64(root_recovery_kit),
            "root_recovery_kit_sha256": hashlib.sha256(root_recovery_kit).hexdigest(),
            "package_index_manifest": index_manifest.as_dict(),
        }
        kit_payload = _canonical_json_bytes(kit)
        if len(kit_payload) > MAX_PACKAGE_KIT_BYTES:
            raise ValueError("recovery package kit exceeds its size limit")
        _write_new_private_file(destination, kit_payload, mode=0o600)

    package_kit_sha256 = hashlib.sha256(kit_payload).hexdigest()
    return {
        "status": "prepared",
        "created_at": created_at,
        "package_id": package_id,
        "package_kit_path": str(destination),
        "package_kit_sha256": package_kit_sha256,
        "backend_profile": backend.profile,
        "root_key_id": root_key.key_id,
        "snapshot_manifest_sha256": snapshot_result["snapshot_manifest_sha256"],
        "source_ledger_generation": source_generation,
        "encrypted_file_count": len(package_files),
        "ciphertext_object_count": len(package_files) + 1,
        "known_query_count": len(query_tuple),
    }


def restore_recovery_package(
    backend: ObjectBackend,
    package_kit: Path,
    recovery_secret: RecoveryKeyAccess,
    output: Path,
) -> dict[str, Any]:
    destination = output.expanduser()
    _require_absent(destination, "recovery output")
    _ensure_private_directory(destination.parent)
    kit_path = package_kit.expanduser()
    kit_payload = _read_private_package_kit(kit_path)

    with (
        tempfile.TemporaryDirectory(
            prefix=f".{destination.name}.restore-", dir=destination.parent
        ) as temporary_name,
        ExitStack() as stack,
    ):
        workspace = Path(temporary_name)
        workspace.chmod(0o700)
        _kit, root_key, encrypted_store, index_manifest, index = _load_package_material(
            backend,
            kit_payload,
            recovery_secret,
            workspace,
        )

        restored_snapshot = workspace / "restored-snapshot"
        restored_snapshot.mkdir(mode=0o700)
        file_count = _restore_package_files(
            encrypted_store,
            index,
            restored_snapshot,
            reserved_source_object_id=index_manifest.source_object_id,
            reserved_storage_object_id=index_manifest.storage_object_id,
            use_b2_io=isinstance(backend, B2S3ObjectBackend),
        )
        snapshot_result = verify_snapshot(restored_snapshot)
        if snapshot_result["snapshot_manifest_sha256"] != index["snapshot_manifest_sha256"]:
            raise RuntimeError("restored snapshot digest does not match the package index")
        restored_manifest = load_snapshot_manifest(restored_snapshot)
        expected_roles = {
            SNAPSHOT_MANIFEST: "snapshot_manifest",
            **{item["path"]: item["role"] for item in restored_manifest["files"]},
        }
        actual_roles = {item["path"]: item["role"] for item in index["files"]}
        if actual_roles != expected_roles:
            raise RuntimeError("recovery package file roles do not match the snapshot manifest")

        candidate_node, clone = stack.enter_context(
            staged_offline_clone(restored_snapshot, destination)
        )
        if clone["snapshot_ledger_generation"] != index["source_ledger_generation"]:
            raise RuntimeError("restored ledger generation does not match the package index")
        materialization = cast(StorageMaterialization | None, clone["storage_materialization"])
        original_clone_marker = restored_snapshot / OFFLINE_CLONE_MARKER
        candidate_clone_marker = candidate_node / OFFLINE_CLONE_MARKER
        if not original_clone_marker.is_file():
            candidate_clone_marker.unlink()
        elif materialization is None:
            # Replace only our disposable clone's 0400 marker, never the saved original.
            candidate_clone_marker.unlink()
            shutil.copy2(original_clone_marker, candidate_clone_marker)
            candidate_clone_marker.chmod(0o400)
        # A remapped offline source keeps its newly generated marker, not stale authorization.
        candidate_settings = Settings(candidate_node)
        ledger = Ledger(candidate_settings, read_only=True, require_checkpointed=False)
        restored_generation = ledger.generation_digest()
        if materialization is not None and (
            materialization["source_generation"] != index["source_ledger_generation"]
            or materialization["restored_generation"] != restored_generation
        ):
            raise RuntimeError("recovery storage materialization generation binding does not match")
        query_receipts = _verify_frozen_queries(ledger, index["known_queries"])
        if ledger.generation_digest() != restored_generation:
            raise RuntimeError("known-query replay changed the restored ledger generation")

        query_suite_sha256 = hashlib.sha256(_canonical_json_bytes(query_receipts)).hexdigest()
        package_kit_sha256 = hashlib.sha256(kit_payload).hexdigest()
        record_successful_backup(
            candidate_settings,
            created_at=index["created_at"],
            package_id=index["package_id"],
            package_kit_sha256=package_kit_sha256,
            snapshot_manifest_sha256=snapshot_result["snapshot_manifest_sha256"],
            source_ledger_generation=index["source_ledger_generation"],
            backend_profile=backend.profile,
        )
        restore_receipt = record_verified_restore(
            candidate_settings,
            verified_at=_now(),
            package_id=index["package_id"],
            package_kit_sha256=package_kit_sha256,
            snapshot_manifest_sha256=snapshot_result["snapshot_manifest_sha256"],
            source_ledger_generation=index["source_ledger_generation"],
            known_query_count=len(query_receipts),
            known_query_receipts_sha256=query_suite_sha256,
        )
        final_status = ledger.status()
        if materialization is not None:
            verify_storage_materialization_receipt(candidate_settings, materialization)
        publish_restored_node(candidate_node, destination)

    published_status = {
        **final_status,
        "database_path": str(Settings(destination).database_path),
    }
    return {
        "status": "verified",
        "package_id": index["package_id"],
        "package_kit_sha256": package_kit_sha256,
        "data_root": str(destination),
        "backend_profile": backend.profile,
        "root_key_id": root_key.key_id,
        "snapshot_manifest_sha256": snapshot_result["snapshot_manifest_sha256"],
        "source_ledger_generation": index["source_ledger_generation"],
        "restored_ledger_generation": restored_generation,
        "storage_materialization": materialization,
        "encrypted_file_count": file_count,
        "known_query_count": len(query_receipts),
        "known_query_receipts_sha256": query_suite_sha256,
        "status_receipt_sha256": restore_receipt["receipt_sha256"],
        "ledger_status": published_status,
    }


def _resume_recovery_package_publication(
    settings: Settings,
    backend: ObjectBackend,
    root_key: RootKey,
    recovery_secret: RecoveryKeyAccess,
    package_kit: Path,
    queries: Sequence[RecoveryQuery],
    *,
    snapshot_byte_limit: int | None = None,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    capture_generation: str | None = None,
) -> dict[str, Any]:
    kit_payload = _read_private_package_kit(package_kit)
    with tempfile.TemporaryDirectory(
        prefix=f".{package_kit.name}.resume-", dir=package_kit.parent
    ) as temporary_name:
        workspace = Path(temporary_name)
        workspace.chmod(0o700)
        kit, recovered_root_key, _, index_manifest, index = _load_package_material(
            backend,
            kit_payload,
            recovery_secret,
            workspace,
        )
        if recovered_root_key.key_id != root_key.key_id:
            raise RuntimeError("existing recovery package uses a different root key")
        if (
            capture_generation is not None
            and index["source_ledger_generation"] != capture_generation
        ):
            raise RuntimeError("existing recovery package uses a different capture generation")
        if snapshot_byte_limit is not None:
            manifests = [
                EncryptedObjectManifest.from_dict(item["encrypted_manifest"])
                for item in index["files"]
            ]
            if sum(item.plaintext_byte_length for item in manifests) > snapshot_byte_limit:
                raise RuntimeError("existing recovery package exceeds the restore payload budget")
        query_keys = set(queries[0].as_dict())
        frozen_queries = [
            {key: item[key] for key in query_keys}
            for item in cast(list[dict[str, object]], index["known_queries"])
        ]
        if frozen_queries != [query.as_dict() for query in queries]:
            raise RuntimeError("existing recovery package uses a different query suite")

        verification_output = workspace / "verified-node"
        verified = restore_recovery_package(
            backend,
            package_kit,
            recovery_secret,
            verification_output,
        )
        if capture_generation is not None:
            require_snapshot_privacy(Settings(verification_output).database_path)
            _require_current_capture_content(settings, Settings(verification_output))
        else:
            current_snapshot = workspace / "current-snapshot"
            create_snapshot(
                settings,
                current_snapshot,
                max_bytes=snapshot_byte_limit,
                encrypted_evidence_reader=encrypted_evidence_reader,
            )
            current_clone = workspace / "current-clone"
            clone = create_offline_clone(current_snapshot, current_clone)
            current_generation = clone["snapshot_ledger_generation"]
            if current_generation != verified["source_ledger_generation"]:
                raise RuntimeError("existing recovery package is not bound to the current ledger")
        if isinstance(backend, B2S3ObjectBackend):
            manifests = [
                EncryptedObjectManifest.from_dict(item["encrypted_manifest"])
                for item in index["files"]
            ] + [index_manifest]

            def reconcile(manifest: EncryptedObjectManifest) -> None:
                backend.reconcile_multipart(manifest.storage_object_id)

            _run_b2_object_io(manifests, reconcile)

    package_kit_sha256 = hashlib.sha256(kit_payload).hexdigest()
    backup_receipt = record_successful_backup(
        settings,
        created_at=cast(str, kit["created_at"]),
        package_id=cast(str, kit["package_id"]),
        package_kit_sha256=package_kit_sha256,
        snapshot_manifest_sha256=cast(str, index["snapshot_manifest_sha256"]),
        source_ledger_generation=cast(str, index["source_ledger_generation"]),
        backend_profile=backend.profile,
    )
    encrypted_file_count = cast(int, verified["encrypted_file_count"])
    return {
        "status": "resumed",
        "package_id": kit["package_id"],
        "package_kit_path": str(package_kit),
        "package_kit_sha256": package_kit_sha256,
        "backend_profile": backend.profile,
        "root_key_id": recovered_root_key.key_id,
        "snapshot_manifest_sha256": index["snapshot_manifest_sha256"],
        "source_ledger_generation": index["source_ledger_generation"],
        "encrypted_file_count": encrypted_file_count,
        "ciphertext_object_count": encrypted_file_count + 1,
        "known_query_count": len(queries),
        "status_receipt_sha256": backup_receipt["receipt_sha256"],
    }


def _require_current_capture_content(settings: Settings, captured: Settings) -> None:
    # A historical retry may omit newer admissions, never revive changed or removed content.
    # Restore materializes storage locations, so compare object identity separately from paths.
    tables = (
        "schema_migrations",
        "installations",
        "devices",
        "source_accounts",
        "contexts",
        "clients",
        "client_capabilities",
        "client_credentials",
        "client_devices",
        "device_enrollments",
        "source_account_policies",
        "source_schema_authorizations",
        "source_files",
        "source_streams",
        "source_segments",
        "source_records",
        "events_current",
        "event_corrections",
        "source_stream_access",
        "source_stream_contexts",
        "event_access",
        "event_contexts",
        "quarantines",
        "web_export_batches",
        "web_export_archive_members",
        "web_export_source_objects",
        "web_export_conversation_observations",
        "web_export_reconciled_events",
        "web_export_event_observations",
        "event_relations",
        "web_export_attachment_links",
        "web_export_attachment_objects",
        "memory_candidates",
        "memory_candidate_evidence_claims",
        "memory_candidate_evidence_links",
        "memory_candidate_access",
        "memory_candidate_contexts",
        "memory_candidate_proposal_receipts",
        "memory_candidate_review_transitions",
        "deletion_tombstones",
        "record_deletion_tombstones",
    )
    with closing(open_maintenance_inspection(settings)) as connection:
        connection.execute(
            "ATTACH DATABASE ? AS captured",
            (captured.database_path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1",),
        )
        connection.execute("BEGIN")
        if connection.execute("SELECT MAX(version) FROM main.schema_migrations").fetchone() != (
            connection.execute("SELECT MAX(version) FROM captured.schema_migrations").fetchone()
        ):
            raise RuntimeError("capture resume requires the same database schema")
        for table in tables:
            columns = "*"
            if table == "source_streams":
                # Ordinary admission changes this timestamp, not canonical stream identity.
                columns = ", ".join(
                    row[1]
                    for row in connection.execute("PRAGMA main.table_info(source_streams)")
                    if row[1] != "updated_at"
                )
            if connection.execute(
                f"SELECT 1 FROM (SELECT {columns} FROM captured.{table} "
                f"EXCEPT SELECT {columns} FROM main.{table}) LIMIT 1"
            ).fetchone():
                raise RuntimeError("retained capture content or access has changed; resume refused")
        columns = "object_id, plaintext_digest, byte_length, media_type, created_at"
        if connection.execute(
            f"SELECT 1 FROM (SELECT {columns} FROM captured.objects "
            f"EXCEPT SELECT {columns} FROM main.objects) LIMIT 1"
        ).fetchone():
            raise RuntimeError("retained capture objects have changed; resume refused")


def _load_package_material(
    backend: ObjectBackend,
    kit_payload: bytes,
    recovery_secret: RecoveryKeyAccess,
    workspace: Path,
) -> tuple[
    dict[str, Any],
    RootKey,
    EncryptedObjectStore,
    EncryptedObjectManifest,
    dict[str, Any],
]:
    kit = _load_package_kit(kit_payload)
    if kit["backend_profile"] != backend.profile:
        raise RuntimeError("recovery package backend profile does not match")
    root_kit = _decode_base64(kit["root_recovery_kit"], "root recovery kit")
    if hashlib.sha256(root_kit).hexdigest() != kit["root_recovery_kit_sha256"]:
        raise RuntimeError("root recovery kit digest does not match")
    root_key = restore_root_key_from_bytes(root_kit, recovery_secret)
    encrypted_store = EncryptedObjectStore(workspace / "encrypted-metadata", backend, root_key)
    index_manifest = EncryptedObjectManifest.from_dict(kit["package_index_manifest"])
    encrypted_store.register_manifest(index_manifest)
    _validate_index_manifest(index_manifest, backend.profile, root_key.key_id)
    index_path = workspace / "package-index.json"
    encrypted_store.restore_file(index_manifest.source_object_id, index_path)
    index_payload = _read_regular_file(index_path, MAX_PACKAGE_INDEX_BYTES)
    index = _load_package_index(index_payload)
    _validate_package_binding(kit, index, backend.profile, root_key.key_id)
    return kit, root_key, encrypted_store, index_manifest, index


def _encrypt_package_file(
    store: EncryptedObjectStore,
    source: Path,
    *,
    path: str,
    role: str,
) -> dict[str, object]:
    media_types = {
        "snapshot_manifest": "application/vnd.cross-assistant-memory.snapshot-manifest+json",
        "database": "application/vnd.sqlite3",
        "object": "application/octet-stream",
        "private_receipt": "application/json",
    }
    try:
        media_type = media_types[role]
    except KeyError as error:
        raise ValueError(f"unsupported recovery package file role: {role}") from error
    manifest = store.put_file(source, media_type=media_type)
    return {"path": path, "role": role, "encrypted_manifest": manifest.as_dict()}


def _freeze_queries(ledger: Ledger, queries: Sequence[RecoveryQuery]) -> list[dict[str, object]]:
    frozen: list[dict[str, object]] = []
    result_count = 0
    for query in queries:
        results = _run_query(ledger, query)
        result_count += len(results)
        frozen.append(
            {
                **query.as_dict(),
                "expected_event_ids": [item.event_id for item in results],
                "expected_results_sha256": _results_sha256(results),
            }
        )
    if result_count == 0:
        raise ValueError("recovery query suite must contain at least one matching result")
    return frozen


def _verify_frozen_queries(
    ledger: Ledger, values: list[dict[str, object]]
) -> list[dict[str, object]]:
    receipts: list[dict[str, object]] = []
    for value in values:
        query_fields = {
            key: value[key]
            for key in (
                "name",
                "query",
                "mode",
                "scopes",
                "project_id",
                "authorities",
                "limit",
            )
        }
        query = RecoveryQuery.from_dict(query_fields)
        results = _run_query(ledger, query)
        result_ids = [item.event_id for item in results]
        if result_ids != value["expected_event_ids"]:
            raise RuntimeError(f"known query result ids changed: {query.name}")
        result_digest = _results_sha256(results)
        if result_digest != value["expected_results_sha256"]:
            raise RuntimeError(f"known query result content changed: {query.name}")
        receipts.append(
            {
                "name_sha256": hashlib.sha256(query.name.encode()).hexdigest(),
                "result_count": len(results),
                "results_sha256": result_digest,
            }
        )
    return receipts


def _run_query(ledger: Ledger, query: RecoveryQuery) -> list[SearchResult]:
    return ledger.search(
        query.query,
        mode=query.mode,
        scopes=query.scopes,
        project_id=query.project_id,
        authorities=query.authorities,
        limit=query.limit,
        principal="local:recovery-verifier",
    )


def _results_sha256(results: Sequence[SearchResult]) -> str:
    stable: list[dict[str, Any]] = []
    for result in results:
        value = result.as_dict()
        value.pop("rank")
        stable.append(value)
    return hashlib.sha256(_canonical_json_bytes(stable)).hexdigest()


def _restore_package_files(
    store: EncryptedObjectStore,
    index: dict[str, Any],
    snapshot: Path,
    *,
    reserved_source_object_id: str,
    reserved_storage_object_id: str,
    use_b2_io: bool = False,
) -> int:
    seen_paths: set[str] = set()
    seen_source_ids = {reserved_source_object_id}
    seen_storage_ids = {reserved_storage_object_id}
    manifests: list[EncryptedObjectManifest] = []
    destinations: dict[str, tuple[Path, bool]] = {}
    for value in index["files"]:
        fields = cast(dict[str, object], value)
        path_value = cast(str, fields["path"])
        if path_value in seen_paths:
            raise ValueError("recovery package contains a duplicate file path")
        seen_paths.add(path_value)
        relative = _validated_relative_path(path_value)
        role = cast(str, fields["role"])
        manifest = EncryptedObjectManifest.from_dict(fields["encrypted_manifest"])
        _validate_payload_manifest(manifest, role)
        if manifest.source_object_id in seen_source_ids:
            raise ValueError("recovery package contains a duplicate source object id")
        if manifest.storage_object_id in seen_storage_ids:
            raise ValueError("recovery package contains a duplicate storage object id")
        seen_source_ids.add(manifest.source_object_id)
        seen_storage_ids.add(manifest.storage_object_id)
        destination = snapshot.joinpath(*relative.parts)
        parent = snapshot
        for part in relative.parts[:-1]:
            parent = parent / part
            _ensure_private_directory(parent)
        store.register_manifest(manifest)
        readonly = role == "private_receipt" and relative.parts[:-1] in {
            BACKUP_RECEIPT_ROOT.parts,
            RESTORE_RECEIPT_ROOT.parts,
            MATERIALIZATION_RECEIPT_ROOT.parts,
        }
        manifests.append(manifest)
        destinations[manifest.source_object_id] = destination, readonly

    def restore(manifest: EncryptedObjectManifest) -> None:
        destination, _ = destinations[manifest.source_object_id]
        store.restore_file(manifest.source_object_id, destination)

    def finish(manifest: EncryptedObjectManifest) -> None:
        destination, readonly = destinations[manifest.source_object_id]
        if readonly:
            destination.chmod(0o400)

    if use_b2_io:
        _run_b2_object_io(manifests, restore, after=finish)
    else:
        for manifest in manifests:
            restore(manifest)
            finish(manifest)
    return len(manifests)


def _validate_payload_manifest(manifest: EncryptedObjectManifest, role: str) -> None:
    expected_media_types = {
        "snapshot_manifest": "application/vnd.cross-assistant-memory.snapshot-manifest+json",
        "database": "application/vnd.sqlite3",
        "object": "application/octet-stream",
        "private_receipt": "application/json",
    }
    if role not in expected_media_types or manifest.media_type != expected_media_types[role]:
        raise ValueError("recovery package file media type does not match its role")
    if manifest.state != ObjectState.VERIFIED:
        raise ValueError("recovery package contains an unverified object manifest")
    if manifest.legacy_source_object_id is not None:
        raise ValueError("recovery package object manifest contains a legacy identifier")


def _load_package_kit(payload: bytes) -> dict[str, Any]:
    try:
        value: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("recovery package kit is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("recovery package kit must be an object")
    fields = cast(dict[object, object], value)
    expected = {
        "format_version",
        "package_id",
        "created_at",
        "backend_profile",
        "root_recovery_kit",
        "root_recovery_kit_sha256",
        "package_index_manifest",
    }
    if set(fields) != expected:
        raise ValueError("recovery package kit fields are invalid")
    if fields.get("format_version") != RECOVERY_PACKAGE_KIT_FORMAT_VERSION:
        raise ValueError("unsupported recovery package kit format")
    package_id = _required_str(fields, "package_id")
    if not _PACKAGE_ID.fullmatch(package_id):
        raise ValueError("recovery package id is invalid")
    _validate_timestamp(_required_str(fields, "created_at"))
    backend_profile = _required_str(fields, "backend_profile")
    if len(backend_profile) > 128:
        raise ValueError("recovery package backend profile is invalid")
    _validate_sha256(_required_str(fields, "root_recovery_kit_sha256"))
    if not isinstance(fields.get("package_index_manifest"), dict):
        raise ValueError("recovery package index manifest is invalid")
    return cast(dict[str, Any], value)


def _load_package_index(payload: bytes) -> dict[str, Any]:
    try:
        value: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("recovery package index is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("recovery package index must be an object")
    fields = cast(dict[object, object], value)
    expected = {
        "format_version",
        "package_id",
        "created_at",
        "backend_profile",
        "root_key_id",
        "snapshot_manifest_sha256",
        "source_ledger_generation",
        "files",
        "known_queries",
    }
    if set(fields) != expected:
        raise ValueError("recovery package index fields are invalid")
    if fields.get("format_version") != RECOVERY_PACKAGE_FORMAT_VERSION:
        raise ValueError("unsupported recovery package index format")
    package_id = _required_str(fields, "package_id")
    if not _PACKAGE_ID.fullmatch(package_id):
        raise ValueError("recovery package id is invalid")
    _validate_timestamp(_required_str(fields, "created_at"))
    _required_str(fields, "backend_profile")
    _required_str(fields, "root_key_id")
    _validate_sha256(_required_str(fields, "snapshot_manifest_sha256"))
    _validate_sha256(_required_str(fields, "source_ledger_generation"))
    files_value = fields.get("files")
    if not isinstance(files_value, list):
        raise ValueError("recovery package file list is invalid")
    raw_files = cast(list[object], files_value)
    if not 1 <= len(raw_files) <= MAX_PACKAGE_FILES:
        raise ValueError("recovery package file list is invalid")
    parsed_files: list[dict[str, object]] = []
    snapshot_manifest_entries = 0
    for item in raw_files:
        if not isinstance(item, dict):
            raise ValueError("recovery package file entry is invalid")
        item_fields = cast(dict[object, object], item)
        if set(item_fields) != {"path", "role", "encrypted_manifest"}:
            raise ValueError("recovery package file entry fields are invalid")
        path = _required_str(item_fields, "path")
        _validated_relative_path(path)
        role = _required_str(item_fields, "role")
        if role not in {"snapshot_manifest", "database", "object", "private_receipt"}:
            raise ValueError("recovery package file role is invalid")
        if not isinstance(item_fields.get("encrypted_manifest"), dict):
            raise ValueError("recovery package encrypted manifest is invalid")
        parsed = cast(dict[str, object], item)
        parsed_files.append(parsed)
        if role == "snapshot_manifest":
            snapshot_manifest_entries += 1
            if path != SNAPSHOT_MANIFEST:
                raise ValueError("recovery package snapshot manifest path is invalid")
    if snapshot_manifest_entries != 1:
        raise ValueError("recovery package must contain exactly one snapshot manifest")

    queries_value = fields.get("known_queries")
    if not isinstance(queries_value, list):
        raise ValueError("recovery package known-query list is invalid")
    raw_queries = cast(list[object], queries_value)
    if not 1 <= len(raw_queries) <= MAX_KNOWN_QUERIES:
        raise ValueError("recovery package known-query list is invalid")
    parsed_queries = [_load_frozen_query(item) for item in raw_queries]
    if not any(item["expected_event_ids"] for item in parsed_queries):
        raise ValueError("recovery package known queries contain no matching results")
    query_names = [cast(str, item["name"]) for item in parsed_queries]
    if len(query_names) != len(set(query_names)):
        raise ValueError("recovery package contains duplicate query names")
    loaded = cast(dict[str, Any], value)
    loaded["files"] = parsed_files
    loaded["known_queries"] = parsed_queries
    return loaded


def _load_frozen_query(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("frozen recovery query must be an object")
    fields = cast(dict[object, object], value)
    query_keys = {
        "name",
        "query",
        "mode",
        "scopes",
        "project_id",
        "authorities",
        "limit",
    }
    if set(fields) != query_keys | {"expected_event_ids", "expected_results_sha256"}:
        raise ValueError("frozen recovery query fields are invalid")
    query = RecoveryQuery.from_dict({key: fields[key] for key in query_keys})
    expected_ids = fields.get("expected_event_ids")
    if not isinstance(expected_ids, list):
        raise ValueError("frozen recovery query event ids are invalid")
    raw_expected_ids = cast(list[object], expected_ids)
    if not all(isinstance(item, str) and item for item in raw_expected_ids):
        raise ValueError("frozen recovery query event ids are invalid")
    parsed_expected_ids = cast(list[str], raw_expected_ids)
    if len(parsed_expected_ids) > query.limit or len(parsed_expected_ids) != len(
        set(parsed_expected_ids)
    ):
        raise ValueError("frozen recovery query event ids are invalid")
    expected_digest = _required_str(fields, "expected_results_sha256")
    _validate_sha256(expected_digest)
    loaded = cast(dict[str, object], value)
    loaded["expected_event_ids"] = parsed_expected_ids
    return loaded


def _validate_index_manifest(
    manifest: EncryptedObjectManifest, backend_profile: str, root_key_id: str
) -> None:
    if manifest.plaintext_byte_length > MAX_PACKAGE_INDEX_BYTES:
        raise ValueError("recovery package index exceeds its size limit")
    if manifest.state != ObjectState.VERIFIED:
        raise ValueError("recovery package index is not verified")
    if manifest.backend_profile != backend_profile or manifest.root_key_id != root_key_id:
        raise ValueError("recovery package index key or backend does not match")
    if manifest.media_type != RECOVERY_PACKAGE_INDEX_MEDIA_TYPE:
        raise ValueError("recovery package index media type is invalid")
    if manifest.legacy_source_object_id is not None:
        raise ValueError("recovery package index contains a legacy identifier")


def _validate_package_binding(
    kit: dict[str, Any],
    index: dict[str, Any],
    backend_profile: str,
    root_key_id: str,
) -> None:
    if kit["package_id"] != index["package_id"] or kit["created_at"] != index["created_at"]:
        raise RuntimeError("recovery package kit does not match its encrypted index")
    if index["backend_profile"] != backend_profile or index["root_key_id"] != root_key_id:
        raise RuntimeError("recovery package index key or backend does not match")


def _validate_queries(queries: Sequence[RecoveryQuery]) -> None:
    if not 1 <= len(queries) <= MAX_KNOWN_QUERIES:
        raise ValueError("at least one bounded recovery query is required")
    names = [item.name for item in queries]
    if len(names) != len(set(names)):
        raise ValueError("recovery query names must be unique")


def _required_str(value: dict[object, object], key: str, *, allow_empty: bool = False) -> str:
    item = value.get(key)
    if not isinstance(item, str) or (not allow_empty and not item):
        raise ValueError(f"{key} is invalid")
    return item


def _required_int(value: dict[object, object], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise ValueError(f"{key} is invalid")
    return item


def _list_str(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is invalid")
    return value


def _validated_relative_path(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or "\\" in value
        or "\0" in value
    ):
        raise ValueError(f"unsafe recovery package path: {value}")
    return relative


def _validate_sha256(value: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ValueError("SHA-256 value is invalid")


def _validate_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is invalid")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as error:
        raise ValueError(f"{label} is invalid") from error


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode()


def _require_absent(path: Path, label: str) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"{label} already exists: {path}")


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"private directory must not be a symlink: {path}")
    existed = path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not existed:
        path.chmod(0o700)
    metadata = path.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RuntimeError(f"private directory is accessible by another user: {path}")


def _write_new_private_file(path: Path, payload: bytes, *, mode: int) -> None:
    _ensure_private_directory(path.parent)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.partial"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(temporary, flags, mode)
    staged_identity: os.stat_result | None = None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            os.fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            staged_identity = os.fstat(handle.fileno())
        publish_file_no_replace(
            temporary,
            path,
            required_mode=mode,
            label="private file",
        )
    except FileExistsError:
        temporary.unlink(missing_ok=True)
        _fsync_directory(path.parent)
        raise
    except BaseException as error:
        _cleanup_failed_file_publication(
            temporary,
            path,
            path.parent,
            staged_identity,
            error,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _cleanup_failed_file_publication(
    temporary: Path,
    target: Path,
    parent: Path,
    staged_identity: os.stat_result | None,
    error: BaseException,
) -> None:
    cleanup_error: BaseException | None = None
    try:
        temporary.unlink(missing_ok=True)
        if staged_identity is not None:
            try:
                target_identity = target.lstat()
            except FileNotFoundError:
                target_identity = None
            if target_identity is not None and (
                target_identity.st_dev,
                target_identity.st_ino,
            ) == (staged_identity.st_dev, staged_identity.st_ino):
                target.unlink()
        _fsync_directory(parent)
    except BaseException as caught:
        cleanup_error = caught
    if cleanup_error is not None:
        raise RuntimeError("failed private-file publication could not be cleaned") from error
    raise error


def _read_regular_file(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"file is unavailable: {path}") from error
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError(f"file is unavailable: {path}")
        if details.st_size > limit:
            raise ValueError(f"file exceeds its size limit: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(limit + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > limit:
        raise ValueError(f"file exceeds its size limit: {path}")
    return payload


def _read_private_package_kit(path: Path) -> bytes:
    normalized = Path(os.path.abspath(path.expanduser()))
    parent_descriptor = open_directory_no_symlinks(
        normalized.parent,
        "recovery package kit parent",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(normalized.name, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise ValueError(
            "recovery package kit must be a regular file without symlink components"
        ) from error
    finally:
        os.close(parent_descriptor)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_PACKAGE_KIT_BYTES
        ):
            raise ValueError(
                "recovery package kit must be an owner-only single-link private regular file"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(MAX_PACKAGE_KIT_BYTES + 1)
            after = os.fstat(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > MAX_PACKAGE_KIT_BYTES:
        raise ValueError(f"file exceeds its size limit: {normalized}")

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if len(payload) != before.st_size or identity(before) != identity(after):
        raise RuntimeError("recovery package kit changed while reading")
    return payload


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _filesystem_backend(path: Path) -> FilesystemObjectBackend:
    return FilesystemObjectBackend(path.expanduser())


def _now() -> str:
    return datetime.now(UTC).isoformat()
