from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import uuid
from collections.abc import Generator
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict, cast

from cross_assistant_memory.config import Settings, default_data_root
from cross_assistant_memory.encrypted_objects import EncryptedObjectManifest, ObjectState
from cross_assistant_memory.evidence_locations import (
    EncryptedEvidenceReader,
    read_location,
    require_local_object_operations,
)
from cross_assistant_memory.evidence_publication import require_mapping_state
from cross_assistant_memory.evidence_rotation import require_rotation_access, rotation_present
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
    publish_directory_no_replace,
    remove_owned_directory_at,
)
from cross_assistant_memory.snapshot_materialization import (
    MATERIALIZATION_RECEIPT_ROOT,
    materialize_verified_snapshot,
    verify_storage_materialization_receipt,
)
from cross_assistant_memory.storage import (
    LEGACY_RECOVERY_SCHEMA_VERSIONS,
    SCHEMA_VERSION,
    Ledger,
    legacy_snapshot_generation,
    maintenance_generation,
    open_maintenance_inspection,
    validate_current_schema_objects,
    validate_schema20_objects,
    validate_schema21_objects,
    validate_schema22_objects,
    validate_schema23_objects,
)

SNAPSHOT_FORMAT_VERSION = 1
SNAPSHOT_MANIFEST = "snapshot-manifest.json"
COPY_CHUNK_BYTES = 1024 * 1024
SNAPSHOT_BACKUP_PAGE_BATCH = 64
OFFLINE_CLONE_FORMAT_VERSION = 1
OFFLINE_CLONE_MARKER = Path("runs/private/web-export-offline-clone.json")
MAX_OFFLINE_CLONE_MARKER_BYTES = 64 * 1024
WEB_SOURCE_CONFIGURATION_RECEIPT = Path("runs/private/web-source-configuration.json")


class SnapshotFile(TypedDict):
    path: str
    role: str
    size: int
    sha256: str


class SnapshotState(TypedDict):
    schema_version: int
    database_counts: dict[str, int]
    object_count: int
    private_receipt_count: int


class SnapshotManifest(TypedDict):
    snapshot_format_version: int
    created_at: str
    source_state: SnapshotState
    files: list[SnapshotFile]


@dataclass(frozen=True)
class _SnapshotObject:
    object_id: str
    byte_length: int
    location: tuple[str, EncryptedObjectManifest] | None


def create_web_source_configuration_snapshot(
    settings: Settings,
    output: Path,
    *,
    source_account_id: str,
    expected_ledger_generation: str,
    max_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Create a content-free offline validation seed, not a recovery backup."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("snapshot max_bytes must be positive")
    source = settings.data_root
    destination = output
    for path in (source, destination):
        if not path.is_absolute() or ".." in path.parts or path != path.resolve():
            raise ValueError("configuration snapshot paths must be absolute without aliases")
    if destination.is_relative_to(source):
        raise ValueError("configuration snapshot output must be outside the source root")
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"snapshot output already exists: {destination}")
    for path in (
        source,
        source / "objects",
        settings.object_root,
        settings.run_root,
        destination.parent,
    ):
        descriptor = open_directory_no_symlinks(path, "configuration snapshot directory")
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("configuration snapshot directories must be owned and private")
        finally:
            os.close(descriptor)
    with ExitStack() as handles:
        parent_descriptor = open_directory_no_symlinks(
            destination.parent, "configuration snapshot parent"
        )
        handles.callback(os.close, parent_descriptor)
        parent_identity = os.fstat(parent_descriptor)
        descriptor, _ = open_regular_file_no_symlinks(
            settings.database_path, "configuration source database"
        )
        handles.callback(os.close, descriptor)
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("configuration source database must be private and single-link")
        ledger = Ledger(settings, read_only=True, require_checkpointed=False)
        with ledger.temporary_web_source_configuration(
            source_account_id=source_account_id,
            expected_ledger_generation=expected_ledger_generation,
        ) as (configuration, identity):
            snapshot_generation = Ledger(configuration, read_only=True).generation_digest()
            receipt = {
                "configuration_only": True,
                "purpose": "offline_web_schema_validation",
                **identity,
                "snapshot_ledger_generation": snapshot_generation,
            }
            _write_private_json(configuration.data_root / WEB_SOURCE_CONFIGURATION_RECEIPT, receipt)
            candidate = configuration.data_root.parent / "snapshot"
            scratch_descriptor = open_directory_no_symlinks(candidate.parent, "review scratch")
            owned: os.stat_result | None = None
            try:
                created, owned = _create_snapshot(
                    configuration,
                    candidate,
                    max_bytes=max_bytes,
                    parent_descriptor=scratch_descriptor,
                )
                if not os.path.samestat(
                    owned,
                    os.stat(candidate.name, dir_fd=scratch_descriptor, follow_symlinks=False),
                ):
                    raise RuntimeError("configuration snapshot identity changed")
                verified = verify_snapshot(candidate)
                if verified["snapshot_manifest_sha256"] != created["snapshot_manifest_sha256"]:
                    raise RuntimeError("configuration snapshot manifest changed")
                _publish_configuration_snapshot(
                    candidate,
                    destination,
                    parent_descriptor,
                    parent_identity,
                    str(created["snapshot_manifest_sha256"]),
                    max_bytes,
                )
            finally:
                try:
                    if owned is not None:
                        remove_owned_directory_at(scratch_descriptor, candidate.name, owned)
                finally:
                    os.close(scratch_descriptor)
    return {
        **verified,
        "status": "created",
        "configuration_only": True,
        "snapshot_path": str(destination),
        **identity,
        "snapshot_ledger_generation": snapshot_generation,
    }


def _publish_configuration_snapshot(
    source: Path,
    destination: Path,
    parent: int,
    parent_identity: os.stat_result,
    manifest_digest: str,
    max_bytes: int,
) -> None:
    # Only these two metadata files may cross from scratch into the caller's directory.
    checked_parent = open_directory_no_symlinks(destination.parent, "configuration output parent")
    try:
        if not os.path.samestat(parent_identity, os.fstat(checked_parent)):
            raise RuntimeError("configuration output parent identity changed")
    finally:
        os.close(checked_parent)
    manifest, digest = _load_manifest(source / SNAPSHOT_MANIFEST)
    expected = {"ledger.sqlite3", WEB_SOURCE_CONFIGURATION_RECEIPT.as_posix()}
    if digest != manifest_digest or {item["path"] for item in manifest["files"]} != expected:
        raise RuntimeError("configuration snapshot manifest changed")
    payloads: dict[str, bytes] = {}
    remaining = max_bytes
    entries = [*manifest["files"], {"path": SNAPSHOT_MANIFEST, "sha256": digest}]
    for entry in entries:
        descriptor, _ = open_regular_file_no_symlinks(source / entry["path"], "configuration file")
        with os.fdopen(descriptor, "rb") as stream:
            data = stream.read(remaining + 1)
        remaining -= len(data)
        if remaining < 0 or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise RuntimeError("configuration snapshot bytes changed or exceed max_bytes")
        payloads[entry["path"]] = data
    name = f".{destination.name}.candidate-{uuid.uuid4().hex}"
    os.mkdir(name, mode=0o700, dir_fd=parent)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(name, flags, dir_fd=parent)
    identity = os.fstat(descriptor)
    try:
        with ExitStack() as handles:
            os.mkdir("runs", mode=0o700, dir_fd=descriptor)
            runs = os.open("runs", flags, dir_fd=descriptor)
            handles.callback(os.close, runs)
            os.mkdir("private", mode=0o700, dir_fd=runs)
            private = os.open("private", flags, dir_fd=runs)
            handles.callback(os.close, private)
            for path, data in payloads.items():
                target = (
                    private if path == WEB_SOURCE_CONFIGURATION_RECEIPT.as_posix() else descriptor
                )
                file_descriptor = os.open(
                    Path(path).name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=target,
                )
                with os.fdopen(file_descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            for directory in (private, runs, descriptor):
                os.fsync(directory)
        copied = verify_snapshot(destination.parent / name)
        if copied["snapshot_manifest_sha256"] != manifest_digest:
            raise RuntimeError("configuration snapshot copy changed")
        publish_restored_node(
            destination.parent / name,
            destination,
            expected_identity=identity,
            expected_parent_identity=parent_identity,
        )
    finally:
        os.close(descriptor)
        remove_owned_directory_at(parent, name, identity)


def create_snapshot(
    settings: Settings,
    output: Path,
    *,
    max_bytes: int | None = None,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
) -> dict[str, Any]:
    result, _identity = _create_snapshot(
        settings, output, max_bytes=max_bytes, encrypted_evidence_reader=encrypted_evidence_reader
    )
    return result


def _create_snapshot(
    settings: Settings,
    output: Path,
    *,
    max_bytes: int | None = None,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    parent_descriptor: int | None = None,
) -> tuple[dict[str, Any], os.stat_result]:
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes <= 0):
        raise ValueError("snapshot max_bytes must be positive")
    remaining = max_bytes
    destination = output.expanduser()
    _require_private_source(settings)
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"snapshot output already exists: {destination}")
    if parent_descriptor is None:
        _ensure_private_directory(destination.parent)
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
        )
        identity = temporary.stat()
    else:
        name = f".{destination.name}.tmp-{uuid.uuid4().hex}"
        os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        identity = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        temporary = destination.parent / name
    try:
        if parent_descriptor is not None:
            checked_parent = open_directory_no_symlinks(destination.parent, "snapshot parent")
            try:
                if not os.path.samestat(os.fstat(parent_descriptor), os.fstat(checked_parent)):
                    raise RuntimeError("snapshot parent identity changed")
            finally:
                os.close(checked_parent)
        database_target = temporary / "ledger.sqlite3"
        if remaining is None:
            _backup_database(settings.database_path, database_target)
        else:
            _backup_database(settings.database_path, database_target, max_bytes=remaining)
        require_snapshot_privacy(database_target)
        database_state = _database_state(database_target)
        files = [_file_entry(database_target, temporary, "database")]
        remaining = _remaining_snapshot_bytes(remaining, files[0]["size"])

        registered_objects = _registered_objects(database_target)
        private_receipts = _copy_private_receipts(settings, temporary, max_bytes=remaining)
        remaining = _remaining_snapshot_bytes(
            remaining, sum(item["size"] for item in private_receipts)
        )
        files.extend(private_receipts)
        manifest_bytes = _planned_snapshot_manifest(database_state, files, registered_objects)
        remaining = _remaining_snapshot_bytes(remaining, len(manifest_bytes))
        source_generation = _copy_snapshot_objects(
            settings, temporary, registered_objects, remaining, encrypted_evidence_reader
        )
        manifest_path = temporary / SNAPSHOT_MANIFEST
        manifest_path.write_bytes(manifest_bytes)
        manifest_path.chmod(0o600)
        verified = verify_snapshot(temporary)
        _require_unchanged_snapshot_source(settings, source_generation)
        if parent_descriptor is None:
            temporary.rename(destination)
        else:
            _normalize_private_directories(temporary)
            publish_restored_node(
                temporary,
                destination,
                expected_identity=identity,
                expected_parent_identity=os.fstat(parent_descriptor),
            )
    except BaseException:
        if parent_descriptor is None:
            shutil.rmtree(temporary, ignore_errors=True)
        else:
            remove_owned_directory_at(parent_descriptor, temporary.name, identity)
        raise
    return {**verified, "status": "created", "snapshot_path": str(destination)}, identity


def create_portable_snapshot(
    settings: Settings,
    output: Path,
    *,
    max_bytes: int | None = None,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
) -> dict[str, Any]:
    """Create a credential-free snapshot suitable for an encrypted portable export."""
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes <= 0):
        raise ValueError("snapshot max_bytes must be positive")
    remaining = max_bytes
    destination = output.expanduser()
    _require_private_source(settings)
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"portable snapshot output already exists: {destination}")
    _ensure_private_directory(destination.parent)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    temporary.chmod(0o700)
    try:
        database_target = temporary / "ledger.sqlite3"
        _backup_database(settings.database_path, database_target, max_bytes=remaining)
        require_snapshot_privacy(database_target)
        source_generation = _snapshot_database_generation(Settings(temporary))
        _sanitize_portable_database(database_target)
        portable_generation = _snapshot_database_generation(Settings(temporary))
        if portable_generation != source_generation:
            raise RuntimeError("portable snapshot sanitization changed the ledger generation")
        database_state = _database_state(database_target)
        files = [_file_entry(database_target, temporary, "database")]
        remaining = _remaining_snapshot_bytes(remaining, files[0]["size"])

        registered_objects = _registered_objects(database_target)
        manifest_bytes = _planned_snapshot_manifest(database_state, files, registered_objects)
        remaining = _remaining_snapshot_bytes(remaining, len(manifest_bytes))
        captured_generation = _copy_snapshot_objects(
            settings, temporary, registered_objects, remaining, encrypted_evidence_reader
        )
        manifest_path = temporary / SNAPSHOT_MANIFEST
        manifest_path.write_bytes(manifest_bytes)
        manifest_path.chmod(0o600)
        verified = verify_snapshot(temporary)
        _verify_portable_snapshot_omissions(database_target, verified)
        _require_unchanged_snapshot_source(settings, captured_generation)
        temporary.rename(destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {
        **verified,
        "status": "created",
        "snapshot_path": str(destination),
        "source_ledger_generation": source_generation,
    }


def verify_snapshot(snapshot: Path) -> dict[str, Any]:
    root = snapshot.expanduser()
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"snapshot must be a regular directory: {root}")
    manifest_path = root / SNAPSHOT_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError(f"snapshot manifest is missing: {manifest_path}")
    manifest, manifest_sha256 = _load_manifest(manifest_path)

    expected_paths: set[str] = set()
    database_entries: list[SnapshotFile] = []
    total_bytes = 0
    for item in manifest["files"]:
        relative = _validated_relative_path(item["path"])
        if item["path"] in expected_paths:
            raise ValueError(f"duplicate snapshot path: {item['path']}")
        expected_paths.add(item["path"])
        path = root.joinpath(*relative.parts)
        size, digest = _hash_regular_file(path, expected_size=item["size"])
        if size != item["size"] or digest != item["sha256"]:
            raise RuntimeError(f"snapshot file failed hash verification: {item['path']}")
        total_bytes += size
        if item["role"] == "database":
            database_entries.append(item)

    actual_paths = _snapshot_file_paths(root)
    if actual_paths != expected_paths:
        missing = sorted(expected_paths - actual_paths)
        unexpected = sorted(actual_paths - expected_paths)
        raise RuntimeError(
            "snapshot manifest does not match files: "
            f"missing={missing[:3]} unexpected={unexpected[:3]}"
        )
    if len(database_entries) != 1:
        raise ValueError("snapshot must contain exactly one database")

    database_relative = _validated_relative_path(database_entries[0]["path"])
    database_path = root.joinpath(*database_relative.parts)
    database_state = _database_state(database_path)
    source_state = manifest["source_state"]
    if database_state["schema_version"] != source_state["schema_version"]:
        raise RuntimeError("restored database schema version does not match the manifest")
    if database_state["counts"] != source_state["database_counts"]:
        raise RuntimeError("restored database counts do not match the manifest")

    registered_objects = _registered_objects(database_path)
    object_entries = {item["path"]: item for item in manifest["files"] if item["role"] == "object"}
    if len(registered_objects) != source_state["object_count"]:
        raise RuntimeError("restored database object count does not match the manifest")
    if set(registered_objects) != set(object_entries):
        raise RuntimeError("restored object set does not match the database")
    for relative, registered in registered_objects.items():
        item = object_entries[relative]
        if (
            item["sha256"] != registered.object_id.removeprefix("sha256:")
            or item["size"] != registered.byte_length
        ):
            raise RuntimeError(f"restored object metadata does not match: {registered.object_id}")

    private_receipt_count = sum(item["role"] == "private_receipt" for item in manifest["files"])
    if private_receipt_count != source_state["private_receipt_count"]:
        raise RuntimeError("restored private receipt count does not match the manifest")
    if _hash_regular_file(manifest_path)[1] != manifest_sha256:
        raise RuntimeError("snapshot manifest changed during verification")
    return {
        "status": "verified",
        "snapshot_manifest_sha256": manifest_sha256,
        "file_count": len(manifest["files"]),
        "total_bytes": total_bytes,
        "schema_version": database_state["schema_version"],
        "database_counts": database_state["counts"],
        "object_count": len(registered_objects),
        "encrypted_object_count": sum(
            item.location is not None for item in registered_objects.values()
        ),
        "private_receipt_count": private_receipt_count,
    }


def load_snapshot_manifest(snapshot: Path) -> SnapshotManifest:
    root = snapshot.expanduser()
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"snapshot must be a regular directory: {root}")
    manifest_path = root / SNAPSHOT_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError(f"snapshot manifest is missing: {manifest_path}")
    manifest, _ = _load_manifest(manifest_path)
    return manifest


def create_offline_clone(snapshot: Path, output: Path) -> dict[str, Any]:
    source = snapshot.expanduser()
    verified_snapshot = verify_snapshot(source)
    manifest, manifest_sha256 = _load_manifest(source / SNAPSHOT_MANIFEST)
    if manifest_sha256 != verified_snapshot["snapshot_manifest_sha256"]:
        raise RuntimeError("snapshot manifest changed after verification")
    destination = output.expanduser()
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"offline clone output already exists: {destination}")
    if destination.resolve() == default_data_root().resolve():
        raise ValueError("offline clone output cannot be the default live data root")
    _ensure_private_directory(destination.parent)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    temporary.chmod(0o700)
    try:
        for child in source.iterdir():
            if child.name == SNAPSHOT_MANIFEST:
                continue
            target = temporary / child.name
            if child.is_dir():
                shutil.copytree(child, target, copy_function=shutil.copy2)
            elif child.is_file():
                shutil.copy2(child, target)
            else:  # pragma: no cover - verify_snapshot rejects this first
                raise RuntimeError(f"snapshot contains an unsupported entry: {child}")

        _normalize_private_directories(temporary)
        _verify_offline_clone_files(temporary, manifest)
        clone_settings = Settings(temporary)
        _ensure_private_directory(clone_settings.object_root)
        _ensure_private_directory(clone_settings.run_root)
        # Normalize only the verified unpublished copy; older artifacts may retain a WAL header.
        with closing(sqlite3.connect(clone_settings.database_path)) as connection:
            connection.execute("PRAGMA locking_mode=EXCLUSIVE").fetchall()
            connection.execute("PRAGMA journal_mode=DELETE").fetchall()
        source_schema_version = cast(int, verified_snapshot["schema_version"])
        if source_schema_version in LEGACY_RECOVERY_SCHEMA_VERSIONS:
            Ledger(clone_settings, allow_schema_upgrade=True)
        elif source_schema_version != SCHEMA_VERSION:
            supported = ", ".join(
                str(item) for item in sorted(LEGACY_RECOVERY_SCHEMA_VERSIONS | {SCHEMA_VERSION})
            )
            raise RuntimeError(
                "offline clone supports snapshot schemas "
                f"{supported}; found {source_schema_version}"
            )
        snapshot_generation = Ledger(
            clone_settings, read_only=True, require_checkpointed=False
        ).generation_digest(schema_version=source_schema_version)
        materialization = (
            materialize_verified_snapshot(
                clone_settings,
                snapshot_manifest_sha256=verified_snapshot["snapshot_manifest_sha256"],
                snapshot_generation=snapshot_generation,
                snapshot_schema_version=source_schema_version,
            )
            if verified_snapshot["encrypted_object_count"]
            else None
        )
        clone_status = Ledger(clone_settings, read_only=True, require_checkpointed=False).status()
        marker = {
            "offline_clone_format_version": OFFLINE_CLONE_FORMAT_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "source_snapshot_path": str(source.resolve()),
            "source_snapshot_manifest_sha256": verified_snapshot["snapshot_manifest_sha256"],
            "source_ledger_generation": clone_status["generation_digest"],
        }
        marker_path = temporary / OFFLINE_CLONE_MARKER
        marker_path.unlink(missing_ok=True)
        _write_private_json(marker_path, marker)
        final_status = Ledger(
            Settings(temporary), read_only=True, require_checkpointed=False
        ).status()
        if final_status["generation_digest"] != clone_status["generation_digest"]:
            raise RuntimeError("offline clone generation changed during finalization")
        if materialization is not None:
            verify_storage_materialization_receipt(clone_settings, materialization)
        marker_sha256 = _sha256_file(marker_path)
        publish_restored_node(temporary, destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    final_marker = destination / OFFLINE_CLONE_MARKER
    published_status = {
        **final_status,
        "database_path": str(Settings(destination).database_path),
    }
    return {
        "status": "created",
        "data_root": str(destination),
        "marker_path": str(final_marker),
        "marker_sha256": marker_sha256,
        "source_snapshot_manifest_sha256": verified_snapshot["snapshot_manifest_sha256"],
        "source_ledger_generation": clone_status["generation_digest"],
        "snapshot_ledger_generation": snapshot_generation,
        "storage_materialization": materialization,
        "ledger_status": published_status,
    }


@contextmanager
def staged_offline_clone(
    snapshot: Path, destination: Path
) -> Generator[tuple[Path, dict[str, Any]], None, None]:
    candidate = destination.with_name(f".{destination.name}.candidate-{uuid.uuid4().hex}")
    clone = create_offline_clone(snapshot, candidate)
    identity = candidate.stat()
    try:
        yield candidate, clone
    finally:
        if candidate.exists() and not candidate.is_symlink():
            retained = candidate.stat()
            if (retained.st_dev, retained.st_ino) == (identity.st_dev, identity.st_ino):
                shutil.rmtree(candidate)


def verify_offline_clone_marker(
    settings: Settings,
    *,
    expected_ledger_generation: str,
) -> dict[str, Any]:
    if settings.data_root.expanduser().resolve() == default_data_root().resolve():
        raise ValueError("the default live data root cannot be an offline clone")
    if settings.data_root.is_symlink() or not settings.data_root.is_dir():
        raise ValueError(f"offline clone root is unavailable: {settings.data_root}")
    clone_database = settings.database_path
    if clone_database.is_symlink():
        raise ValueError("offline clone database must not be a symlink")
    try:
        clone_database_details = clone_database.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"offline clone database is missing: {clone_database}") from exc
    if not stat.S_ISREG(clone_database_details.st_mode):
        raise ValueError("offline clone database must be a regular file")
    if clone_database_details.st_nlink != 1:
        raise ValueError("offline clone database must have exactly one hard link")
    live_database = Settings(default_data_root()).database_path
    if live_database.exists() and not live_database.is_symlink():
        live_database_details = live_database.lstat()
        if stat.S_ISREG(live_database_details.st_mode) and os.path.samestat(
            clone_database_details,
            live_database_details,
        ):
            raise ValueError("offline clone database must not share the live database inode")
    marker_path = settings.data_root / OFFLINE_CLONE_MARKER
    try:
        descriptor = os.open(
            marker_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError as exc:
        raise ValueError(f"offline clone marker is missing: {marker_path}") from exc
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("offline clone marker must be a regular file")
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077:
            raise RuntimeError("offline clone marker is not private to the current user")
        if before.st_size > MAX_OFFLINE_CLONE_MARKER_BYTES:
            raise ValueError("offline clone marker exceeds its size limit")
        marker_bytes = handle.read(MAX_OFFLINE_CLONE_MARKER_BYTES + 1)
        after = os.fstat(handle.fileno())
    if len(marker_bytes) > MAX_OFFLINE_CLONE_MARKER_BYTES:
        raise ValueError("offline clone marker exceeds its size limit")
    if len(marker_bytes) != before.st_size or _stat_identity(before) != _stat_identity(after):
        raise RuntimeError("offline clone marker changed while it was read")
    loaded: object = json.loads(marker_bytes)
    if not isinstance(loaded, dict):
        raise ValueError("offline clone marker must contain an object")
    marker = cast(dict[str, Any], loaded)
    expected_keys = {
        "offline_clone_format_version",
        "created_at",
        "source_snapshot_path",
        "source_snapshot_manifest_sha256",
        "source_ledger_generation",
    }
    if set(marker) != expected_keys:
        raise ValueError("offline clone marker structure is invalid")
    if marker.get("offline_clone_format_version") != OFFLINE_CLONE_FORMAT_VERSION:
        raise ValueError("unsupported offline clone marker version")
    source_generation = marker.get("source_ledger_generation")
    if source_generation != expected_ledger_generation:
        raise RuntimeError("offline clone marker does not bind the approved ledger generation")
    snapshot_digest = marker.get("source_snapshot_manifest_sha256")
    if not isinstance(snapshot_digest, str) or not _is_sha256(snapshot_digest):
        raise ValueError("offline clone marker snapshot digest is invalid")
    source_path = marker.get("source_snapshot_path")
    if not isinstance(source_path, str) or not Path(source_path).is_absolute():
        raise ValueError("offline clone marker source path is invalid")
    created_at = marker.get("created_at")
    if not isinstance(created_at, str) or not created_at:
        raise ValueError("offline clone marker creation time is invalid")
    return {
        "marker_path": str(marker_path),
        "marker_sha256": hashlib.sha256(marker_bytes).hexdigest(),
        "source_snapshot_manifest_sha256": snapshot_digest,
        "source_ledger_generation": source_generation,
    }


def _require_private_source(settings: Settings) -> None:
    for path in (settings.data_root, settings.object_root, settings.run_root):
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"private data directory is unavailable: {path}")
    if settings.database_path.is_symlink() or not settings.database_path.is_file():
        raise ValueError(f"ledger database is unavailable: {settings.database_path}")


def _remaining_snapshot_bytes(remaining: int | None, size: int) -> int | None:
    if remaining is None:
        return None
    if size > remaining:
        raise RuntimeError("snapshot exceeds max_bytes budget")
    return remaining - size


def snapshot_source_generation(settings: Settings) -> str:
    """Read under the caller's writer lease using only an existing, complete sidecar set."""
    _require_private_source(settings)
    source = settings.database_path
    sidecars = _snapshot_source_sidecars(source)
    before = _snapshot_source_stamp(settings)
    generation = _snapshot_database_generation(settings, require_checkpointed=not sidecars)
    if sidecars != _snapshot_source_sidecars(source) or before != _snapshot_source_stamp(settings):
        raise RuntimeError("snapshot source changed while reading its generation")
    return generation


def _snapshot_database_generation(settings: Settings, *, require_checkpointed: bool = True) -> str:
    with closing(
        open_maintenance_inspection(settings, require_checkpointed=require_checkpointed)
    ) as connection:
        connection.execute("BEGIN")
        version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        if version == SCHEMA_VERSION:
            validate_current_schema_objects(connection)
            require_rotation_access(connection, settings)
            return maintenance_generation(connection)
        if version in {20, 21, 22, 23}:
            if version >= 21:
                require_rotation_access(connection, settings)
            return legacy_snapshot_generation(connection)
    return Ledger(
        settings, read_only=True, require_checkpointed=require_checkpointed
    ).generation_digest()


def _backup_database(source: Path, destination: Path, *, max_bytes: int | None = None) -> None:
    sidecars_before = _snapshot_source_sidecars(source)
    before = source.stat()
    query = "?mode=ro&immutable=1" if not sidecars_before else "?mode=ro"
    source_uri = source.resolve().as_uri() + query
    with (
        closing(sqlite3.connect(source_uri, uri=True, timeout=15)) as source_connection,
        closing(sqlite3.connect(destination)) as destination_connection,
    ):
        require_rotation_access(source_connection, Settings(source.parent))
        # Keep the unpublished copy self-contained without changing the source's journal mode.
        destination_connection.execute("PRAGMA locking_mode=EXCLUSIVE").fetchall()
        if max_bytes is None:
            source_connection.backup(destination_connection)
        else:

            def check_size(_status: int, _remaining: int, total: int) -> None:
                page_size = cast(int, source_connection.execute("PRAGMA page_size").fetchone()[0])
                _remaining_snapshot_bytes(max_bytes, total * page_size)

            page_count = cast(int, source_connection.execute("PRAGMA page_count").fetchone()[0])
            check_size(0, 0, page_count)
            # Recheck online growth after each bounded batch, not after a full copy.
            source_connection.backup(
                destination_connection, pages=SNAPSHOT_BACKUP_PAGE_BATCH, progress=check_size
            )
        # Recovery must not depend on the original host's mounted config/key paths. Only the
        # unpublished copy loses completed maintenance state; source journals remain retained.
        if rotation_present(destination_connection):
            phase = destination_connection.execute(
                "SELECT phase FROM evidence_rotation WHERE singleton=1"
            ).fetchone()
            if phase is not None and phase[0] not in {"active", "rolled_back"}:
                raise RuntimeError("snapshot requires completed evidence rotation")
            destination_connection.execute("PRAGMA secure_delete=ON")
            destination_connection.execute("DELETE FROM evidence_rotation")
        destination_connection.commit()
        destination_connection.execute("PRAGMA journal_mode=DELETE").fetchall()
        require_rotation_access(source_connection, Settings(source.parent))
    after = source.stat()
    sidecars_after = _snapshot_source_sidecars(source)
    if sidecars_after != sidecars_before:
        raise RuntimeError("snapshot source SQLite sidecars changed during backup")
    if not sidecars_before and _stat_identity(before) != _stat_identity(after):
        raise RuntimeError("snapshot source database changed during backup")
    destination.chmod(0o600)


def require_snapshot_privacy(path: Path) -> None:
    # Check the stable copy only; legacy verification and recovery must remain possible.
    with closing(_open_snapshot_database(path)) as connection:
        version_row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        if version_row is None or version_row[0] is None:
            raise RuntimeError("database schema version is unavailable")
        schema_version = cast(int, version_row[0])
        if (
            schema_version >= 20
            and connection.execute("SELECT 1 FROM evidence_publication_work LIMIT 1").fetchone()
        ):
            raise RuntimeError("snapshot creation requires completed evidence publication work")
        if (
            schema_version >= 19
            and connection.execute(
                "SELECT 1 FROM deletion_object_work w "
                "JOIN deletion_operations d USING(operation_id) "
                "WHERE w.encrypted_purge_json IS NOT NULL AND d.status != 'complete' LIMIT 1"
            ).fetchone()
        ):
            raise RuntimeError("snapshot creation requires completed encrypted deletion work")
        if schema_version >= 10:
            retained_container = connection.execute(
                "SELECT 1 FROM web_export_source_objects WHERE object_id IS NOT NULL LIMIT 1"
            ).fetchone()
            if retained_container is not None:
                raise RuntimeError(
                    "snapshot creation requires explicit remediation: retained legacy "
                    "web-export containers may contain excluded records; originals were not changed"
                )

        events = "events_current" if schema_version >= 2 else "events"
        excluded_event = connection.execute(
            f"SELECT 1 FROM {events} WHERE privacy = 'no_memory' LIMIT 1"
        ).fetchone()
        if excluded_event is not None:
            raise RuntimeError(
                "snapshot creation requires explicit remediation: retained no_memory events "
                "cannot enter new snapshots; originals were not changed"
            )
        # Explicit private retention is distinct from no_memory and remains backup-eligible.


def _sanitize_portable_database(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        with connection:
            connection.execute("DELETE FROM client_credentials")
            connection.execute("DELETE FROM device_enrollments")
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='web_export_import_receipts'"
            ).fetchone():
                connection.execute("DELETE FROM web_export_import_receipts")
            connection.execute("DROP TABLE events_fts")
            connection.execute(
                """
                CREATE VIRTUAL TABLE events_fts USING fts5(
                  event_id UNINDEXED,
                  content_text,
                  tokenize = 'unicode61 remove_diacritics 2'
                )
                """
            )
        connection.execute("VACUUM")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    path.chmod(0o600)


def _verify_portable_snapshot_omissions(
    database_path: Path,
    snapshot_result: dict[str, Any],
) -> None:
    if snapshot_result["private_receipt_count"] != 0:
        raise RuntimeError("portable snapshot contains private receipts")
    with closing(_open_snapshot_database(database_path)) as connection:
        credential_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM client_credentials").fetchone()[0]
        )
        enrollment_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM device_enrollments").fetchone()[0]
        )
        search_index_count = cast(
            int, connection.execute("SELECT COUNT(*) FROM events_fts").fetchone()[0]
        )
        freelist_count = cast(int, connection.execute("PRAGMA freelist_count").fetchone()[0])
        import_receipt_count = 0
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_export_import_receipts'"
        ).fetchone():
            import_receipt_count = cast(
                int,
                connection.execute("SELECT COUNT(*) FROM web_export_import_receipts").fetchone()[0],
            )
    if credential_count or enrollment_count:
        raise RuntimeError("portable snapshot contains credential-bearing rows")
    if import_receipt_count:
        raise RuntimeError("portable snapshot contains private import receipts")
    if search_index_count:
        raise RuntimeError("portable snapshot contains a rebuildable search index")
    if freelist_count:
        raise RuntimeError("portable snapshot database was not compacted")


def _snapshot_source_sidecars(source: Path) -> tuple[str, ...]:
    present: list[str] = []
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{source}{suffix}")
        if sidecar.is_symlink():
            raise RuntimeError("snapshot source SQLite sidecar must not be a symlink")
        if sidecar.exists():
            if not sidecar.is_file():
                raise RuntimeError("snapshot source SQLite sidecar must be a regular file")
            present.append(suffix)
    observed = tuple(present)
    if observed not in ((), ("-wal", "-shm"), ("-journal",)):
        raise RuntimeError("snapshot source has an incomplete SQLite sidecar set")
    return observed


def _database_state(path: Path) -> dict[str, Any]:
    base_table_names = (
        "source_files",
        "source_records",
        "objects",
        "events",
        "quarantines",
        "memory_candidates",
        "mutation_receipts",
        "query_receipts",
    )
    with closing(_open_snapshot_database(path)) as connection:
        integrity = cast(str, connection.execute("PRAGMA integrity_check").fetchone()[0])
        if integrity != "ok":
            raise RuntimeError(f"database integrity check failed: {integrity}")
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise RuntimeError("database foreign-key check failed")
        version_row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        if version_row is None or version_row[0] is None:
            raise RuntimeError("database schema version is unavailable")
        schema_version = cast(int, version_row[0])
        if schema_version == SCHEMA_VERSION:
            validate_current_schema_objects(connection)
        elif schema_version == 20:
            validate_schema20_objects(connection)
        elif schema_version == 21:
            validate_schema21_objects(connection)
        elif schema_version == 22:
            validate_schema22_objects(connection)
        elif schema_version == 23:
            validate_schema23_objects(connection)
        table_names = base_table_names + (("event_corrections",) if schema_version >= 2 else ())
        if schema_version >= 3:
            table_names += ("source_streams", "source_segments", "source_cursors")
        if schema_version >= 4:
            table_names += (
                "installations",
                "devices",
                "source_accounts",
                "contexts",
                "source_stream_access",
                "source_stream_contexts",
                "event_access",
                "event_contexts",
                "memory_candidate_access",
                "memory_candidate_contexts",
            )
        if schema_version >= 5:
            table_names += ("clients", "client_capabilities", "client_credentials")
        if schema_version >= 6:
            table_names += ("client_devices", "device_enrollments")
        if schema_version >= 7:
            table_names += ("source_account_policies", "upload_batches")
        if schema_version >= 8:
            table_names += ("source_capture_metadata",)
        if schema_version >= 9:
            table_names += ("source_schema_authorizations",)
        if schema_version >= 10:
            table_names += (
                "web_export_batches",
                "web_export_archive_members",
                "web_export_source_objects",
                "web_export_conversation_observations",
                "web_export_reconciled_events",
                "web_export_event_observations",
                "event_relations",
            )
        if schema_version >= 11:
            table_names += (
                "memory_candidate_evidence_claims",
                "memory_candidate_evidence_links",
            )
        if schema_version >= 12:
            table_names += (
                "web_export_attachment_links",
                "web_export_attachment_objects",
            )
        if schema_version >= 13:
            table_names += (
                "deletion_tombstones",
                "deletion_operations",
                "deletion_object_work",
            )
        if schema_version >= 14:
            table_names += (
                "memory_candidate_proposal_receipts",
                "memory_candidate_review_transitions",
            )
        if schema_version >= 23:
            table_names += ("web_export_import_receipts",)
        counts = {
            name: cast(int, connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0])
            for name in table_names
        }
    return {"schema_version": schema_version, "counts": counts}


def _registered_objects(path: Path) -> dict[str, _SnapshotObject]:
    objects: dict[str, _SnapshotObject] = {}
    with closing(_open_snapshot_database(path)) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(objects)")}
        has_locations = "storage_kind" in columns
        if not has_locations:
            require_local_object_operations(connection)
        storage_column = "storage_kind" if has_locations else "'local'"
        rows = connection.execute(
            f"SELECT object_path, object_id, byte_length, {storage_column} "
            "FROM objects ORDER BY object_path"
        ).fetchall()
        for object_path, object_id, byte_length, storage_kind in rows:
            relative = _validated_relative_path(cast(str, object_path))
            digest = cast(str, object_id).removeprefix("sha256:")
            if (
                re.fullmatch(r"sha256:[0-9a-f]{64}", object_id) is None
                or relative.parts[:2] != ("objects", "sha256")
                or len(relative.parts) != 4
                or relative.parts[-2] != digest[:2]
                or relative.name != digest
                or relative.as_posix() in objects
                or type(byte_length) is not int
                or byte_length < 0
            ):
                raise RuntimeError("database contains invalid snapshot object metadata")
            location = read_location(connection, object_id) if has_locations else None
            require_mapping_state(storage_kind, location)
            if location is not None:
                identity, manifest = location
                if manifest.state != ObjectState.VERIFIED:
                    raise RuntimeError("pending encrypted publication must finish before snapshot")
                if (
                    re.fullmatch(r"[0-9a-f]{64}", identity) is None
                    or manifest.legacy_source_object_id != object_id
                    or manifest.plaintext_sha256 != digest
                    or manifest.plaintext_byte_length != byte_length
                ):
                    raise RuntimeError("encrypted snapshot object does not match its mapping")
            objects[relative.as_posix()] = _SnapshotObject(object_id, byte_length, location)
    return objects


def _planned_snapshot_manifest(
    database_state: dict[str, Any],
    existing_files: list[SnapshotFile],
    objects: dict[str, _SnapshotObject],
) -> bytes:
    object_files = [
        SnapshotFile(
            path=relative,
            role="object",
            size=item.byte_length,
            sha256=item.object_id.removeprefix("sha256:"),
        )
        for relative, item in objects.items()
    ]
    manifest = SnapshotManifest(
        snapshot_format_version=SNAPSHOT_FORMAT_VERSION,
        created_at=datetime.now(UTC).isoformat(),
        source_state=SnapshotState(
            schema_version=database_state["schema_version"],
            database_counts=database_state["counts"],
            object_count=len(objects),
            private_receipt_count=sum(item["role"] == "private_receipt" for item in existing_files),
        ),
        files=sorted(existing_files + object_files, key=lambda item: item["path"]),
    )
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _require_unchanged_snapshot_source(settings: Settings, generation: str | None) -> None:
    if generation is not None and snapshot_source_generation(settings) != generation:
        raise RuntimeError("snapshot source generation changed during encrypted materialization")


def _snapshot_source_stamp(settings: Settings) -> tuple[tuple[str, int, int, int, int, int], ...]:
    sidecars = _snapshot_source_sidecars(settings.database_path)
    paths = [settings.database_path] + [
        Path(f"{settings.database_path}{suffix}") for suffix in sidecars if suffix != "-shm"
    ]
    return tuple(
        (path.name, *_stat_identity(details), details.st_ctime_ns)
        for path in paths
        for details in [path.stat()]
    )


def _copy_snapshot_objects(
    settings: Settings,
    destination: Path,
    objects: dict[str, _SnapshotObject],
    remaining: int | None,
    reader: EncryptedEvidenceReader | None,
) -> str | None:
    disk_objects = _disk_object_paths(settings)
    local_objects = {path for path, item in objects.items() if item.location is None}
    missing = local_objects - disk_objects
    unregistered = disk_objects - set(objects)
    if missing or unregistered:
        raise RuntimeError(
            "object store does not match the ledger: "
            f"missing={sorted(missing)[:3]} unregistered={sorted(unregistered)[:3]}"
        )
    _remaining_snapshot_bytes(remaining, sum(item.byte_length for item in objects.values()))
    remote = [item for item in objects.values() if item.location is not None]
    generation = None
    source_stamp = None
    if remote:
        if reader is None:
            raise RuntimeError("encrypted evidence reader is not configured for snapshot")
        generation = _snapshot_database_generation(Settings(destination))
        source_stamp = _snapshot_source_stamp(settings)
        _require_unchanged_snapshot_source(settings, generation)
        for item in remote:
            assert item.location is not None
            identity, manifest = item.location
            if (
                identity != reader.backend.identity_sha256
                or manifest.backend_profile != reader.backend.profile
                or manifest.root_key_id != reader.root_key.key_id
            ):
                raise RuntimeError("encrypted snapshot reader does not match its mapping")
            if (
                item.byte_length > reader.max_plaintext_bytes
                or manifest.ciphertext_byte_length > reader.max_ciphertext_bytes
            ):
                raise RuntimeError("encrypted snapshot object exceeds its read budget")

    for relative, item in sorted(objects.items()):
        # Watch physical writes cheaply per object; bind the full generation at both ends.
        if source_stamp is not None and _snapshot_source_stamp(settings) != source_stamp:
            raise RuntimeError("snapshot source generation changed during materialization")
        target = destination.joinpath(*PurePosixPath(relative).parts)
        if item.location is None:
            source = settings.data_root.expanduser().joinpath(*PurePosixPath(relative).parts)
            # Bound growing local files by admitted size even without a total snapshot budget.
            size, digest = _copy_regular_file(source, target, max_bytes=item.byte_length)
        else:
            assert reader is not None
            identity, manifest = item.location
            payload = reader.read(
                manifest,
                object_id=item.object_id,
                expected_size=item.byte_length,
                backend_identity_sha256=identity,
            )
            if _snapshot_source_stamp(settings) != source_stamp:
                raise RuntimeError("snapshot source generation changed during materialization")
            size, digest = len(payload), hashlib.sha256(payload).hexdigest()
            if size != item.byte_length or digest != item.object_id.removeprefix("sha256:"):
                raise RuntimeError("encrypted snapshot evidence failed verification")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            del payload
        remaining = _remaining_snapshot_bytes(remaining, size)
        if size != item.byte_length or digest != item.object_id.removeprefix("sha256:"):
            raise RuntimeError(f"evidence object failed verification: {item.object_id}")
    return generation


def _open_snapshot_database(path: Path) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def _disk_object_paths(settings: Settings) -> set[str]:
    paths: set[str] = set()
    for path in settings.object_root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"object store contains a symlink: {path}")
        if path.is_file():
            paths.add(path.relative_to(settings.data_root).as_posix())
        elif not path.is_dir():
            raise RuntimeError(f"object store contains a non-regular entry: {path}")
    return paths


def _copy_private_receipts(
    settings: Settings, destination: Path, *, max_bytes: int | None = None
) -> list[SnapshotFile]:
    remaining = max_bytes
    source_root = settings.run_root / "private"
    if not source_root.exists():
        return []
    if source_root.is_symlink() or not source_root.is_dir():
        raise RuntimeError(f"private receipt root is invalid: {source_root}")
    entries: list[SnapshotFile] = []
    for source in sorted(source_root.rglob("*")):
        if source.is_symlink():
            raise RuntimeError(f"private receipt tree contains a symlink: {source}")
        if source.is_dir():
            continue
        if not source.is_file():
            raise RuntimeError(f"private receipt tree contains a non-regular entry: {source}")
        relative = source.relative_to(settings.data_root).as_posix()
        target = destination.joinpath(*PurePosixPath(relative).parts)
        size, digest = _copy_regular_file(source, target, max_bytes=remaining)
        remaining = _remaining_snapshot_bytes(remaining, size)
        entries.append(
            SnapshotFile(path=relative, role="private_receipt", size=size, sha256=digest)
        )
    return entries


def _copy_regular_file(
    source: Path, destination: Path, *, max_bytes: int | None = None
) -> tuple[int, str]:
    if source.is_symlink() or not source.is_file():
        raise RuntimeError(f"source is not a regular file: {source}")
    before = source.stat()
    _remaining_snapshot_bytes(max_bytes, before.st_size)
    remaining = max_bytes
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination.parent.chmod(0o700)
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        destination_flags |= os.O_NOFOLLOW
    source_descriptor = os.open(source, source_flags)
    destination_descriptor = os.open(destination, destination_flags, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        with (
            os.fdopen(source_descriptor, "rb") as source_handle,
            os.fdopen(destination_descriptor, "wb") as destination_handle,
        ):
            while chunk := source_handle.read(
                COPY_CHUNK_BYTES if remaining is None else min(COPY_CHUNK_BYTES, remaining + 1)
            ):
                remaining = _remaining_snapshot_bytes(remaining, len(chunk))
                destination_handle.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
            after = os.fstat(source_handle.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    if _stat_identity(before) != _stat_identity(after):
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"source changed while snapshotting: {source}")
    return size, digest.hexdigest()


def _hash_regular_file(path: Path, *, expected_size: int | None = None) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"snapshot entry is not a regular file: {path}")
    before = path.stat()
    if expected_size is not None and before.st_size != expected_size:
        raise RuntimeError(f"snapshot file failed hash verification: {path}")
    remaining = before.st_size
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if _stat_identity(os.fstat(handle.fileno())) != _stat_identity(before):
            raise RuntimeError("snapshot entry changed before verification")
        while chunk := handle.read(min(COPY_CHUNK_BYTES, remaining + 1)):
            if len(chunk) > remaining:
                raise RuntimeError("snapshot entry grew during verification")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(handle.fileno())
        published = path.lstat()
        if remaining or any(
            _stat_identity(details) != _stat_identity(before)
            or details.st_ctime_ns != before.st_ctime_ns
            for details in (after, published)
        ):
            raise RuntimeError("snapshot entry changed during verification")
    return before.st_size, digest.hexdigest()


def _verify_offline_clone_files(root: Path, manifest: SnapshotManifest) -> None:
    expected_paths: set[str] = set()
    for item in manifest["files"]:
        relative = _validated_relative_path(item["path"])
        path = root.joinpath(*relative.parts)
        size, digest = _hash_regular_file(path, expected_size=item["size"])
        if size != item["size"] or digest != item["sha256"]:
            raise RuntimeError(f"offline clone file failed verification: {item['path']}")
        expected_paths.add(item["path"])
    actual_paths = _snapshot_file_paths(root)
    if actual_paths != expected_paths:
        missing = sorted(expected_paths - actual_paths)
        unexpected = sorted(actual_paths - expected_paths)
        raise RuntimeError(
            f"offline clone file set changed: missing={missing[:3]} unexpected={unexpected[:3]}"
        )


def _normalize_private_directories(root: Path) -> None:
    for path in (root, *sorted(root.rglob("*"))):
        if path.is_symlink():
            raise RuntimeError(f"offline clone contains a symlink: {path}")
        if path.is_dir():
            path.chmod(0o700)
        elif not path.is_file():
            raise RuntimeError(f"offline clone contains a non-regular entry: {path}")
        elif path.relative_to(root).parent == MATERIALIZATION_RECEIPT_ROOT:
            path.chmod(0o400)


def publish_restored_node(
    temporary: Path,
    destination: Path,
    *,
    expected_identity: os.stat_result | None = None,
    expected_parent_identity: os.stat_result | None = None,
) -> None:
    root = Path(os.path.abspath(temporary))
    directories = [root]
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("offline clone contains a symlink before publication")
        if path.is_dir():
            directories.append(path)
        else:
            descriptor, _ = open_regular_file_no_symlinks(path, "offline clone file")
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for path in reversed(directories):
        descriptor = open_directory_no_symlinks(path, "offline clone directory")
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    identity = expected_identity if expected_identity is not None else root.stat()
    target = Path(os.path.abspath(destination))
    parent = open_directory_no_symlinks(target.parent, "offline clone parent")
    try:
        if expected_parent_identity is not None and not os.path.samestat(
            expected_parent_identity, os.fstat(parent)
        ):
            raise RuntimeError("offline clone parent identity changed")
        publish_directory_no_replace(
            root,
            target,
            required_mode=0o700,
            label="offline clone",
            **(
                {
                    "expected_identity": expected_identity,
                    "expected_parent_identity": expected_parent_identity,
                }
                if expected_identity is not None or expected_parent_identity is not None
                else {}
            ),
        )
    except BaseException:
        # A failure after the rename must not leave this attempt looking published.
        if remove_owned_directory_at(parent, target.name, identity):
            os.fsync(parent)
        raise
    finally:
        os.close(parent)


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


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    _ensure_private_directory(path.parent)
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o400)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(COPY_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _file_entry(path: Path, root: Path, role: str) -> SnapshotFile:
    size, digest = _hash_regular_file(path)
    return SnapshotFile(path=path.relative_to(root).as_posix(), role=role, size=size, sha256=digest)


def _snapshot_file_paths(root: Path) -> set[str]:
    paths: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"snapshot contains a symlink: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative != SNAPSHOT_MANIFEST:
                paths.add(relative)
        elif not path.is_dir():
            raise RuntimeError(f"snapshot contains a non-regular entry: {path}")
    return paths


def _load_manifest(path: Path) -> tuple[SnapshotManifest, str]:
    descriptor, normalized = open_regular_file_no_symlinks(
        path.parent.resolve() / path.name, "snapshot manifest"
    )
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        payload = handle.read(before.st_size + 1)
        after = os.fstat(handle.fileno())
        published = normalized.lstat()
    if len(payload) != before.st_size or any(
        _stat_identity(details) != _stat_identity(before)
        or details.st_ctime_ns != before.st_ctime_ns
        for details in (after, published)
    ):
        raise RuntimeError("snapshot manifest changed during verification")
    digest = hashlib.sha256(payload).hexdigest()
    raw: object = json.loads(payload)
    if not isinstance(raw, dict):
        raise ValueError("snapshot manifest must be an object")
    data = cast(dict[str, object], raw)
    if data.get("snapshot_format_version") != SNAPSHOT_FORMAT_VERSION:
        raise ValueError("unsupported snapshot manifest version")
    files = data.get("files")
    state = data.get("source_state")
    if (
        not isinstance(data.get("created_at"), str)
        or not isinstance(files, list)
        or not isinstance(state, dict)
    ):
        raise ValueError("snapshot manifest structure is invalid")
    for raw_item in cast(list[object], files):
        if not isinstance(raw_item, dict):
            raise ValueError("snapshot manifest file entry is invalid")
        item = cast(dict[str, object], raw_item)
        if (
            not isinstance(item.get("path"), str)
            or item.get("role") not in {"database", "object", "private_receipt"}
            or not isinstance(item.get("size"), int)
            or cast(int, item["size"]) < 0
            or not isinstance(item.get("sha256"), str)
            or len(cast(str, item["sha256"])) != 64
        ):
            raise ValueError("snapshot manifest file entry is invalid")
    state_data = cast(dict[str, object], state)
    counts = state_data.get("database_counts")
    if (
        not isinstance(state_data.get("schema_version"), int)
        or not isinstance(counts, dict)
        or not isinstance(state_data.get("object_count"), int)
        or not isinstance(state_data.get("private_receipt_count"), int)
    ):
        raise ValueError("snapshot manifest source state is invalid")
    count_data = cast(dict[object, object], counts)
    if not all(
        isinstance(key, str) and isinstance(value, int) for key, value in count_data.items()
    ):
        raise ValueError("snapshot manifest database counts are invalid")
    return cast(SnapshotManifest, data), digest


def _validated_relative_path(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"unsafe snapshot path: {value}")
    return relative


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns
