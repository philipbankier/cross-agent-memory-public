from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import uuid
from contextlib import ExitStack, closing
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

from cross_assistant_memory.backup import (
    OFFLINE_CLONE_MARKER,
    SNAPSHOT_MANIFEST,
    create_portable_snapshot,
    load_snapshot_manifest,
    publish_restored_node,
    staged_offline_clone,
    verify_snapshot,
)
from cross_assistant_memory.config import Settings, default_data_root
from cross_assistant_memory.encrypted_objects import (
    EncryptedObjectManifest,
    EncryptedObjectStore,
    FilesystemObjectBackend,
    ObjectState,
    RecoverySecret,
    RootKey,
    build_recovery_kit,
    restore_root_key_from_bytes,
)
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.object_store import (
    BackendObjectStat,
    IncompleteCleanupReport,
)
from cross_assistant_memory.snapshot_materialization import (
    StorageMaterialization,
    verify_storage_materialization_receipt,
)
from cross_assistant_memory.storage import (
    SCHEMA_VERSION,
    Ledger,
    exclusive_ledger_writer,
    open_maintenance_inspection,
)

PORTABLE_EXPORT_FORMAT_VERSION = 1
PORTABLE_KIT_FORMAT_VERSION = 1
PORTABLE_KIT = "portable-kit.json"
PORTABLE_INDEX_MEDIA_TYPE = "application/vnd.cross-assistant-memory.portable-index+json"
PORTABLE_OMISSIONS = (
    "client_credentials",
    "device_enrollments",
    "private_receipts",
    "events_fts",
)
MAX_PORTABLE_KIT_BYTES = 2 * 1024 * 1024
MAX_PORTABLE_INDEX_BYTES = 64 * 1024 * 1024
MAX_PORTABLE_FILES = 100_000
MAX_RELATIVE_PATH_BYTES = 4096
COPY_CHUNK_BYTES = 1024 * 1024

_PACKAGE_ID = re.compile(r"portable_[0-9a-f]{32}")
_ROOT_KEY_ID = re.compile(r"root_[0-9a-f]{32}")
_STORAGE_OBJECT_ID = re.compile(r"storage_[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def create_filesystem_portable_export(
    settings: Settings,
    *,
    output: Path,
    recovery_secret_path: Path,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    recovery_secret = RecoverySecret.load(recovery_secret_path.expanduser())
    return create_portable_export(
        settings,
        output,
        recovery_secret,
        encrypted_evidence_reader=encrypted_evidence_reader,
        max_bytes=max_bytes,
    )


def verify_filesystem_portable_export(
    export: Path,
    *,
    recovery_secret_path: Path,
) -> dict[str, Any]:
    recovery_secret = RecoverySecret.load(recovery_secret_path.expanduser())
    return verify_portable_export(export, recovery_secret)


def import_filesystem_portable_export(
    export: Path,
    *,
    recovery_secret_path: Path,
    output: Path,
) -> dict[str, Any]:
    recovery_secret = RecoverySecret.load(recovery_secret_path.expanduser())
    return import_portable_export(export, recovery_secret, output)


def create_portable_export(
    settings: Settings,
    output: Path,
    recovery_secret: RecoverySecret,
    *,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    with exclusive_ledger_writer(settings):
        return _create_portable_export_locked(
            settings,
            output,
            recovery_secret,
            encrypted_evidence_reader=encrypted_evidence_reader,
            max_bytes=max_bytes,
        )


def _create_portable_export_locked(
    settings: Settings,
    output: Path,
    recovery_secret: RecoverySecret,
    *,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    destination = output.expanduser()
    _require_absent(destination, "portable export")
    _ensure_portable_output_parent(destination.parent)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    temporary.chmod(0o700)
    package_id = f"portable_{uuid.uuid4().hex}"
    root_key = RootKey.generate()
    try:
        backend = FilesystemObjectBackend(temporary)
        with tempfile.TemporaryDirectory(prefix="cross-memory-portable-export-") as workspace_name:
            workspace = Path(workspace_name)
            workspace.chmod(0o700)
            snapshot = workspace / "snapshot"
            snapshot_result = create_portable_snapshot(
                settings,
                snapshot,
                encrypted_evidence_reader=encrypted_evidence_reader,
                max_bytes=max_bytes,
            )
            snapshot_manifest = load_snapshot_manifest(snapshot)
            if len(snapshot_manifest["files"]) + 1 > MAX_PORTABLE_FILES:
                raise ValueError("portable export exceeds its file-count limit")

            store = EncryptedObjectStore(workspace / "encrypted-metadata", backend, root_key)
            package_files = [
                _encrypt_portable_file(
                    store,
                    snapshot / SNAPSHOT_MANIFEST,
                    path=SNAPSHOT_MANIFEST,
                    role="snapshot_manifest",
                )
            ]
            for item in snapshot_manifest["files"]:
                relative = _validated_relative_path(item["path"])
                package_files.append(
                    _encrypt_portable_file(
                        store,
                        snapshot.joinpath(*relative.parts),
                        path=item["path"],
                        role=item["role"],
                    )
                )

            created_at = _now()
            index = {
                "format_version": PORTABLE_EXPORT_FORMAT_VERSION,
                "package_id": package_id,
                "created_at": created_at,
                "backend_profile": backend.profile,
                "root_key_id": root_key.key_id,
                "source_schema_version": snapshot_result["schema_version"],
                "source_ledger_generation": snapshot_result["source_ledger_generation"],
                "snapshot_manifest_sha256": snapshot_result["snapshot_manifest_sha256"],
                "omissions": list(PORTABLE_OMISSIONS),
                "files": package_files,
            }
            index_payload = _canonical_json_bytes(index)
            if len(index_payload) > MAX_PORTABLE_INDEX_BYTES:
                raise ValueError("portable export index exceeds its size limit")
            index_path = workspace / "portable-index.json"
            _write_new_private_file(index_path, index_payload, mode=0o600)
            index_manifest = store.put_file(index_path, media_type=PORTABLE_INDEX_MEDIA_TYPE)

            root_recovery_kit = build_recovery_kit(root_key, recovery_secret)
            kit = {
                "format_version": PORTABLE_KIT_FORMAT_VERSION,
                "package_id": package_id,
                "created_at": created_at,
                "backend_profile": backend.profile,
                "root_recovery_kit": _encode_base64(root_recovery_kit),
                "root_recovery_kit_sha256": hashlib.sha256(root_recovery_kit).hexdigest(),
                "portable_index_manifest": index_manifest.as_dict(),
            }
            kit_payload = _canonical_json_bytes(kit)
            if len(kit_payload) > MAX_PORTABLE_KIT_BYTES:
                raise ValueError("portable export kit exceeds its size limit")
            _write_new_private_file(temporary / PORTABLE_KIT, kit_payload, mode=0o600)

        incomplete = temporary / "incomplete"
        if any(incomplete.iterdir()):
            raise RuntimeError("portable export contains incomplete ciphertext uploads")
        incomplete.rmdir()

        verified = verify_portable_export(temporary, recovery_secret)
        temporary.rename(destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {
        **verified,
        "status": "created",
        "export_path": str(destination),
    }


def verify_portable_export(
    export: Path,
    recovery_secret: RecoverySecret,
) -> dict[str, Any]:
    root = export.expanduser()
    backend, kit_payload, kit, root_key = _open_portable_export(root, recovery_secret)
    with tempfile.TemporaryDirectory(prefix="cross-memory-portable-verify-") as workspace_name:
        workspace = Path(workspace_name)
        workspace.chmod(0o700)
        restored = _restore_portable_snapshot(
            backend=backend,
            kit=kit,
            root_key=root_key,
            workspace=workspace,
        )
    return {
        "status": "verified",
        "package_id": restored["package_id"],
        "portable_kit_sha256": hashlib.sha256(kit_payload).hexdigest(),
        "backend_profile": backend.profile,
        "root_key_id": root_key.key_id,
        "snapshot_manifest_sha256": restored["snapshot_manifest_sha256"],
        "source_ledger_generation": restored["source_ledger_generation"],
        "encrypted_file_count": restored["encrypted_file_count"],
        "ciphertext_object_count": restored["ciphertext_object_count"],
        "omissions": list(PORTABLE_OMISSIONS),
    }


def import_portable_export(
    export: Path,
    recovery_secret: RecoverySecret,
    output: Path,
) -> dict[str, Any]:
    destination = output.expanduser()
    _require_absent(destination, "portable import output")
    if destination.resolve() == default_data_root().resolve():
        raise ValueError("portable import output cannot be the default live data root")
    _ensure_private_directory(destination.parent)
    backend, kit_payload, kit, root_key = _open_portable_export(
        export.expanduser(), recovery_secret
    )

    with (
        tempfile.TemporaryDirectory(
            prefix=f".{destination.name}.portable-import-", dir=destination.parent
        ) as workspace_name,
        ExitStack() as stack,
    ):
        workspace = Path(workspace_name)
        workspace.chmod(0o700)
        restored = _restore_portable_snapshot(
            backend=backend,
            kit=kit,
            root_key=root_key,
            workspace=workspace,
        )
        snapshot = cast(Path, restored["snapshot_path"])
        candidate, clone = stack.enter_context(staged_offline_clone(snapshot, destination))
        if clone["snapshot_ledger_generation"] != restored["source_ledger_generation"]:
            raise RuntimeError("portable snapshot ledger generation does not match the index")
        (candidate / OFFLINE_CLONE_MARKER).unlink(missing_ok=True)
        imported_settings = Settings(candidate)
        restored_generation = Ledger(
            imported_settings, read_only=True, require_checkpointed=False
        ).generation_digest()
        materialization = cast(StorageMaterialization | None, clone["storage_materialization"])
        if materialization is not None and (
            materialization["source_generation"] != restored["source_ledger_generation"]
            or materialization["restored_generation"] != restored_generation
        ):
            raise RuntimeError("portable storage materialization generation binding does not match")
        rebuilt = Ledger(imported_settings).rebuild_search_index(
            expected_generation_digest=restored_generation
        )
        _verify_imported_node(
            imported_settings,
            expected_generation=restored_generation,
            storage_materialization=materialization,
        )
        final_status = Ledger(
            imported_settings, read_only=True, require_checkpointed=False
        ).status()
        publish_restored_node(candidate, destination)

    return {
        "status": "imported",
        "package_id": restored["package_id"],
        "portable_kit_sha256": hashlib.sha256(kit_payload).hexdigest(),
        "data_root": str(destination),
        "backend_profile": backend.profile,
        "root_key_id": root_key.key_id,
        "snapshot_manifest_sha256": restored["snapshot_manifest_sha256"],
        "source_ledger_generation": restored["source_ledger_generation"],
        "restored_ledger_generation": restored_generation,
        "storage_materialization": materialization,
        "encrypted_file_count": restored["encrypted_file_count"],
        "indexed_events": rebuilt["indexed_events"],
        "ledger_status": {
            **final_status,
            "database_path": str(Settings(destination).database_path),
        },
        "omissions": list(PORTABLE_OMISSIONS),
    }


def _open_portable_export(
    root: Path,
    recovery_secret: RecoverySecret,
) -> tuple[_ReadOnlyFilesystemBackend, bytes, dict[str, Any], RootKey]:
    backend = _ReadOnlyFilesystemBackend(root)
    kit_path = root / PORTABLE_KIT
    kit_payload = _read_regular_file(kit_path, MAX_PORTABLE_KIT_BYTES)
    kit = _load_portable_kit(kit_payload)
    if kit["backend_profile"] != backend.profile:
        raise RuntimeError("portable export backend profile does not match")
    root_kit = _decode_base64(kit["root_recovery_kit"], "root recovery kit")
    _strict_json(root_kit, "root recovery kit")
    if hashlib.sha256(root_kit).hexdigest() != kit["root_recovery_kit_sha256"]:
        raise RuntimeError("root recovery kit digest does not match")
    root_key = restore_root_key_from_bytes(root_kit, recovery_secret)
    return backend, kit_payload, kit, root_key


def _restore_portable_snapshot(
    *,
    backend: _ReadOnlyFilesystemBackend,
    kit: dict[str, Any],
    root_key: RootKey,
    workspace: Path,
) -> dict[str, Any]:
    store = EncryptedObjectStore(workspace / "encrypted-metadata", backend, root_key)
    index_manifest = EncryptedObjectManifest.from_dict(kit["portable_index_manifest"])
    _validate_index_manifest(index_manifest, backend.profile, root_key.key_id)
    store.register_manifest(index_manifest)
    index_path = workspace / "portable-index.json"
    store.restore_file(index_manifest.source_object_id, index_path)
    index_payload = _read_regular_file(index_path, MAX_PORTABLE_INDEX_BYTES)
    index = _load_portable_index(index_payload)
    _validate_portable_binding(kit, index, backend.profile, root_key.key_id)

    snapshot = workspace / "restored-snapshot"
    snapshot.mkdir(mode=0o700)
    restored_ids = _restore_portable_files(
        store,
        index,
        snapshot,
        reserved_source_object_id=index_manifest.source_object_id,
        reserved_storage_object_id=index_manifest.storage_object_id,
    )
    expected_storage_ids = restored_ids | {index_manifest.storage_object_id}
    backend.verify_exact_object_set(expected_storage_ids)

    _validate_strict_snapshot_manifest(snapshot / SNAPSHOT_MANIFEST)
    snapshot_result = verify_snapshot(snapshot)
    if snapshot_result["snapshot_manifest_sha256"] != index["snapshot_manifest_sha256"]:
        raise RuntimeError("portable snapshot digest does not match the encrypted index")
    manifest = load_snapshot_manifest(snapshot)
    expected_roles = {
        SNAPSHOT_MANIFEST: "snapshot_manifest",
        **{item["path"]: item["role"] for item in manifest["files"]},
    }
    actual_roles = {item["path"]: item["role"] for item in index["files"]}
    if actual_roles != expected_roles:
        raise RuntimeError("portable file roles do not match the snapshot manifest")
    _verify_portable_snapshot(
        snapshot,
        snapshot_result,
        expected_generation=index["source_ledger_generation"],
        expected_schema_version=index["source_schema_version"],
    )
    return {
        "package_id": index["package_id"],
        "snapshot_path": snapshot,
        "snapshot_manifest_sha256": snapshot_result["snapshot_manifest_sha256"],
        "source_ledger_generation": index["source_ledger_generation"],
        "encrypted_file_count": len(index["files"]),
        "ciphertext_object_count": len(expected_storage_ids),
    }


def _encrypt_portable_file(
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
    }
    try:
        media_type = media_types[role]
    except KeyError as error:
        raise ValueError(f"unsupported portable file role: {role}") from error
    manifest = store.put_file(source, media_type=media_type)
    return {"path": path, "role": role, "encrypted_manifest": manifest.as_dict()}


def _restore_portable_files(
    store: EncryptedObjectStore,
    index: dict[str, Any],
    snapshot: Path,
    *,
    reserved_source_object_id: str,
    reserved_storage_object_id: str,
) -> set[str]:
    seen_paths: set[str] = set()
    seen_source_ids = {reserved_source_object_id}
    seen_storage_ids = {reserved_storage_object_id}
    restored_storage_ids: set[str] = set()
    for value in index["files"]:
        fields = cast(dict[str, object], value)
        path_value = cast(str, fields["path"])
        if path_value in seen_paths:
            raise ValueError("portable export contains a duplicate file path")
        seen_paths.add(path_value)
        relative = _validated_relative_path(path_value)
        role = cast(str, fields["role"])
        manifest = EncryptedObjectManifest.from_dict(fields["encrypted_manifest"])
        _validate_payload_manifest(manifest, role, index)
        if manifest.source_object_id in seen_source_ids:
            raise ValueError("portable export contains a duplicate source object id")
        if manifest.storage_object_id in seen_storage_ids:
            raise ValueError("portable export contains a duplicate storage object id")
        seen_source_ids.add(manifest.source_object_id)
        seen_storage_ids.add(manifest.storage_object_id)
        destination = snapshot.joinpath(*relative.parts)
        _ensure_private_directory(destination.parent)
        store.register_manifest(manifest)
        store.restore_file(manifest.source_object_id, destination)
        restored_storage_ids.add(manifest.storage_object_id)
    return restored_storage_ids


def _validate_payload_manifest(
    manifest: EncryptedObjectManifest,
    role: str,
    index: dict[str, Any],
) -> None:
    expected_media_types = {
        "snapshot_manifest": "application/vnd.cross-assistant-memory.snapshot-manifest+json",
        "database": "application/vnd.sqlite3",
        "object": "application/octet-stream",
    }
    if role not in expected_media_types or manifest.media_type != expected_media_types[role]:
        raise ValueError("portable file media type does not match its role")
    if manifest.state != ObjectState.VERIFIED:
        raise ValueError("portable export contains an unverified object manifest")
    if manifest.backend_profile != index["backend_profile"]:
        raise ValueError("portable file backend profile does not match the index")
    if manifest.root_key_id != index["root_key_id"]:
        raise ValueError("portable file root key does not match the index")
    if manifest.legacy_source_object_id is not None:
        raise ValueError("portable file manifest contains a legacy identifier")


def _verify_portable_snapshot(
    snapshot: Path,
    snapshot_result: dict[str, Any],
    *,
    expected_generation: str,
    expected_schema_version: int,
) -> None:
    if expected_schema_version != SCHEMA_VERSION:
        raise RuntimeError(
            f"portable export requires schema {SCHEMA_VERSION}; found {expected_schema_version}"
        )
    if snapshot_result["schema_version"] != expected_schema_version:
        raise RuntimeError("portable snapshot schema does not match the encrypted index")
    if snapshot_result["private_receipt_count"] != 0:
        raise RuntimeError("portable snapshot contains private receipts")
    database = snapshot / "ledger.sqlite3"
    with closing(_open_read_only_database(database)) as connection:
        credentials = cast(
            int, connection.execute("SELECT COUNT(*) FROM client_credentials").fetchone()[0]
        )
        enrollments = cast(
            int, connection.execute("SELECT COUNT(*) FROM device_enrollments").fetchone()[0]
        )
        indexed = cast(int, connection.execute("SELECT COUNT(*) FROM events_fts").fetchone()[0])
        freelist = cast(int, connection.execute("PRAGMA freelist_count").fetchone()[0])
    if credentials or enrollments:
        raise RuntimeError("portable snapshot contains credential-bearing rows")
    if indexed:
        raise RuntimeError("portable snapshot contains a rebuildable search index")
    if freelist:
        raise RuntimeError("portable snapshot database contains free pages")
    generation = Ledger(Settings(snapshot), read_only=True).generation_digest()
    if generation != expected_generation:
        raise RuntimeError("portable snapshot ledger generation does not match the index")


def _verify_imported_node(
    settings: Settings,
    *,
    expected_generation: str,
    storage_materialization: StorageMaterialization | None = None,
) -> None:
    allowed_receipt: Path | None = None
    if storage_materialization is not None:
        verify_storage_materialization_receipt(settings, storage_materialization)
        allowed_receipt = settings.data_root / storage_materialization["receipt_path"]
    private_root = settings.run_root / "private"
    if private_root.exists():
        for path in private_root.rglob("*"):
            if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                raise RuntimeError("portable import contains an unsafe private receipt entry")
            if path.is_file() and path != allowed_receipt:
                raise RuntimeError("portable import unexpectedly contains a private receipt")
    with closing(open_maintenance_inspection(settings, require_checkpointed=False)) as connection:
        integrity = cast(str, connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        credentials = cast(
            int, connection.execute("SELECT COUNT(*) FROM client_credentials").fetchone()[0]
        )
        enrollments = cast(
            int, connection.execute("SELECT COUNT(*) FROM device_enrollments").fetchone()[0]
        )
        indexed = cast(int, connection.execute("SELECT COUNT(*) FROM events_fts").fetchone()[0])
        expected_indexed = cast(
            int,
            connection.execute(
                "SELECT COUNT(*) FROM events_current WHERE privacy = 'included'"
            ).fetchone()[0],
        )
    if integrity != "ok" or foreign_key_errors:
        raise RuntimeError("portable import database verification failed")
    if credentials or enrollments:
        raise RuntimeError("portable import recreated credential-bearing rows")
    if indexed != expected_indexed:
        raise RuntimeError("portable import search index is incomplete")
    generation = Ledger(settings, read_only=True, require_checkpointed=False).generation_digest()
    if generation != expected_generation:
        raise RuntimeError("portable import changed the restored ledger generation")


def _load_portable_kit(payload: bytes) -> dict[str, Any]:
    value = _strict_json(payload, "portable export kit")
    if not isinstance(value, dict):
        raise ValueError("portable export kit must be an object")
    fields = cast(dict[object, object], value)
    expected = {
        "format_version",
        "package_id",
        "created_at",
        "backend_profile",
        "root_recovery_kit",
        "root_recovery_kit_sha256",
        "portable_index_manifest",
    }
    if set(fields) != expected:
        raise ValueError("portable export kit fields are invalid")
    if fields.get("format_version") != PORTABLE_KIT_FORMAT_VERSION:
        raise ValueError("unsupported portable export kit format")
    _validate_package_id(_required_str(fields, "package_id"))
    _validate_timestamp(_required_str(fields, "created_at"))
    if _required_str(fields, "backend_profile") != "filesystem-v1":
        raise ValueError("portable export backend profile is invalid")
    _decode_base64(_required_str(fields, "root_recovery_kit"), "root recovery kit")
    _validate_sha256(_required_str(fields, "root_recovery_kit_sha256"))
    if not isinstance(fields.get("portable_index_manifest"), dict):
        raise ValueError("portable index manifest is invalid")
    return cast(dict[str, Any], value)


def _load_portable_index(payload: bytes) -> dict[str, Any]:
    value = _strict_json(payload, "portable export index")
    if not isinstance(value, dict):
        raise ValueError("portable export index must be an object")
    fields = cast(dict[object, object], value)
    expected = {
        "format_version",
        "package_id",
        "created_at",
        "backend_profile",
        "root_key_id",
        "source_schema_version",
        "source_ledger_generation",
        "snapshot_manifest_sha256",
        "omissions",
        "files",
    }
    if set(fields) != expected:
        raise ValueError("portable export index fields are invalid")
    if fields.get("format_version") != PORTABLE_EXPORT_FORMAT_VERSION:
        raise ValueError("unsupported portable export index format")
    _validate_package_id(_required_str(fields, "package_id"))
    _validate_timestamp(_required_str(fields, "created_at"))
    if _required_str(fields, "backend_profile") != "filesystem-v1":
        raise ValueError("portable export backend profile is invalid")
    root_key_id = _required_str(fields, "root_key_id")
    if not _ROOT_KEY_ID.fullmatch(root_key_id):
        raise ValueError("portable export root key id is invalid")
    schema_version = _required_int(fields, "source_schema_version")
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"portable export requires schema {SCHEMA_VERSION}; found {schema_version}"
        )
    _validate_sha256(_required_str(fields, "source_ledger_generation"))
    _validate_sha256(_required_str(fields, "snapshot_manifest_sha256"))
    if fields.get("omissions") != list(PORTABLE_OMISSIONS):
        raise ValueError("portable export omissions are invalid")

    files_value = fields.get("files")
    if not isinstance(files_value, list):
        raise ValueError("portable export file list is invalid")
    raw_files = cast(list[object], files_value)
    if not 2 <= len(raw_files) <= MAX_PORTABLE_FILES:
        raise ValueError("portable export file list is invalid")
    snapshot_manifest_count = 0
    database_count = 0
    parsed_files: list[dict[str, object]] = []
    for item in raw_files:
        if not isinstance(item, dict):
            raise ValueError("portable export file entry is invalid")
        item_fields = cast(dict[object, object], item)
        if set(item_fields) != {"path", "role", "encrypted_manifest"}:
            raise ValueError("portable export file entry fields are invalid")
        path = _required_str(item_fields, "path")
        _validated_relative_path(path)
        role = _required_str(item_fields, "role")
        if role not in {"snapshot_manifest", "database", "object"}:
            raise ValueError("portable export file role is invalid")
        if not isinstance(item_fields.get("encrypted_manifest"), dict):
            raise ValueError("portable export encrypted manifest is invalid")
        if role == "snapshot_manifest":
            snapshot_manifest_count += 1
            if path != SNAPSHOT_MANIFEST:
                raise ValueError("portable snapshot manifest path is invalid")
        if role == "database":
            database_count += 1
            if path != "ledger.sqlite3":
                raise ValueError("portable database path is invalid")
        parsed_files.append(cast(dict[str, object], item))
    if snapshot_manifest_count != 1 or database_count != 1:
        raise ValueError("portable export requires one snapshot manifest and one database")
    loaded = cast(dict[str, Any], value)
    loaded["files"] = parsed_files
    return loaded


def _validate_strict_snapshot_manifest(path: Path) -> None:
    value = _strict_json(
        _read_regular_file(path, MAX_PORTABLE_INDEX_BYTES), "portable snapshot manifest"
    )
    if not isinstance(value, dict):
        raise ValueError("portable snapshot manifest must be an object")
    fields = cast(dict[object, object], value)
    if set(fields) != {"snapshot_format_version", "created_at", "source_state", "files"}:
        raise ValueError("portable snapshot manifest fields are invalid")
    state = fields.get("source_state")
    files = fields.get("files")
    if not isinstance(state, dict) or not isinstance(files, list):
        raise ValueError("portable snapshot manifest structure is invalid")
    if set(cast(dict[object, object], state)) != {
        "schema_version",
        "database_counts",
        "object_count",
        "private_receipt_count",
    }:
        raise ValueError("portable snapshot source state fields are invalid")
    for item in cast(list[object], files):
        if not isinstance(item, dict) or set(cast(dict[object, object], item)) != {
            "path",
            "role",
            "size",
            "sha256",
        }:
            raise ValueError("portable snapshot file entry fields are invalid")


def _validate_index_manifest(
    manifest: EncryptedObjectManifest,
    backend_profile: str,
    root_key_id: str,
) -> None:
    if manifest.state != ObjectState.VERIFIED:
        raise ValueError("portable export index is not verified")
    if manifest.backend_profile != backend_profile or manifest.root_key_id != root_key_id:
        raise ValueError("portable export index key or backend does not match")
    if manifest.media_type != PORTABLE_INDEX_MEDIA_TYPE:
        raise ValueError("portable export index media type is invalid")
    if manifest.legacy_source_object_id is not None:
        raise ValueError("portable export index contains a legacy identifier")


def _validate_portable_binding(
    kit: dict[str, Any],
    index: dict[str, Any],
    backend_profile: str,
    root_key_id: str,
) -> None:
    if kit["package_id"] != index["package_id"] or kit["created_at"] != index["created_at"]:
        raise RuntimeError("portable export kit does not match its encrypted index")
    if index["backend_profile"] != backend_profile or index["root_key_id"] != root_key_id:
        raise RuntimeError("portable export index key or backend does not match")


class _ReadOnlyFilesystemBackend:
    def __init__(self, root: Path) -> None:
        self._root = root
        if root.is_symlink() or not root.is_dir():
            raise ValueError(f"portable export must be a regular directory: {root}")
        self._objects = root / "objects"
        if self._objects.is_symlink() or not self._objects.is_dir():
            raise ValueError("portable export object directory is invalid")
        top_level = {path.name for path in root.iterdir()}
        if top_level != {PORTABLE_KIT, "objects"}:
            raise ValueError("portable export contains unexpected top-level entries")
        self._object_ids = self._scan_objects()

    @property
    def profile(self) -> str:
        return "filesystem-v1"

    def exists(self, storage_object_id: str) -> bool:
        _validate_storage_object_id(storage_object_id)
        return storage_object_id in self._object_ids

    def put_file(self, storage_object_id: str, source: Path) -> None:
        del storage_object_id, source
        raise RuntimeError("portable export backend is read-only")

    def open(self, storage_object_id: str) -> BinaryIO:
        _validate_storage_object_id(storage_object_id)
        if storage_object_id not in self._object_ids:
            raise KeyError(f"portable ciphertext object is missing: {storage_object_id}")
        path = self._objects / storage_object_id
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            os.close(descriptor)
            raise RuntimeError("portable ciphertext object is not a private regular file")
        return os.fdopen(descriptor, "rb")

    def stat(self, storage_object_id: str) -> BackendObjectStat:
        _validate_storage_object_id(storage_object_id)
        if storage_object_id not in self._object_ids:
            raise KeyError(f"portable ciphertext object is missing: {storage_object_id}")
        path = self._objects / storage_object_id
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("portable ciphertext object is not a regular file")
        details = path.stat()
        if details.st_nlink != 1:
            raise RuntimeError("portable ciphertext object must have exactly one hard link")
        return BackendObjectStat(
            byte_length=details.st_size,
            etag=f"{details.st_dev}:{details.st_ino}:{details.st_mtime_ns}",
        )

    def cleanup_incomplete(self, *, older_than_epoch: float) -> IncompleteCleanupReport:
        del older_than_epoch
        return IncompleteCleanupReport(
            removed_entries=(),
            removed_count=0,
            scanned_count=0,
            scan_truncated=False,
        )

    def verify_exact_object_set(self, expected: set[str]) -> None:
        observed = self._scan_objects()
        if observed != expected:
            missing = sorted(expected - observed)
            unexpected = sorted(observed - expected)
            raise RuntimeError(
                "portable ciphertext object set does not match the encrypted index: "
                f"missing={missing[:3]} unexpected={unexpected[:3]}"
            )

    def _scan_objects(self) -> set[str]:
        values: set[str] = set()
        for path in self._objects.iterdir():
            if len(values) > MAX_PORTABLE_FILES:
                raise ValueError("portable export exceeds its ciphertext object-count limit")
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("portable object directory contains an unsafe entry")
            _validate_storage_object_id(path.name)
            if path.stat().st_nlink != 1:
                raise RuntimeError("portable ciphertext object must have exactly one hard link")
            values.add(path.name)
        return values


def _open_read_only_database(path: Path) -> sqlite3.Connection:
    if path.is_symlink() or not path.is_file():
        raise ValueError("portable ledger database is unavailable")
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)


def _validated_relative_path(value: str) -> PurePosixPath:
    if len(value.encode("utf-8")) > MAX_RELATIVE_PATH_BYTES:
        raise ValueError("portable path exceeds its size limit")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or relative.as_posix() != value
        or ".." in relative.parts
        or "\\" in value
        or "\0" in value
    ):
        raise ValueError(f"unsafe portable path: {value}")
    return relative


def _strict_json(payload: bytes, label: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(payload, object_pairs_hook=reject_duplicates)
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"{label} is not valid JSON") from error


def _read_regular_file(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"file is unavailable: {path}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"file is unavailable: {path}")
        if before.st_size > limit:
            raise ValueError(f"file exceeds its size limit: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > limit:
        raise ValueError(f"file exceeds its size limit: {path}")
    if _stat_identity(before) != _stat_identity(after) or len(payload) != before.st_size:
        raise RuntimeError(f"file changed while it was read: {path}")
    return payload


def _write_new_private_file(path: Path, payload: bytes, *, mode: int) -> None:
    _ensure_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise ValueError(f"private output already exists: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(mode)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"private directory must not be a symlink: {path}")
    existed = path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not existed:
        path.chmod(0o700)
    details = path.stat()
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise RuntimeError(f"private directory is accessible by another user: {path}")


def _ensure_portable_output_parent(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"portable output parent must not be a symlink: {path}")
    existed = path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"portable output parent must be a directory: {path}")
    if not existed:
        path.chmod(0o700)


def _require_absent(path: Path, label: str) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"{label} already exists: {path}")


def _required_str(value: dict[object, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} is invalid")
    return item


def _required_int(value: dict[object, object], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise ValueError(f"{key} is invalid")
    return item


def _validate_package_id(value: str) -> None:
    if not _PACKAGE_ID.fullmatch(value):
        raise ValueError("portable package id is invalid")


def _validate_storage_object_id(value: str) -> None:
    if not _STORAGE_OBJECT_ID.fullmatch(value):
        raise ValueError("portable storage object id is invalid")


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


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns
