from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import closing
from pathlib import Path
from typing import TypedDict, cast

from cross_assistant_memory.config import Settings, default_data_root
from cross_assistant_memory.encrypted_objects import ObjectState
from cross_assistant_memory.evidence_locations import read_location
from cross_assistant_memory.evidence_publication import require_mapping_state
from cross_assistant_memory.safe_files import (
    open_regular_file_no_symlinks,
    publish_file_no_replace,
)
from cross_assistant_memory.storage import SCHEMA_VERSION, Ledger

MATERIALIZATION_RECEIPT_ROOT = Path("runs/private/storage-materialization")
MAX_MATERIALIZATION_RECEIPT_BYTES = 64 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_OBJECT_METADATA = (
    "SELECT object_id, plaintext_digest, byte_length, media_type, object_path "
    "FROM objects ORDER BY object_id"
)


class StorageMaterialization(TypedDict):
    receipt_path: str
    receipt_sha256: str
    receipt_byte_length: int
    source_generation: str
    restored_generation: str
    object_count: int


class _RemoteObject(TypedDict):
    object_id: str
    source_object_id: str
    storage_object_id: str
    backend_profile: str
    backend_identity_sha256: str
    root_key_id: str
    ciphertext_sha256: str
    ciphertext_byte_length: int


class _MaterializationReceipt(TypedDict):
    format_version: int
    source_schema_version: int
    restored_schema_version: int
    source_snapshot_manifest_sha256: str
    source_generation: str
    restored_generation: str
    retained_remote_objects: list[_RemoteObject]


def materialize_verified_snapshot(
    settings: Settings,
    *,
    snapshot_manifest_sha256: str,
    snapshot_generation: str,
    snapshot_schema_version: int,
) -> StorageMaterialization | None:
    """Remap only an unpublished, already hash-verified snapshot copy, never its source."""
    if settings.data_root.resolve() == default_data_root().resolve():
        raise ValueError("snapshot materialization cannot target the default live root")
    if any(
        _SHA256.fullmatch(value) is None
        for value in (snapshot_manifest_sha256, snapshot_generation)
    ):
        raise ValueError("snapshot materialization requires exact source digests")
    ledger = Ledger(settings, read_only=True, require_checkpointed=False)
    if snapshot_schema_version < 18:
        raise ValueError("snapshot schema does not support encrypted evidence mappings")
    if ledger.generation_digest(schema_version=snapshot_schema_version) != snapshot_generation:
        raise RuntimeError("snapshot generation changed before storage materialization")
    # Schema 17 predates storage mappings; its digest keeps content and policy identity separate.
    semantic_generation = ledger.generation_digest(schema_version=17)
    retained: list[_RemoteObject] = []
    with closing(sqlite3.connect(settings.database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        with connection:
            original_objects = connection.execute(_OBJECT_METADATA).fetchall()
            rows = connection.execute(
                "SELECT object_id, storage_kind FROM objects ORDER BY object_id"
            ).fetchall()
            for object_id, kind in rows:
                location = read_location(connection, object_id)
                require_mapping_state(kind, location)
                if location is None:
                    continue
                identity, manifest = location
                if manifest.state != ObjectState.VERIFIED or kind != "encrypted":
                    raise RuntimeError("pending evidence cannot be materialized for restore")
                retained.append(
                    _RemoteObject(
                        object_id=object_id,
                        source_object_id=manifest.source_object_id,
                        storage_object_id=manifest.storage_object_id,
                        backend_profile=manifest.backend_profile,
                        backend_identity_sha256=identity,
                        root_key_id=manifest.root_key_id,
                        ciphertext_sha256=manifest.ciphertext_sha256,
                        ciphertext_byte_length=manifest.ciphertext_byte_length,
                    )
                )
            if not retained:
                return None
            count = cast(
                int,
                connection.execute("SELECT COUNT(*) FROM encrypted_object_locations").fetchone()[0],
            )
            if count != len(retained):
                raise RuntimeError("snapshot has orphaned encrypted locations")
            connection.execute(
                "UPDATE objects SET storage_kind = 'local' WHERE storage_kind = 'encrypted'"
            )
            connection.execute("DELETE FROM encrypted_object_locations")
            if connection.execute(_OBJECT_METADATA).fetchall() != original_objects:
                raise RuntimeError("snapshot materialization changed evidence identities")
        connection.execute("VACUUM")
    if ledger.generation_digest(schema_version=17) != semantic_generation:
        raise RuntimeError("snapshot materialization changed content or policy")
    restored_generation = ledger.generation_digest()
    receipt = _MaterializationReceipt(
        format_version=1,
        source_schema_version=snapshot_schema_version,
        restored_schema_version=SCHEMA_VERSION,
        source_snapshot_manifest_sha256=snapshot_manifest_sha256,
        source_generation=snapshot_generation,
        restored_generation=restored_generation,
        retained_remote_objects=retained,
    )
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > MAX_MATERIALIZATION_RECEIPT_BYTES:
        raise RuntimeError("snapshot materialization receipt exceeds its byte budget")
    digest = hashlib.sha256(payload).hexdigest()
    relative = MATERIALIZATION_RECEIPT_ROOT / f"{digest}.json"
    result = StorageMaterialization(
        receipt_path=relative.as_posix(),
        receipt_sha256=digest,
        receipt_byte_length=len(payload),
        source_generation=snapshot_generation,
        restored_generation=restored_generation,
        object_count=len(retained),
    )
    _write_receipt(settings, relative, payload)
    verify_storage_materialization_receipt(settings, result)
    return result


def verify_storage_materialization_receipt(
    settings: Settings, materialization: StorageMaterialization
) -> None:
    """Verify the exact receipt and fresh restored generation, not provider-side erasure."""
    digest = materialization["receipt_sha256"]
    size = materialization["receipt_byte_length"]
    relative = MATERIALIZATION_RECEIPT_ROOT / f"{digest}.json"
    if (
        _SHA256.fullmatch(digest) is None
        or materialization["receipt_path"] != relative.as_posix()
        or type(size) is not int
        or not 0 < size <= MAX_MATERIALIZATION_RECEIPT_BYTES
        or type(materialization["object_count"]) is not int
        or materialization["object_count"] <= 0
    ):
        raise ValueError("snapshot materialization receipt binding is invalid")
    path = settings.data_root.resolve() / relative
    descriptor, _ = open_regular_file_no_symlinks(path, "snapshot materialization receipt")
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if (
            before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
            or before.st_size != size
        ):
            raise RuntimeError("snapshot materialization receipt identity is invalid")
        payload = handle.read(size + 1)
        after = os.fstat(handle.fileno())
        published = path.lstat()
    if (
        len(payload) != size
        or hashlib.sha256(payload).hexdigest() != digest
        or any(
            (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            for item in (after, published)
        )
    ):
        raise RuntimeError("snapshot materialization receipt failed verification")
    receipt = cast(_MaterializationReceipt, json.loads(payload))
    if (
        receipt["format_version"] != 1
        or not 18 <= receipt["source_schema_version"] <= SCHEMA_VERSION
        or not receipt["source_schema_version"]
        <= receipt["restored_schema_version"]
        <= SCHEMA_VERSION
        or receipt["source_generation"] != materialization["source_generation"]
        or receipt["restored_generation"] != materialization["restored_generation"]
        or len(receipt["retained_remote_objects"]) != materialization["object_count"]
        or Ledger(settings, read_only=True, require_checkpointed=False).generation_digest(
            schema_version=receipt["restored_schema_version"]
        )
        != materialization["restored_generation"]
    ):
        raise RuntimeError("snapshot materialization receipt generation does not match")


def _write_receipt(settings: Settings, relative: Path, payload: bytes) -> None:
    root = settings.data_root.resolve()
    destination = root / relative
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        current.mkdir(mode=0o700, exist_ok=True)
        details = current.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise RuntimeError("snapshot materialization receipt directory is not private")
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.partial")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        publish_file_no_replace(
            temporary, destination, required_mode=0o400, label="snapshot materialization receipt"
        )
    finally:
        temporary.unlink(missing_ok=True)
