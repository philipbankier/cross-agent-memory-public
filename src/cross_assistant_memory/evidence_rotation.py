from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import closing
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import (
    MAX_MANIFEST_BYTES,
    MAX_OPERATIONAL_KEY_BYTES,
    EncryptedObjectManifest,
    FilesystemObjectBackend,
    ObjectState,
    OperationalKey,
    RootKey,
    rewrap_authenticated_manifest,
    validate_authenticated_manifest,
)
from cross_assistant_memory.private_json import load_owner_only_json, write_owner_only_json
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
    publish_file_no_replace,
)

if TYPE_CHECKING:
    from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
    from cross_assistant_memory.runtime_evidence import EvidenceConfig
    from cross_assistant_memory.storage import ExclusiveWriterToken

MAX_ROTATION_OBJECTS = 10_000
MAX_ROTATION_JOURNAL_BYTES = 32 * 1024 * 1024
MAX_EXTENDED_ROTATION_OBJECTS = 100_000
MAX_EXTENDED_ROTATION_INVENTORY_BYTES = 112 * 1024 * 1024
MAX_EXTENDED_ROTATION_JOURNAL_BYTES = 192 * 1024 * 1024
MAX_ROTATION_RUNTIME_BYTES = 32 * 1024
MAX_CONFIG_BYTES = 16 * 1024
_JOURNAL_GROWTH_RESERVE = MAX_ROTATION_RUNTIME_BYTES + 128
_PROCESS = uuid.uuid4().hex
_AAD = b"cross-assistant-memory:evidence-rotation:v1\0"
_PHASES = {"prepared", "mapped", "switched", "active", "reverting", "restored", "rolled_back"}
LEGACY_ROTATION_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS evidence_rotation (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  phase TEXT NOT NULL CHECK (phase IN ('prepared', 'mapped', 'switched', 'active',
                                      'reverting', 'restored', 'rolled_back')),
  restart_owner TEXT NOT NULL CHECK (length(restart_owner) = 32),
  journal_json TEXT NOT NULL CHECK (length(journal_json) <= {MAX_ROTATION_JOURNAL_BYTES}),
  authentication_tag TEXT NOT NULL CHECK (length(authentication_tag) <= 1024),
  runtime_json TEXT NOT NULL CHECK (length(runtime_json) <= {MAX_ROTATION_RUNTIME_BYTES})
);
"""
ROTATION_SCHEMA = LEGACY_ROTATION_SCHEMA.replace(
    str(MAX_ROTATION_JOURNAL_BYTES), str(MAX_EXTENDED_ROTATION_JOURNAL_BYTES)
)


@dataclass(frozen=True)
class RotationLimits:
    objects: int
    inventory_bytes: int
    journal_bytes: int


def _capacity_limits(capacity: str) -> RotationLimits:
    if capacity == "standard":
        return RotationLimits(
            MAX_ROTATION_OBJECTS, MAX_ROTATION_JOURNAL_BYTES // 3, MAX_ROTATION_JOURNAL_BYTES
        )
    if capacity == "extended":
        return RotationLimits(
            MAX_EXTENDED_ROTATION_OBJECTS,
            MAX_EXTENDED_ROTATION_INVENTORY_BYTES,
            MAX_EXTENDED_ROTATION_JOURNAL_BYTES,
        )
    raise ValueError("unsupported rotation capacity")


def _plan_limits(plan: dict[str, Any]) -> RotationLimits:
    if (
        type(plan.get("format_version")) is not int
        or plan.get("format_version") != 2
        or type(plan.get("capacity")) is not str
    ):
        raise ValueError("unsupported rotation plan format or capacity")
    limits = _capacity_limits(plan["capacity"])
    selected = plan.get("capacity_limits")
    # Retained journals keep their original authenticated bound after a capacity increase.
    previous_extended = (
        RotationLimits(50_000, 64 * 1024 * 1024, 192 * 1024 * 1024),
        RotationLimits(50_000, 80 * 1024 * 1024, 192 * 1024 * 1024),
        RotationLimits(64_000, 100 * 1024 * 1024, 192 * 1024 * 1024),
    )
    if plan["capacity"] == "extended":
        for issued in previous_extended:
            if selected == asdict(issued):
                limits = issued
                break
    if (
        type(selected) is not dict
        or selected != asdict(limits)
        or any(type(value) is not int for value in cast(dict[str, object], selected).values())
    ):
        raise ValueError("rotation capacity limits changed")
    return limits


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate rotation field")
        result[key] = value
    return result


def _document(raw: str, maximum: int) -> dict[str, Any]:
    if len(raw) > maximum or len(raw.encode()) > maximum:
        raise ValueError("rotation document exceeds its byte limit")
    value: object = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("rotation document must be an object")
    return cast(dict[str, Any], value)


@dataclass(frozen=True)
class FileBinding:
    path: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    sha256: str
    parent_device: int
    parent_inode: int

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> FileBinding:
        if set(value) != {field.name for field in fields(cls)}:
            raise ValueError("invalid rotation file binding")
        result = cls(**value)
        if (
            type(result.path) is not str
            or not Path(result.path).is_absolute()
            or type(result.sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", result.sha256) is None
            or any(
                type(value[name]) is not int or value[name] < 0
                for name in value
                if name not in {"path", "sha256"}
            )
        ):
            raise ValueError("invalid rotation file binding")
        return result


def capture_file(path: Path, maximum: int) -> tuple[FileBinding, bytes]:
    descriptor, normalized = open_regular_file_no_symlinks(path, "rotation input")
    parent = open_directory_no_symlinks(normalized.parent, "rotation input parent")
    try:
        before = os.fstat(descriptor)
        parent_stat = os.fstat(parent)
        if (
            before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size > maximum
            or parent_stat.st_uid != os.geteuid()
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
        ):
            raise ValueError("rotation input must be bounded owner-only material")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        current = os.stat(normalized.name, dir_fd=parent, follow_symlinks=False)

        def stamp(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
                item.st_mode,
                item.st_nlink,
            )

        if (
            stamp(before) != stamp(after)
            or stamp(after) != stamp(current)
            or len(raw) != before.st_size
        ):
            raise RuntimeError("rotation input changed while reading")
        check_parent = open_directory_no_symlinks(normalized.parent, "rotation input parent")
        try:
            check = os.fstat(check_parent)
            if (check.st_dev, check.st_ino) != (parent_stat.st_dev, parent_stat.st_ino):
                raise RuntimeError("rotation input parent changed")
        finally:
            os.close(check_parent)
        return FileBinding(
            str(normalized),
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            _hash(raw),
            parent_stat.st_dev,
            parent_stat.st_ino,
        ), raw
    finally:
        os.close(descriptor)
        os.close(parent)


def require_file(binding: FileBinding, maximum: int, *, at: Path | None = None) -> bytes:
    observed, raw = capture_file(at or Path(binding.path), maximum)
    expected = asdict(binding)
    expected["path"] = observed.path
    if asdict(observed) != expected:
        raise RuntimeError("rotation input identity or bytes changed")
    return raw


def key_fingerprint(root: RootKey) -> str:
    return _hash(_json([root.key_id, _hash(root.serialize_cleartext_keyset())]).encode())


def _load_key(path: Path) -> tuple[FileBinding, RootKey]:
    binding, _ = capture_file(path, MAX_OPERATIONAL_KEY_BYTES)
    root = OperationalKey.load(path).root_key
    require_file(binding, MAX_OPERATIONAL_KEY_BYTES)
    return binding, root


def _database_identity(settings: Settings) -> list[object]:
    descriptor, path = open_regular_file_no_symlinks(settings.database_path, "rotation database")
    try:
        details = os.fstat(descriptor)
        if details.st_nlink != 1 or details.st_uid != os.geteuid():
            raise ValueError("invalid rotation database ownership")
        return [str(path), details.st_dev, details.st_ino]
    finally:
        os.close(descriptor)


def rotation_present(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_rotation'"
        ).fetchone()
        is not None
    )


def require_rotation_access(
    connection: sqlite3.Connection,
    settings: Settings,
    reader: EncryptedEvidenceReader | None = None,
) -> None:
    if not rotation_present(connection):
        return
    row = connection.execute(
        "SELECT phase, CASE WHEN length(runtime_json) <= ? THEN runtime_json END "
        "FROM evidence_rotation WHERE singleton=1",
        (MAX_ROTATION_RUNTIME_BYTES,),
    ).fetchone()
    if row is None:
        return
    if row[0] not in {"active", "rolled_back"}:
        raise RuntimeError("evidence rotation requires maintenance resume or rollback and restart")
    try:
        runtime = _document(row[1], MAX_ROTATION_RUNTIME_BYTES)
        if set(runtime) != {"database", "config", "key", "key_fingerprint", "backend", "profile"}:
            raise ValueError("invalid runtime binding")
        if runtime["database"] != _database_identity(settings):
            raise ValueError("rotation belongs to a different node")
        if reader is not None and (
            key_fingerprint(reader.root_key) != runtime["key_fingerprint"]
            or reader.backend.identity_sha256 != runtime["backend"]
            or reader.backend.profile != runtime["profile"]
        ):
            raise ValueError("cached evidence key or backend is stale")
    except Exception:
        raise RuntimeError(
            "evidence rotation runtime binding changed; restart or inspect maintenance"
        ) from None


def check_rotation_access(
    settings: Settings,
    reader: EncryptedEvidenceReader | None = None,
    *,
    require_checkpointed: bool = False,
) -> None:
    from cross_assistant_memory.storage import open_maintenance_inspection

    if not settings.database_path.exists():
        return
    with closing(
        open_maintenance_inspection(settings, require_checkpointed=require_checkpointed)
    ) as connection:
        require_rotation_access(connection, settings, reader)


def _quiescent(connection: sqlite3.Connection, settings: Settings) -> None:
    from cross_assistant_memory.recovery import b2_backup_staging_path

    for sql in (
        "SELECT 1 FROM evidence_publication_work LIMIT 1",
        "SELECT 1 FROM deletion_operations WHERE status != 'complete' LIMIT 1",
        "SELECT 1 FROM encrypted_object_locations l JOIN objects o USING(object_id) "
        "WHERE o.storage_kind != 'encrypted' LIMIT 1",
        "SELECT 1 FROM objects o LEFT JOIN encrypted_object_locations l USING(object_id) "
        "WHERE o.storage_kind = 'encrypted' AND l.object_id IS NULL LIMIT 1",
    ):
        if connection.execute(sql).fetchone():
            raise RuntimeError(
                "rotation requires completed publication/deletion and consistent mappings"
            )
    stage = b2_backup_staging_path(settings)
    if stage.exists() or stage.is_symlink():
        raise RuntimeError("rotation refuses interrupted package staging")
    publication = settings.data_root / ".encrypted-evidence-publication"
    if publication.exists() or publication.is_symlink():
        descriptor = open_directory_no_symlinks(publication, "publication")
        try:
            with os.scandir(descriptor) as entries:
                for count, entry in enumerate(entries):
                    if count >= 2 or entry.name not in {"manifests", "staging"}:
                        raise RuntimeError("rotation refuses publication remnants")
                    child = open_directory_no_symlinks(publication / entry.name, "publication")
                    try:
                        with os.scandir(child) as files:
                            if next(files, None) is not None:
                                raise RuntimeError("rotation refuses publication remnants")
                    finally:
                        os.close(child)
        finally:
            os.close(descriptor)


def _inventory(connection: sqlite3.Connection, limits: RotationLimits) -> list[dict[str, Any]]:
    if (
        connection.execute("SELECT count(*) FROM encrypted_object_locations").fetchone()[0]
        > limits.objects
    ):
        raise ValueError("rotation inventory exceeds its object limit")
    inventory: list[dict[str, Any]] = []
    total = 0
    for row in connection.execute(
        "SELECT l.object_id, o.byte_length, l.source_object_id, l.storage_object_id, "
        "l.backend_profile, l.backend_identity_sha256, "
        "CASE WHEN length(l.manifest_json) <= ? THEN l.manifest_json END "
        "FROM encrypted_object_locations l JOIN objects o USING(object_id) ORDER BY l.object_id",
        (MAX_MANIFEST_BYTES,),
    ):
        if row[6] is None:
            raise ValueError("rotation manifest exceeds its byte limit")
        item: dict[str, Any] = dict(
            zip(
                ("object_id", "size", "source", "storage", "profile", "backend", "before"),
                row,
                strict=True,
            )
        )
        total += len(_json(item).encode())
        if total > limits.inventory_bytes:
            raise ValueError("rotation inventory exceeds its journal budget")
        inventory.append(item)
    if not inventory:
        raise ValueError("rotation requires mapped encrypted evidence")
    return inventory


def _authenticate(
    item: dict[str, Any], raw: str, root: RootKey, plan: dict[str, Any]
) -> EncryptedObjectManifest:
    manifest = EncryptedObjectManifest.from_dict(_document(raw, MAX_MANIFEST_BYTES))
    if (
        manifest.legacy_source_object_id != item["object_id"]
        or item["object_id"] != f"sha256:{manifest.plaintext_sha256}"
        or manifest.plaintext_byte_length != item["size"]
        or (manifest.source_object_id, manifest.storage_object_id, manifest.backend_profile)
        != (item["source"], item["storage"], item["profile"])
        or item["backend"] != plan["backend"]
        or item["profile"] != plan["profile"]
    ):
        raise ValueError("rotation manifest identity differs from the ledger")
    validate_authenticated_manifest(
        root,
        manifest,
        backend_profile=plan["profile"],
        max_plaintext_bytes=plan["plaintext_limit"],
        max_ciphertext_bytes=plan["ciphertext_limit"],
        allowed_states=(ObjectState.VERIFIED,),
    )
    return manifest


def _plan(
    connection: sqlite3.Connection,
    settings: Settings,
    config_path: Path,
    new_key_path: Path,
    capacity: str,
) -> tuple[dict[str, Any], RootKey, RootKey]:
    from cross_assistant_memory.runtime_evidence import EvidenceConfig
    from cross_assistant_memory.storage import (
        SCHEMA_VERSION,
        maintenance_generation,
        validate_current_schema_objects,
    )

    limits = _capacity_limits(capacity)
    if (
        connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        != SCHEMA_VERSION
    ):
        raise RuntimeError("rotation requires the current schema; upgrade separately")
    validate_current_schema_objects(connection)
    prior = connection.execute(
        "SELECT singleton, phase, restart_owner, "
        "CASE WHEN length(journal_json)<=? THEN journal_json END, "
        "CASE WHEN length(authentication_tag)<=1024 THEN authentication_tag END, "
        "CASE WHEN length(runtime_json)<=? THEN runtime_json END "
        "FROM evidence_rotation WHERE singleton=1",
        (MAX_EXTENDED_ROTATION_JOURNAL_BYTES, MAX_ROTATION_RUNTIME_BYTES),
    ).fetchone()
    supersedes = None
    prior_digest = None
    if prior is not None:
        require_rotation_access(connection, settings)
        _, _, prior_journal, _ = _read_journal(connection)
        supersedes = prior_journal["operation_id"]
        prior_digest = _hash(_json(tuple(prior)).encode())
    _quiescent(connection, settings)
    config_binding, raw = capture_file(config_path, MAX_CONFIG_BYTES)
    config_dict = _document(raw.decode(), MAX_CONFIG_BYTES)
    config = EvidenceConfig.from_dict(config_dict)
    if config.data_root != settings.data_root.resolve(strict=True):
        raise ValueError("rotation configuration belongs to another root")
    new_path = new_key_path.resolve(strict=True)
    if new_path != new_key_path or new_path.is_relative_to(config.data_root):
        raise ValueError("new rotation key requires an external physical path")
    old_binding, old_root = _load_key(config.operational_key)
    new_binding, new_root = _load_key(new_path)
    if (
        old_root.key_id == new_root.key_id
        or old_root.serialize_cleartext_keyset() == new_root.serialize_cleartext_keyset()
    ):
        raise ValueError("rotation requires distinct root IDs and key material")
    profile, identity = _backend_binding(config)
    if prior is not None:
        committed = _document(prior[5], MAX_ROTATION_RUNTIME_BYTES)
        if key_fingerprint(old_root) != committed["key_fingerprint"]:
            raise ValueError("rotation must start with the committed root")
        if (profile, identity) != (committed["profile"], committed["backend"]):
            raise ValueError("rotation must preserve the committed backend domain")
    updated_config = {**config_dict, "operational_key": str(new_path)}
    plan: dict[str, Any] = {
        "format_version": 2,
        "capacity": capacity,
        "capacity_limits": asdict(limits),
        "database": _database_identity(settings),
        "config": asdict(config_binding),
        "config_before": raw.decode(),
        "config_after": updated_config,
        "old_key": asdict(old_binding),
        "new_key": asdict(new_binding),
        "old_fingerprint": key_fingerprint(old_root),
        "new_fingerprint": key_fingerprint(new_root),
        "profile": profile,
        "backend": identity,
        "plaintext_limit": config.max_plaintext_bytes,
        "ciphertext_limit": config.max_ciphertext_bytes,
        "before_generation": maintenance_generation(connection),
        "inventory": _inventory(connection, limits),
        "supersedes_operation_id": supersedes,
        "prior_journal_sha256": prior_digest,
    }
    for item in plan["inventory"]:
        _authenticate(item, item["before"], old_root, plan)
    require_file(config_binding, MAX_CONFIG_BYTES)
    require_file(old_binding, MAX_OPERATIONAL_KEY_BYTES)
    require_file(new_binding, MAX_OPERATIONAL_KEY_BYTES)
    return plan, old_root, new_root


def _backend_binding(config: EvidenceConfig) -> tuple[str, str]:
    if isinstance(config.backend, Path):
        backend = FilesystemObjectBackend(config.backend, create=False)
        return backend.profile, backend.identity_sha256
    profile = "backblaze-b2-s3-v1"
    return profile, _hash(
        json.dumps(
            [profile, config.backend.bucket, config.backend.endpoint_url], separators=(",", ":")
        ).encode()
    )


def plan_rotation(
    settings: Settings, config: Path, new_key: Path, *, capacity: str = "standard"
) -> dict[str, Any]:
    from cross_assistant_memory.storage import open_maintenance_inspection

    _database_identity(settings)
    with closing(open_maintenance_inspection(settings)) as connection:
        connection.execute("BEGIN")
        plan, _, _ = _plan(connection, settings, config, new_key, capacity)
    digest = _hash(_json(plan).encode())
    return {
        "status": "planned",
        "plan_sha256": digest,
        "operation_id": "rotation_" + digest[:32],
        "capacity": capacity,
        "capacity_limits": plan["capacity_limits"],
        "object_count": len(plan["inventory"]),
        "generation_digest": plan["before_generation"],
        "scope": "primary-evidence-maintenance",
        "supersedes_operation_id": plan["supersedes_operation_id"],
        "restart_required": True,
    }


def _runtime(plan: dict[str, Any], config: FileBinding, *, old: bool) -> str:
    return _json(
        {
            "database": plan["database"],
            "config": asdict(config),
            "key": plan["old_key" if old else "new_key"],
            "key_fingerprint": plan["old_fingerprint" if old else "new_fingerprint"],
            "backend": plan["backend"],
            "profile": plan["profile"],
        }
    )


def _read_journal(connection: sqlite3.Connection) -> tuple[str, str, dict[str, Any], str]:
    row = connection.execute(
        "SELECT phase, restart_owner, CASE WHEN length(journal_json)<=? THEN journal_json END, "
        "CASE WHEN length(authentication_tag)<=1024 THEN authentication_tag END "
        "FROM evidence_rotation WHERE singleton=1",
        (MAX_EXTENDED_ROTATION_JOURNAL_BYTES,),
    ).fetchone()
    if row is None or row[0] not in _PHASES or row[2] is None or row[3] is None:
        raise RuntimeError("rotation journal is unavailable")
    journal = _document(row[2], MAX_EXTENDED_ROTATION_JOURNAL_BYTES)
    if (
        set(journal) - {"new_config", "after_generation"} != {"operation_id", "plan"}
        or type(journal["operation_id"]) is not str
        or re.fullmatch(r"rotation_[0-9a-f]{32}", journal["operation_id"]) is None
        or type(journal["plan"]) is not dict
    ):
        raise ValueError("invalid rotation journal")
    plan = cast(dict[str, Any], journal["plan"])
    limits = _plan_limits(plan)
    if len(row[2].encode()) > limits.journal_bytes:
        raise ValueError("rotation journal exceeds its selected byte limit")
    inventory = plan.get("inventory")
    if type(inventory) is not list or not 0 < len(cast(list[object], inventory)) <= limits.objects:
        raise ValueError("invalid rotation inventory")
    return row[0], row[1], journal, row[3]


def rotation_status(settings: Settings) -> dict[str, Any]:
    from cross_assistant_memory.storage import open_maintenance_inspection

    _database_identity(settings)
    with closing(open_maintenance_inspection(settings)) as connection:
        if (
            not rotation_present(connection)
            or not connection.execute("SELECT 1 FROM evidence_rotation").fetchone()
        ):
            return {"status": "not_started"}
        phase, _, journal, _ = _read_journal(connection)
        return {
            "status": phase,
            "operation_id": journal["operation_id"],
            "object_count": len(journal["plan"]["inventory"]),
            "capacity": journal["plan"]["capacity"],
            "restart_required": phase not in {"active", "rolled_back"},
        }


def _set_phase(connection: sqlite3.Connection, phase: str, *, restart: bool = False) -> None:
    if restart:
        connection.execute(
            "UPDATE evidence_rotation SET phase=?, restart_owner=? WHERE singleton=1",
            (phase, _PROCESS),
        )
    else:
        connection.execute("UPDATE evidence_rotation SET phase=? WHERE singleton=1", (phase,))


def _checkpoint(label: str) -> None:
    """Fault-injection boundary after a durable maintenance step."""


def apply_rotation(
    settings: Settings,
    config: Path,
    new_key: Path,
    *,
    expected_plan_sha256: str,
    execute: bool = False,
    supersede_operation_id: str | None = None,
    capacity: str = "standard",
) -> dict[str, Any]:
    from cross_assistant_memory.storage import Ledger, exclusive_ledger_writer

    if not execute:
        return plan_rotation(settings, config, new_key, capacity=capacity)
    _database_identity(settings)
    with exclusive_ledger_writer(settings) as token:
        ledger = Ledger(settings, exclusive_writer_token=token)
        with closing(ledger.maintenance_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            plan, old_root, new_root = _plan(connection, settings, config, new_key, capacity)
            limits = _plan_limits(plan)
            if _hash(_json(plan).encode()) != expected_plan_sha256:
                raise RuntimeError("rotation plan changed")
            if supersede_operation_id != plan["supersedes_operation_id"]:
                raise RuntimeError(
                    "rotation requires explicit supersession of the prior rollback scope"
                )
            after_bytes = 0
            for item in plan["inventory"]:
                manifest = _authenticate(item, item["before"], old_root, plan)
                updated = rewrap_authenticated_manifest(
                    manifest,
                    old_root,
                    new_root,
                    backend_profile=plan["profile"],
                    max_plaintext_bytes=plan["plaintext_limit"],
                    max_ciphertext_bytes=plan["ciphertext_limit"],
                    allowed_states=(ObjectState.VERIFIED,),
                )
                updated_raw = _json(updated.as_dict())
                after_bytes += len(_json({**item, "before": updated_raw}).encode())
                if after_bytes > limits.inventory_bytes:
                    raise ValueError("rewrapped rotation inventory exceeds its journal budget")
                item["after"] = updated_raw
            operation = "rotation_" + expected_plan_sha256[:32]
            journal = {"operation_id": operation, "plan": plan}
            raw = _json(journal)
            if len(raw.encode()) > limits.journal_bytes - _JOURNAL_GROWTH_RESERVE:
                raise ValueError("rotation journal exceeds its byte limit with recovery reserve")
            tag = base64.b64encode(old_root.primitive().encrypt(b"", _AAD + raw.encode())).decode()
            connection.execute("DELETE FROM evidence_rotation WHERE singleton=1")
            connection.execute(
                "INSERT INTO evidence_rotation VALUES (1, 'prepared', ?, ?, ?, ?)",
                (
                    _PROCESS,
                    raw,
                    tag,
                    _runtime(plan, FileBinding.from_dict(plan["config"]), old=True),
                ),
            )
        _checkpoint("prepared")
        # The recovery path reads its own authenticated journal; release preparation copies first.
        del plan, journal, raw
        return _continue(settings, token, operation, rollback=False)


def resume_rotation(
    settings: Settings, operation_id: str, *, rollback: bool = False, execute: bool = False
) -> dict[str, Any]:
    from cross_assistant_memory.storage import exclusive_ledger_writer, recover_maintenance_database

    if not execute:
        return rotation_status(settings)
    _database_identity(settings)
    with exclusive_ledger_writer(settings) as token:
        recover_maintenance_database(settings, token)
        return _continue(settings, token, operation_id, rollback=rollback)


def _config_paths(plan: dict[str, Any], operation: str) -> tuple[Path, Path, Path]:
    config = Path(plan["config"]["path"])
    return config, config.parent / f".{operation}.before", config.parent / f".{operation}.after"


def _move(source: Path, target: Path, binding: FileBinding) -> None:
    require_file(binding, MAX_CONFIG_BYTES, at=source)
    publish_file_no_replace(
        source, target, required_mode=0o400, label="rotation configuration", retain_on_failure=True
    )
    require_file(binding, MAX_CONFIG_BYTES, at=target)


def _switch_config(
    connection: sqlite3.Connection, journal: dict[str, Any], *, old: bool
) -> FileBinding:
    plan = journal["plan"]
    config, before, after = _config_paths(plan, journal["operation_id"])
    original = FileBinding.from_dict(plan["config"])
    if old and "new_config" not in journal:
        require_file(original, MAX_CONFIG_BYTES)
        _flush_config_parent(config)
        return original
    if "new_config" not in journal:
        if after.exists() or after.is_symlink():
            raw = load_owner_only_json(after, label="rotation config", max_bytes=MAX_CONFIG_BYTES)
            if raw != plan["config_after"]:
                raise RuntimeError("rotation staging configuration changed")
        else:
            write_owner_only_json(
                after, plan["config_after"], label="rotation config", max_bytes=MAX_CONFIG_BYTES
            )
        new_binding, _ = capture_file(after, MAX_CONFIG_BYTES)
        if len(_json(asdict(new_binding)).encode()) > MAX_ROTATION_RUNTIME_BYTES:
            raise ValueError("rotation configuration binding exceeds its recovery reserve")
        journal["new_config"] = asdict(new_binding)
        _save_journal(connection, journal)
        connection.commit()
        _checkpoint("config_staged")
    replacement = FileBinding.from_dict(journal["new_config"])
    wanted, other = (original, replacement) if old else (replacement, original)
    retained_wanted, retained_other = (before, after) if old else (after, before)
    if config.exists() or config.is_symlink():
        current, _ = capture_file(config, MAX_CONFIG_BYTES)
        if (
            current.sha256 == wanted.sha256
            and current.inode == wanted.inode
            and current.device == wanted.device
        ):
            require_file(wanted, MAX_CONFIG_BYTES, at=config)
            _flush_config_parent(config)
            return current
        require_file(other, MAX_CONFIG_BYTES, at=config)
        _move(config, retained_other, other)
        _checkpoint("config_detached")
    require_file(other, MAX_CONFIG_BYTES, at=retained_other)
    _move(retained_wanted, config, wanted)
    _checkpoint("config_published")
    require_file(wanted, MAX_CONFIG_BYTES, at=config)
    return capture_file(config, MAX_CONFIG_BYTES)[0]


def _flush_config_parent(config: Path) -> None:
    descriptor = open_directory_no_symlinks(config.parent, "rotation configuration parent")
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _save_journal(connection: sqlite3.Connection, journal: dict[str, Any]) -> None:
    plan = journal["plan"]
    _, root = _load_key(Path(plan["old_key"]["path"]))
    require_file(FileBinding.from_dict(plan["old_key"]), MAX_OPERATIONAL_KEY_BYTES)
    raw = _json(journal)
    if len(raw.encode()) > _plan_limits(plan).journal_bytes:
        raise ValueError("rotation journal exceeds its byte limit")
    tag = base64.b64encode(root.primitive().encrypt(b"", _AAD + raw.encode())).decode()
    connection.execute(
        "UPDATE evidence_rotation SET journal_json=?, authentication_tag=? WHERE singleton=1",
        (raw, tag),
    )


def _continue(
    settings: Settings, token: ExclusiveWriterToken, operation: str, *, rollback: bool
) -> dict[str, Any]:
    from cross_assistant_memory.runtime_evidence import EvidenceConfig
    from cross_assistant_memory.storage import (
        Ledger,
        maintenance_generation,
        record_rotation_mutation,
    )

    ledger = Ledger(settings, exclusive_writer_token=token, rotation_maintenance=True)
    with closing(ledger.maintenance_connection()) as connection:
        phase, owner, journal, tag = _read_journal(connection)
        if (
            re.fullmatch(r"rotation_[0-9a-f]{32}", operation) is None
            or journal["operation_id"] != operation
        ):
            raise ValueError("rotation operation identity changed")
        plan = journal["plan"]
        if plan["database"] != _database_identity(settings):
            raise RuntimeError("rotation database identity changed")
        old_binding, old_root = _load_key(Path(plan["old_key"]["path"]))
        new_binding, new_root = _load_key(Path(plan["new_key"]["path"]))
        if asdict(old_binding) != plan["old_key"] or asdict(new_binding) != plan["new_key"]:
            raise RuntimeError("rotation key file changed")
        try:
            if (
                old_root.primitive().decrypt(
                    base64.b64decode(tag, validate=True), _AAD + _json(journal).encode()
                )
                != b""
            ):
                raise ValueError("invalid tag plaintext")
        except Exception:
            raise RuntimeError("rotation journal authentication failed") from None
        if _backend_binding(EvidenceConfig.from_dict(plan["config_after"])) != (
            plan["profile"],
            plan["backend"],
        ):
            raise RuntimeError("rotation backend namespace changed")
        _quiescent(connection, settings)
        current = _inventory(connection, _plan_limits(plan))
        matches_before = matches_after = len(current) == len(plan["inventory"])
        if matches_before:
            for observed, item in zip(current, plan["inventory"], strict=True):
                before = {k: v for k, v in item.items() if k != "after"}
                matches_before = matches_before and observed == before
                matches_after = matches_after and observed == {**before, "before": item["after"]}
        del current
        generation = maintenance_generation(connection)
        is_before = matches_before and generation == plan["before_generation"]
        is_after = matches_after and generation == journal.get("after_generation")
        if not is_before and not is_after:
            raise RuntimeError("rotation refuses intervening ledger writes or changed inventory")
        if (phase in {"prepared", "restored", "rolled_back"} and not is_before) or (
            phase in {"mapped", "switched", "active"} and not is_after
        ):
            raise RuntimeError("rotation phase does not match its ledger state")
        _require_config_state(journal)
        for item in plan["inventory"]:
            _authenticate(item, item["before"], old_root, plan)
            _authenticate(item, item["after"], new_root, plan)
        if rollback and phase not in {"reverting", "restored", "rolled_back"}:
            with connection:
                _set_phase(connection, "reverting", restart=True)
            owner, phase = _PROCESS, "reverting"
            _checkpoint("reverting")
        reverse = phase in {"reverting", "restored", "rolled_back"}
        if phase in {"active", "rolled_back"}:
            require_rotation_access(connection, settings)
            return {"status": phase, "operation_id": operation, "restart_required": False}
        if phase == "prepared" or phase == "reverting":
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                for binding in (old_binding, new_binding):
                    require_file(binding, MAX_OPERATIONAL_KEY_BYTES)
                if phase == "prepared":
                    require_file(FileBinding.from_dict(plan["config"]), MAX_CONFIG_BYTES)
                for item in plan["inventory"]:
                    connection.execute(
                        "UPDATE encrypted_object_locations SET manifest_json=? WHERE object_id=?",
                        (item["before" if reverse else "after"], item["object_id"]),
                    )
                updated_generation = maintenance_generation(connection)
                if updated_generation != generation:
                    record_rotation_mutation(
                        connection, operation, generation, updated_generation, rollback=reverse
                    )
                if not reverse:
                    journal["after_generation"] = maintenance_generation(connection)
                    _save_journal(connection, journal)
                _set_phase(connection, "restored" if reverse else "mapped")
                _checkpoint("before_mapping_commit")
                for binding in (old_binding, new_binding):
                    require_file(binding, MAX_OPERATIONAL_KEY_BYTES)
                _require_config_state(journal)
            phase = "restored" if reverse else "mapped"
            _checkpoint(phase)
        config = _switch_config(connection, journal, old=reverse)
        for binding in (old_binding, new_binding):
            require_file(binding, MAX_OPERATIONAL_KEY_BYTES)
        with connection:
            connection.execute(
                "UPDATE evidence_rotation SET runtime_json=? WHERE singleton=1",
                (_runtime(plan, config, old=reverse),),
            )
            _set_phase(connection, "restored" if reverse else "switched")
        _checkpoint("config_committed")
        if owner == _PROCESS:
            return {
                "status": "restart_required",
                "operation_id": operation,
                "restart_required": True,
            }
        # Only a fresh maintenance process can release the fence after loading the selected key.
        selected, selected_root = _load_key(Path(plan["old_key" if reverse else "new_key"]["path"]))
        require_file(config, MAX_CONFIG_BYTES)
        if (
            key_fingerprint(selected_root)
            != plan["old_fingerprint" if reverse else "new_fingerprint"]
        ):
            raise RuntimeError("rotation restart selected the wrong key")
        require_file(selected, MAX_OPERATIONAL_KEY_BYTES)
        _quiescent(connection, settings)
        with connection:
            _set_phase(connection, "rolled_back" if reverse else "active")
        _checkpoint("complete")
        return {
            "status": "rolled_back" if reverse else "active",
            "operation_id": operation,
            "restart_required": False,
            "object_count": len(plan["inventory"]),
        }


def _require_config_state(journal: dict[str, Any]) -> None:
    plan = journal["plan"]
    config, before, after = _config_paths(plan, journal["operation_id"])
    original = FileBinding.from_dict(plan["config"])
    replacement = FileBinding.from_dict(journal["new_config"]) if "new_config" in journal else None
    if config.exists() or config.is_symlink():
        observed, _ = capture_file(config, MAX_CONFIG_BYTES)
        candidates = [original] + ([replacement] if replacement is not None else [])
        if not any(
            {**asdict(item), "path": str(config)} == asdict(observed) for item in candidates
        ):
            raise RuntimeError("rotation configuration changed")
        if replacement is not None:
            if observed.inode == original.inode and observed.device == original.device:
                require_file(replacement, MAX_CONFIG_BYTES, at=after)
            else:
                require_file(original, MAX_CONFIG_BYTES, at=before)
    elif replacement is None:
        raise RuntimeError("rotation configuration is missing")
    else:
        require_file(original, MAX_CONFIG_BYTES, at=before)
        require_file(replacement, MAX_CONFIG_BYTES, at=after)
