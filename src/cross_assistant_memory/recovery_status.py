from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from cross_assistant_memory.config import Settings
from cross_assistant_memory.safe_files import publish_file_no_replace

BACKUP_RECEIPT_ROOT = Path("runs/private/recovery-backups")
RESTORE_RECEIPT_ROOT = Path("runs/private/recovery-restores")
RECOVERY_STATUS_FORMAT_VERSION = 1
MAX_RECOVERY_RECEIPT_BYTES = 64 * 1024
MAX_RECOVERY_RECEIPTS = 10_000

_PACKAGE_ID = re.compile(r"package_[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_BACKEND_PROFILE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_RECEIPT_FILENAME = re.compile(r"(package_[0-9a-f]{32})\.([0-9a-f]{64})\.json")
_RECEIPT_STAGING_FILENAME = re.compile(
    r"\.package_[0-9a-f]{32}\.[0-9a-f]{64}\.json\.[0-9a-f]{32}\.partial"
)


def record_successful_backup(
    settings: Settings,
    *,
    created_at: str,
    package_id: str,
    package_kit_sha256: str,
    snapshot_manifest_sha256: str,
    source_ledger_generation: str,
    backend_profile: str,
) -> dict[str, object]:
    receipt: dict[str, object] = {
        "format_version": RECOVERY_STATUS_FORMAT_VERSION,
        "created_at": created_at,
        "package_id": package_id,
        "package_kit_sha256": package_kit_sha256,
        "snapshot_manifest_sha256": snapshot_manifest_sha256,
        "source_ledger_generation": source_ledger_generation,
        "backend_profile": backend_profile,
    }
    validated = _validate_backup_receipt(receipt)
    return _publish_receipt(settings, BACKUP_RECEIPT_ROOT, package_id, validated)


def record_verified_restore(
    settings: Settings,
    *,
    verified_at: str,
    package_id: str,
    package_kit_sha256: str,
    snapshot_manifest_sha256: str,
    source_ledger_generation: str,
    known_query_count: int,
    known_query_receipts_sha256: str,
) -> dict[str, object]:
    receipt: dict[str, object] = {
        "format_version": RECOVERY_STATUS_FORMAT_VERSION,
        "verified_at": verified_at,
        "package_id": package_id,
        "package_kit_sha256": package_kit_sha256,
        "snapshot_manifest_sha256": snapshot_manifest_sha256,
        "source_ledger_generation": source_ledger_generation,
        "known_query_count": known_query_count,
        "known_query_receipts_sha256": known_query_receipts_sha256,
    }
    validated = _validate_restore_receipt(receipt)
    return _publish_receipt(settings, RESTORE_RECEIPT_ROOT, package_id, validated)


def inspect_recovery_status(settings: Settings) -> dict[str, object]:
    backups, invalid_backups = _load_receipts(
        settings,
        BACKUP_RECEIPT_ROOT,
        _validate_backup_receipt,
        timestamp_field="created_at",
    )
    restores, invalid_restores = _load_receipts(
        settings,
        RESTORE_RECEIPT_ROOT,
        _validate_restore_receipt,
        timestamp_field="verified_at",
    )
    invalid_count = invalid_backups + invalid_restores
    last_backup = backups[-1] if backups else None
    last_restore = restores[-1] if restores else None
    if invalid_count:
        status = "evidence_invalid"
    elif last_backup is not None and last_restore is not None:
        status = "backup_and_restore_verified"
    elif last_backup is not None:
        status = "backup_recorded"
    elif last_restore is not None:
        status = "restore_verified"
    else:
        status = "not_recorded_by_node"
    return {
        "status": status,
        "last_successful_backup": last_backup,
        "last_verified_restore": last_restore,
        "invalid_receipt_count": invalid_count,
    }


def _publish_receipt(
    settings: Settings,
    relative_root: Path,
    package_id: str,
    receipt: dict[str, object],
) -> dict[str, object]:
    _validate_package_id(package_id)
    root = settings.data_root / relative_root
    _prepare_private_receipt_root(settings, root)
    payload = _canonical_json_bytes(receipt)
    receipt_sha256 = hashlib.sha256(payload).hexdigest()
    target = root / f"{package_id}.{receipt_sha256}.json"
    for path in _bounded_receipt_paths(root):
        if path == target:
            continue
        if path.name.startswith(f"{package_id}.") or path.name == f"{package_id}.json":
            raise RuntimeError("recovery receipt identity conflicts with existing evidence")
    if target.exists() or target.is_symlink():
        existing = _read_regular_file(target)
        if existing != payload:
            raise RuntimeError("recovery receipt identity conflicts with existing evidence")
        _fsync_directory(root)
    else:
        temporary = root / f".{target.name}.{uuid.uuid4().hex}.partial"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(temporary, flags, 0o400)
        staged_identity: os.stat_result | None = None
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                os.fchmod(handle.fileno(), 0o400)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
                staged_identity = os.fstat(handle.fileno())
            publish_file_no_replace(
                temporary,
                target,
                required_mode=0o400,
                label="recovery receipt",
            )
        except FileExistsError:
            temporary.unlink(missing_ok=True)
            _fsync_directory(root)
            try:
                existing = _read_regular_file(target)
            except (OSError, ValueError) as error:
                raise RuntimeError(
                    "recovery receipt identity conflicts with existing evidence"
                ) from error
            if existing != payload:
                raise RuntimeError(
                    "recovery receipt identity conflicts with existing evidence"
                ) from None
        except BaseException as error:
            _cleanup_failed_publication(
                temporary,
                target,
                root,
                staged_identity,
                error,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return {**receipt, "receipt_sha256": receipt_sha256}


def _load_receipts(
    settings: Settings,
    relative_root: Path,
    validator: Callable[[dict[str, object]], dict[str, object]],
    *,
    timestamp_field: str,
) -> tuple[list[dict[str, object]], int]:
    root = settings.data_root / relative_root
    if not root.exists() and not root.is_symlink():
        return [], 0
    if not _is_private_directory(root):
        return [], 1
    try:
        paths = _bounded_receipt_paths(root)
    except (OSError, RuntimeError):
        return [], 1
    receipts: list[dict[str, object]] = []
    invalid_count = 0
    for path in paths:
        try:
            if _RECEIPT_STAGING_FILENAME.fullmatch(path.name) is not None:
                continue
            match = _RECEIPT_FILENAME.fullmatch(path.name)
            if match is None:
                raise ValueError("recovery receipt filename is invalid")
            payload = _read_regular_file(path)
            if hashlib.sha256(payload).hexdigest() != match.group(2):
                raise ValueError("recovery receipt digest does not match its filename")
            raw = json.loads(payload, object_pairs_hook=_unique_json_object)
            if not isinstance(raw, dict):
                raise ValueError("recovery receipt must be an object")
            receipt = validator(cast(dict[str, object], raw))
            if match.group(1) != receipt["package_id"]:
                raise ValueError("recovery receipt filename does not match its package")
            if _canonical_json_bytes(receipt) != payload:
                raise ValueError("recovery receipt bytes are not canonical")
            receipts.append({**receipt, "receipt_sha256": match.group(2)})
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
            invalid_count += 1
    receipts.sort(
        key=lambda item: (
            cast(str, item[timestamp_field]),
            cast(str, item["package_id"]),
        )
    )
    return receipts, invalid_count


def _validate_backup_receipt(value: dict[str, object]) -> dict[str, object]:
    expected = {
        "format_version",
        "created_at",
        "package_id",
        "package_kit_sha256",
        "snapshot_manifest_sha256",
        "source_ledger_generation",
        "backend_profile",
    }
    format_version = value.get("format_version")
    if (
        set(value) != expected
        or not isinstance(format_version, int)
        or isinstance(format_version, bool)
        or format_version != RECOVERY_STATUS_FORMAT_VERSION
    ):
        raise ValueError("successful backup receipt structure is invalid")
    created_at = _validate_timestamp(value.get("created_at"), "backup creation time")
    package_id = _validate_package_id(value.get("package_id"))
    backend_profile = value.get("backend_profile")
    if not isinstance(backend_profile, str) or _BACKEND_PROFILE.fullmatch(backend_profile) is None:
        raise ValueError("backup backend profile is invalid")
    return {
        "format_version": RECOVERY_STATUS_FORMAT_VERSION,
        "created_at": created_at,
        "package_id": package_id,
        "package_kit_sha256": _validate_sha256(value.get("package_kit_sha256")),
        "snapshot_manifest_sha256": _validate_sha256(value.get("snapshot_manifest_sha256")),
        "source_ledger_generation": _validate_sha256(value.get("source_ledger_generation")),
        "backend_profile": backend_profile,
    }


def _validate_restore_receipt(value: dict[str, object]) -> dict[str, object]:
    expected = {
        "format_version",
        "verified_at",
        "package_id",
        "package_kit_sha256",
        "snapshot_manifest_sha256",
        "source_ledger_generation",
        "known_query_count",
        "known_query_receipts_sha256",
    }
    format_version = value.get("format_version")
    if (
        set(value) != expected
        or not isinstance(format_version, int)
        or isinstance(format_version, bool)
        or format_version != RECOVERY_STATUS_FORMAT_VERSION
    ):
        raise ValueError("verified restore receipt structure is invalid")
    known_query_count = value.get("known_query_count")
    if not isinstance(known_query_count, int) or isinstance(known_query_count, bool):
        raise ValueError("verified restore query count is invalid")
    if known_query_count < 0:
        raise ValueError("verified restore query count is invalid")
    return {
        "format_version": RECOVERY_STATUS_FORMAT_VERSION,
        "verified_at": _validate_timestamp(value.get("verified_at"), "restore verification time"),
        "package_id": _validate_package_id(value.get("package_id")),
        "package_kit_sha256": _validate_sha256(value.get("package_kit_sha256")),
        "snapshot_manifest_sha256": _validate_sha256(value.get("snapshot_manifest_sha256")),
        "source_ledger_generation": _validate_sha256(value.get("source_ledger_generation")),
        "known_query_count": known_query_count,
        "known_query_receipts_sha256": _validate_sha256(value.get("known_query_receipts_sha256")),
    }


def _prepare_private_receipt_root(settings: Settings, root: Path) -> None:
    settings.ensure_directories()
    for path in (settings.run_root / "private", root):
        if path.is_symlink():
            raise ValueError("recovery receipt directory must not be a symlink")
        existed = path.exists()
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        if not existed:
            path.chmod(0o700)
        if not _is_private_directory(path):
            raise RuntimeError("recovery receipt directory is not private")


def _is_private_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _read_regular_file(path: Path) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_size > MAX_RECOVERY_RECEIPT_BYTES
        ):
            raise ValueError("recovery receipt is not a bounded private regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(MAX_RECOVERY_RECEIPT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > MAX_RECOVERY_RECEIPT_BYTES:
        raise ValueError("recovery receipt exceeds its size limit")
    return payload


def _bounded_receipt_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    with os.scandir(root) as entries:
        for entry in entries:
            paths.append(Path(entry.path))
            if len(paths) > MAX_RECOVERY_RECEIPTS:
                raise RuntimeError("recovery receipt count exceeds its inspection limit")
    return sorted(paths)


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


def _cleanup_failed_publication(
    temporary: Path,
    target: Path,
    root: Path,
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
        _fsync_directory(root)
    except BaseException as caught:
        cleanup_error = caught
    if cleanup_error is not None:
        raise RuntimeError("failed recovery receipt publication could not be cleaned") from error
    raise error


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("recovery receipt contains a duplicate key")
        value[key] = item
    return value


def _validate_package_id(value: object) -> str:
    if not isinstance(value, str) or _PACKAGE_ID.fullmatch(value) is None:
        raise ValueError("recovery package id is invalid")
    return value


def _validate_sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError("recovery receipt digest is invalid")
    return value


def _validate_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} is invalid")
    return parsed.astimezone(UTC).isoformat()


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode()
