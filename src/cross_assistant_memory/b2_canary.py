from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import stat
import sys
import tempfile
import uuid
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

from cross_assistant_memory.b2_object_store import (
    B2_OBJECT_KEY_PREFIX,
    B2_S3_PROFILE,
    MIN_MULTIPART_PART_BYTES,
    B2S3ObjectBackend,
    B2S3Profile,
    B2S3SettingsInspector,
    S3Client,
    create_b2_s3_client,
)
from cross_assistant_memory.encrypted_objects import (
    EncryptedObjectManifest,
    EncryptedObjectStore,
    FilesystemObjectBackend,
    RootKey,
)
from cross_assistant_memory.object_store import (
    BackendObjectStat,
    IncompleteCleanupReport,
    ProviderSetting,
    SettingState,
)
from cross_assistant_memory.safe_files import open_directory_no_symlinks

CANARY_FORMAT_VERSION = 1
RETAINED_VERSION_CANARY_FORMAT_VERSION = 1
CANARY_MULTIPART_THRESHOLD_BYTES = 10 * 1024 * 1024
CANARY_MULTIPART_PART_BYTES = MIN_MULTIPART_PART_BYTES
DIRECT_PLAINTEXT_BYTES = 256 * 1024
MULTIPART_PLAINTEXT_BYTES = CANARY_MULTIPART_THRESHOLD_BYTES
INTERRUPTED_PLAINTEXT_BYTES = MIN_MULTIPART_PART_BYTES
MAX_EXACT_VERSIONS = 100
MAX_EXACT_MULTIPART_UPLOADS = 20
MAX_CANARY_RECEIPT_BYTES = 1024 * 1024

_STORAGE_OBJECT_ID_PREFIX = "storage_"


class B2CanarySafetyError(RuntimeError):
    pass


@dataclass(frozen=True)
class CanarySettingReceipt:
    name: str
    state: str
    summary: str

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "state": self.state, "summary": self.summary}


@dataclass(frozen=True)
class B2CanaryInspection:
    eligible: bool
    rejection_codes: tuple[str, ...]
    settings: tuple[CanarySettingReceipt, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "eligible": self.eligible,
            "rejection_codes": list(self.rejection_codes),
            "settings": [setting.as_dict() for setting in self.settings],
        }


@dataclass(frozen=True)
class CanaryObjectReceipt:
    transfer: str
    storage_object_id: str
    plaintext_byte_length: int
    plaintext_sha256: str
    ciphertext_byte_length: int
    ciphertext_sha256: str
    head_byte_length: int
    head_version_id: str | None
    listed_version_count: int
    listed_delete_marker_count: int
    deleted_version_count: int
    deleted_delete_marker_count: int
    retry_attempts_observed: int | None

    def as_dict(self) -> dict[str, object]:
        return {
            "transfer": self.transfer,
            "storage_object_id": self.storage_object_id,
            "plaintext_byte_length": self.plaintext_byte_length,
            "plaintext_sha256": self.plaintext_sha256,
            "ciphertext_byte_length": self.ciphertext_byte_length,
            "ciphertext_sha256": self.ciphertext_sha256,
            "head_byte_length": self.head_byte_length,
            "head_version_id": self.head_version_id,
            "listed_version_count": self.listed_version_count,
            "listed_delete_marker_count": self.listed_delete_marker_count,
            "deleted_version_count": self.deleted_version_count,
            "deleted_delete_marker_count": self.deleted_delete_marker_count,
            "retry_attempts_observed": self.retry_attempts_observed,
        }


@dataclass(frozen=True)
class InterruptedMultipartReceipt:
    storage_object_id: str
    part_byte_length: int
    part_sha256: str
    upload_id_sha256: str
    listed_before_abort_count: int
    listed_after_abort_count: int
    listed_version_count: int
    deleted_version_count: int
    deleted_delete_marker_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "storage_object_id": self.storage_object_id,
            "part_byte_length": self.part_byte_length,
            "part_sha256": self.part_sha256,
            "upload_id_sha256": self.upload_id_sha256,
            "listed_before_abort_count": self.listed_before_abort_count,
            "listed_after_abort_count": self.listed_after_abort_count,
            "listed_version_count": self.listed_version_count,
            "deleted_version_count": self.deleted_version_count,
            "deleted_delete_marker_count": self.deleted_delete_marker_count,
        }


@dataclass(frozen=True)
class B2CanaryReceipt:
    format_version: int
    status: str
    created_at: str
    completed_at: str
    provider_profile: str
    bucket_sha256: str
    endpoint_sha256: str
    region_sha256: str
    inspection: B2CanaryInspection
    objects: tuple[CanaryObjectReceipt, ...]
    interrupted_multipart: InterruptedMultipartReceipt
    cleanup_verified: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "provider_profile": self.provider_profile,
            "bucket_sha256": self.bucket_sha256,
            "endpoint_sha256": self.endpoint_sha256,
            "region_sha256": self.region_sha256,
            "inspection": self.inspection.as_dict(),
            "objects": [item.as_dict() for item in self.objects],
            "interrupted_multipart": self.interrupted_multipart.as_dict(),
            "cleanup_verified": self.cleanup_verified,
        }


@dataclass(frozen=True)
class B2CanaryCleanupVerification:
    receipt_sha256: str
    object_version_count: int
    delete_marker_count: int
    multipart_upload_count: int
    head_present_count: int
    verified_absent: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "receipt_sha256": self.receipt_sha256,
            "object_version_count": self.object_version_count,
            "delete_marker_count": self.delete_marker_count,
            "multipart_upload_count": self.multipart_upload_count,
            "head_present_count": self.head_present_count,
            "verified_absent": self.verified_absent,
        }


@dataclass(frozen=True)
class B2RetainedVersionReceipt:
    format_version: int
    status: str
    created_at: str
    completed_at: str
    provider_profile: str
    bucket_sha256: str
    endpoint_sha256: str
    region_sha256: str
    inspection: B2CanaryInspection
    storage_object_id: str
    ciphertext_byte_length: int
    ciphertext_sha256: str
    uploaded_version_id_sha256: str
    delete_marker_version_id_sha256: str
    head_absent_after_key_delete: bool
    retained_object_version_count: int
    delete_marker_count: int
    retained_version_readback_verified: bool
    deleted_version_count: int
    deleted_delete_marker_count: int
    cleanup_verified: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "provider_profile": self.provider_profile,
            "bucket_sha256": self.bucket_sha256,
            "endpoint_sha256": self.endpoint_sha256,
            "region_sha256": self.region_sha256,
            "inspection": self.inspection.as_dict(),
            "storage_object_id": self.storage_object_id,
            "ciphertext_byte_length": self.ciphertext_byte_length,
            "ciphertext_sha256": self.ciphertext_sha256,
            "uploaded_version_id_sha256": self.uploaded_version_id_sha256,
            "delete_marker_version_id_sha256": self.delete_marker_version_id_sha256,
            "head_absent_after_key_delete": self.head_absent_after_key_delete,
            "retained_object_version_count": self.retained_object_version_count,
            "delete_marker_count": self.delete_marker_count,
            "retained_version_readback_verified": self.retained_version_readback_verified,
            "deleted_version_count": self.deleted_version_count,
            "deleted_delete_marker_count": self.deleted_delete_marker_count,
            "cleanup_verified": self.cleanup_verified,
        }


@dataclass(frozen=True)
class B2CanaryCleanupTarget:
    bucket_sha256: str
    endpoint_sha256: str
    region_sha256: str
    storage_object_ids: tuple[str, ...]


@dataclass(frozen=True)
class _PreparedObject:
    transfer: str
    manifest: EncryptedObjectManifest
    metadata_root: Path
    ciphertext_path: Path
    root_key: RootKey


@dataclass(frozen=True)
class _ExactVersion:
    version_id: str
    delete_marker: bool


@dataclass(frozen=True)
class _CleanupResult:
    versions_before: tuple[_ExactVersion, ...]
    deleted_version_count: int
    deleted_delete_marker_count: int


class _CaptureBackend:
    def __init__(self, root: Path) -> None:
        self._root = root
        self._delegate = FilesystemObjectBackend(root)

    @property
    def profile(self) -> str:
        return B2_S3_PROFILE

    def exists(self, storage_object_id: str) -> bool:
        return self._delegate.exists(storage_object_id)

    def put_file(self, storage_object_id: str, source: Path) -> None:
        self._delegate.put_file(storage_object_id, source)

    def open(self, storage_object_id: str) -> BinaryIO:
        return self._delegate.open(storage_object_id)

    def stat(self, storage_object_id: str) -> BackendObjectStat:
        return self._delegate.stat(storage_object_id)

    def cleanup_incomplete(self, *, older_than_epoch: float) -> IncompleteCleanupReport:
        return self._delegate.cleanup_incomplete(older_than_epoch=older_than_epoch)

    def object_path(self, storage_object_id: str) -> Path:
        _validate_storage_object_id(storage_object_id)
        path = self._root / "objects" / storage_object_id
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("captured encrypted object is missing")
        return path


def inspect_b2_canary_settings(client: S3Client, profile: B2S3Profile) -> B2CanaryInspection:
    report = B2S3SettingsInspector(client, profile.bucket).inspect()
    lifecycle_effect = _inspect_lifecycle_canary_effect(client, profile.bucket, report.lifecycle)
    named_settings = (
        ("bucket_access", report.bucket_access),
        ("versioning", report.versioning),
        ("lifecycle", report.lifecycle),
        ("lifecycle_canary_effect", lifecycle_effect),
        ("replication", report.replication),
        ("object_lock", report.object_lock),
        ("default_retention", report.default_retention),
    )
    settings = tuple(_setting_receipt(name, value) for name, value in named_settings)
    rejections: list[str] = []
    if report.bucket_access.state is not SettingState.KNOWN:
        rejections.append("bucket_access_not_known")
    if (
        report.versioning.state is not SettingState.KNOWN
        or report.versioning.summary != "status=Enabled"
    ):
        rejections.append("versioning_not_enabled")
    if lifecycle_effect.state is SettingState.KNOWN:
        if not (lifecycle_effect.summary or "").startswith("safe=true;"):
            rejections.append("lifecycle_can_affect_canary")
    elif lifecycle_effect.state is not SettingState.NOT_CONFIGURED:
        rejections.append("lifecycle_not_known")
    object_lock_safe = report.object_lock.state is SettingState.NOT_CONFIGURED or (
        report.object_lock.state is SettingState.KNOWN
        and report.object_lock.summary == "status=Disabled"
    )
    if not object_lock_safe:
        rejections.append("object_lock_not_disabled")
    if report.default_retention.state is not SettingState.NOT_CONFIGURED:
        rejections.append("default_retention_not_absent")
    return B2CanaryInspection(
        eligible=not rejections,
        rejection_codes=tuple(rejections),
        settings=settings,
    )


def _inspect_lifecycle_canary_effect(
    client: S3Client,
    bucket: str,
    lifecycle: ProviderSetting,
) -> ProviderSetting:
    if lifecycle.state is SettingState.NOT_CONFIGURED:
        return ProviderSetting(SettingState.NOT_CONFIGURED, "no lifecycle rules")
    if lifecycle.state is not SettingState.KNOWN:
        return ProviderSetting(lifecycle.state, lifecycle.summary)
    try:
        response = client.get_bucket_lifecycle_configuration(Bucket=bucket)
        return _assess_lifecycle_rules(response)
    except Exception as error:
        return ProviderSetting(
            SettingState.UNAVAILABLE,
            f"assessment_error={type(error).__name__}",
        )


def _assess_lifecycle_rules(response: Mapping[str, object]) -> ProviderSetting:
    rules = _mapping_entries(response.get("Rules"), "B2 lifecycle rule list")
    applicable_rules = 0
    minimum_delay_days: int | None = None
    for rule in rules:
        status = rule.get("Status")
        if status == "Disabled":
            continue
        if status != "Enabled":
            return ProviderSetting(SettingState.UNAVAILABLE, "lifecycle status is invalid")
        try:
            prefix = _lifecycle_prefix(rule)
        except ValueError as error:
            return ProviderSetting(SettingState.UNAVAILABLE, str(error))
        if not B2_OBJECT_KEY_PREFIX.startswith(prefix):
            continue
        applicable_rules += 1
        action_names = set(rule) - {"ID", "Status", "Filter", "Prefix"}
        if action_names & {
            "Expiration",
            "Transitions",
            "NoncurrentVersionTransitions",
        }:
            return ProviderSetting(
                SettingState.KNOWN,
                "safe=false; reason=expiration_or_transition",
            )
        if not action_names or not action_names <= {
            "AbortIncompleteMultipartUpload",
            "NoncurrentVersionExpiration",
        }:
            return ProviderSetting(SettingState.UNAVAILABLE, "lifecycle actions are unknown")
        delays: list[int] = []
        if "AbortIncompleteMultipartUpload" in action_names:
            try:
                delays.append(
                    _positive_mapping_int(
                        rule.get("AbortIncompleteMultipartUpload"),
                        "DaysAfterInitiation",
                        {"DaysAfterInitiation"},
                    )
                )
            except ValueError as error:
                return ProviderSetting(SettingState.UNAVAILABLE, str(error))
        if "NoncurrentVersionExpiration" in action_names:
            try:
                delays.append(
                    _positive_mapping_int(
                        rule.get("NoncurrentVersionExpiration"),
                        "NoncurrentDays",
                        {"NoncurrentDays", "NewerNoncurrentVersions"},
                    )
                )
            except ValueError as error:
                return ProviderSetting(SettingState.UNAVAILABLE, str(error))
        current_minimum = min(delays)
        minimum_delay_days = (
            current_minimum
            if minimum_delay_days is None
            else min(minimum_delay_days, current_minimum)
        )
    delay = "none" if minimum_delay_days is None else str(minimum_delay_days)
    return ProviderSetting(
        SettingState.KNOWN,
        f"safe=true; applicable_enabled_rules={applicable_rules}; minimum_delay_days={delay}",
    )


def _lifecycle_prefix(rule: Mapping[str, object]) -> str:
    legacy = rule.get("Prefix")
    filter_value = rule.get("Filter")
    if legacy is not None and filter_value is not None:
        raise ValueError("lifecycle rule has conflicting filters")
    if legacy is not None:
        if not isinstance(legacy, str):
            raise ValueError("lifecycle prefix is invalid")
        return legacy
    if not isinstance(filter_value, dict):
        raise ValueError("lifecycle filter is unavailable")
    fields = cast(dict[object, object], filter_value)
    if set(fields) != {"Prefix"}:
        raise ValueError("lifecycle filter is not prefix-only")
    prefix = fields.get("Prefix")
    if not isinstance(prefix, str):
        raise ValueError("lifecycle prefix is invalid")
    return prefix


def _positive_mapping_int(value: object, key: str, allowed: set[str]) -> int:
    if not isinstance(value, dict):
        raise ValueError("lifecycle action is invalid")
    fields = {str(name): item for name, item in cast(dict[object, object], value).items()}
    if not set(fields) <= allowed:
        raise ValueError("lifecycle action fields are unknown")
    result = fields.get(key)
    if not isinstance(result, int) or isinstance(result, bool) or result <= 0:
        raise ValueError("lifecycle delay is invalid")
    optional = fields.get("NewerNoncurrentVersions")
    if optional is not None and (
        not isinstance(optional, int) or isinstance(optional, bool) or optional <= 0
    ):
        raise ValueError("lifecycle version bound is invalid")
    return result


def run_b2_canary(
    client: S3Client,
    profile: B2S3Profile,
    receipt_path: Path,
) -> B2CanaryReceipt:
    receipt_path = Path(os.path.abspath(receipt_path.expanduser()))
    recovery_path = receipt_path.with_name(f"{receipt_path.name}.recovery.json")
    _require_new_output(receipt_path)
    _require_new_output(recovery_path)
    inspection = inspect_b2_canary_settings(client, profile)
    if not inspection.eligible:
        raise B2CanarySafetyError("B2 canary settings inspection rejected live writes")

    started_at = _now()
    backend = B2S3ObjectBackend(
        client,
        profile.bucket,
        multipart_threshold_bytes=CANARY_MULTIPART_THRESHOLD_BYTES,
        multipart_part_bytes=CANARY_MULTIPART_PART_BYTES,
        cleanup_abort_limit=MAX_EXACT_MULTIPART_UPLOADS,
        cleanup_scan_limit=MAX_EXACT_MULTIPART_UPLOADS,
    )
    with tempfile.TemporaryDirectory(prefix="cross-agent-memory-b2-canary-") as temporary:
        root = Path(temporary)
        direct = _prepare_object(root, "direct", DIRECT_PLAINTEXT_BYTES, "direct")
        multipart = _prepare_object(root, "multipart", MULTIPART_PLAINTEXT_BYTES, "multipart")
        interrupted = _prepare_object(
            root, "interrupted", INTERRUPTED_PLAINTEXT_BYTES, "interrupted"
        )
        if direct.manifest.ciphertext_byte_length >= CANARY_MULTIPART_THRESHOLD_BYTES:
            raise RuntimeError("direct canary ciphertext crossed the multipart threshold")
        if multipart.manifest.ciphertext_byte_length < CANARY_MULTIPART_THRESHOLD_BYTES:
            raise RuntimeError("multipart canary ciphertext did not cross its threshold")
        if interrupted.manifest.ciphertext_byte_length < CANARY_MULTIPART_PART_BYTES:
            raise RuntimeError("interrupted canary ciphertext is shorter than one part")
        prepared = (direct, multipart, interrupted)
        storage_object_ids = tuple(item.manifest.storage_object_id for item in prepared)
        _preflight_exact_keys(client, backend, profile.bucket, storage_object_ids)
        _write_private_json(
            recovery_path,
            {
                "format_version": CANARY_FORMAT_VERSION,
                "status": "prepared",
                "bucket_sha256": _sha256_text(profile.bucket),
                "storage_object_ids": list(storage_object_ids),
                "interrupted_upload_id": None,
            },
        )

        operation_error: BaseException | None = None
        direct_stat: BackendObjectStat | None = None
        multipart_stat: BackendObjectStat | None = None
        interrupted_upload_id: str | None = None
        interrupted_upload_id_digest: str | None = None
        interrupted_part = b""
        listed_before_abort = 0
        listed_after_abort = 0
        try:
            direct_stat = _upload_and_verify(direct, backend)
            multipart_stat = _upload_and_verify(multipart, backend)
            interrupted_part = _read_exact_part(interrupted.ciphertext_path)
            interrupted_key = _object_key(interrupted.manifest.storage_object_id)
            created = client.create_multipart_upload(
                Bucket=profile.bucket,
                Key=interrupted_key,
                ContentType="application/octet-stream",
            )
            interrupted_upload_id = _response_string(created, "UploadId")
            interrupted_upload_id_digest = _sha256_text(interrupted_upload_id)
            _write_private_json(
                recovery_path,
                {
                    "format_version": CANARY_FORMAT_VERSION,
                    "status": "multipart_created",
                    "bucket_sha256": _sha256_text(profile.bucket),
                    "storage_object_ids": list(storage_object_ids),
                    "interrupted_upload_id": interrupted_upload_id,
                },
                replace=True,
            )
            uploaded = client.upload_part(
                Bucket=profile.bucket,
                Key=interrupted_key,
                UploadId=interrupted_upload_id,
                PartNumber=1,
                Body=interrupted_part,
                ContentLength=len(interrupted_part),
            )
            _response_string(uploaded, "ETag")
            uploads = _list_exact_multipart_uploads(client, profile.bucket, interrupted_key)
            listed_before_abort = len(uploads)
            if uploads != (interrupted_upload_id,):
                raise B2CanarySafetyError("interrupted multipart listing was not exact")
            client.abort_multipart_upload(
                Bucket=profile.bucket,
                Key=interrupted_key,
                UploadId=interrupted_upload_id,
            )
            uploads = _list_exact_multipart_uploads(client, profile.bucket, interrupted_key)
            listed_after_abort = len(uploads)
            if interrupted_upload_id in uploads:
                raise B2CanarySafetyError("interrupted multipart upload remained after abort")
            interrupted_upload_id = None
        except BaseException as error:
            operation_error = error

        try:
            cleanup = _cleanup_exact_keys(client, backend, profile.bucket, storage_object_ids)
        except Exception as error:
            raise B2CanarySafetyError(
                f"exact canary cleanup could not be verified; recovery={recovery_path}"
            ) from error

        if operation_error is not None:
            _remove_private_json(recovery_path)
            if not isinstance(operation_error, Exception):
                raise operation_error
            raise B2CanarySafetyError(
                "B2 canary operation failed after verified cleanup: "
                f"{type(operation_error).__name__}"
            ) from operation_error
        if direct_stat is None or multipart_stat is None or interrupted_upload_id_digest is None:
            raise B2CanarySafetyError("B2 canary result was incomplete")

        direct_cleanup = cleanup[direct.manifest.storage_object_id]
        multipart_cleanup = cleanup[multipart.manifest.storage_object_id]
        interrupted_cleanup = cleanup[interrupted.manifest.storage_object_id]
        if not _has_one_object_version(direct_cleanup) or not _has_one_object_version(
            multipart_cleanup
        ):
            _remove_private_json(recovery_path)
            raise B2CanarySafetyError(
                "completed canary objects did not produce one exact version each"
            )
        if interrupted_cleanup.versions_before:
            _remove_private_json(recovery_path)
            raise B2CanarySafetyError(
                "interrupted multipart canary unexpectedly produced an object version"
            )
        receipt = B2CanaryReceipt(
            format_version=CANARY_FORMAT_VERSION,
            status="passed",
            created_at=started_at,
            completed_at=_now(),
            provider_profile=B2_S3_PROFILE,
            bucket_sha256=_sha256_text(profile.bucket),
            endpoint_sha256=_sha256_text(profile.endpoint_url),
            region_sha256=_sha256_text(profile.region),
            inspection=inspection,
            objects=(
                _object_receipt(direct, direct_stat, direct_cleanup),
                _object_receipt(multipart, multipart_stat, multipart_cleanup),
            ),
            interrupted_multipart=InterruptedMultipartReceipt(
                storage_object_id=interrupted.manifest.storage_object_id,
                part_byte_length=len(interrupted_part),
                part_sha256=hashlib.sha256(interrupted_part).hexdigest(),
                upload_id_sha256=interrupted_upload_id_digest,
                listed_before_abort_count=listed_before_abort,
                listed_after_abort_count=listed_after_abort,
                listed_version_count=sum(
                    not item.delete_marker for item in interrupted_cleanup.versions_before
                ),
                deleted_version_count=interrupted_cleanup.deleted_version_count,
                deleted_delete_marker_count=interrupted_cleanup.deleted_delete_marker_count,
            ),
            cleanup_verified=True,
        )
        _write_private_json(receipt_path, receipt.as_dict())
        _remove_private_json(recovery_path)
        return receipt


def run_b2_retained_version_canary(
    client: S3Client,
    profile: B2S3Profile,
    receipt_path: Path,
) -> B2RetainedVersionReceipt:
    receipt_path = Path(os.path.abspath(receipt_path.expanduser()))
    recovery_path = receipt_path.with_name(f"{receipt_path.name}.recovery.json")
    _require_new_output(receipt_path)
    _require_new_output(recovery_path)
    inspection = inspect_b2_canary_settings(client, profile)
    if not inspection.eligible:
        raise B2CanarySafetyError("B2 canary settings inspection rejected live writes")

    started_at = _now()
    backend = B2S3ObjectBackend(client, profile.bucket)
    with tempfile.TemporaryDirectory(prefix="cross-agent-memory-b2-retained-version-") as temporary:
        prepared = _prepare_object(
            Path(temporary), "retained-version", DIRECT_PLAINTEXT_BYTES, "direct"
        )
        storage_object_id = prepared.manifest.storage_object_id
        key = _object_key(storage_object_id)
        _preflight_exact_keys(client, backend, profile.bucket, (storage_object_id,))
        _write_private_json(
            recovery_path,
            {
                "format_version": RETAINED_VERSION_CANARY_FORMAT_VERSION,
                "status": "prepared",
                "bucket_sha256": _sha256_text(profile.bucket),
                "endpoint_sha256": _sha256_text(profile.endpoint_url),
                "region_sha256": _sha256_text(profile.region),
                "storage_object_ids": [storage_object_id],
            },
        )

        operation_error: BaseException | None = None
        uploaded_version_id = ""
        delete_marker_version_id = ""
        head_absent = False
        retained_versions: tuple[_ExactVersion, ...] = ()
        readback_verified = False
        try:
            uploaded = _upload_and_verify(prepared, backend)
            if uploaded.version_id is None:
                raise RuntimeError("B2 retained-version canary upload omitted a version id")
            uploaded_version_id = uploaded.version_id
            deleted = client.delete_object(Bucket=profile.bucket, Key=key)
            delete_marker_version_id = _response_string(deleted, "VersionId")
            if deleted.get("DeleteMarker") is not True:
                raise RuntimeError("B2 key-only deletion did not report a delete marker")
            head_absent = not backend.exists(storage_object_id)
            if not head_absent:
                raise RuntimeError("B2 key-only deletion left the current object visible")
            retained_versions = _list_exact_versions(client, profile.bucket, key)
            object_versions = tuple(item for item in retained_versions if not item.delete_marker)
            delete_markers = tuple(item for item in retained_versions if item.delete_marker)
            if (
                len(object_versions) != 1
                or object_versions[0].version_id != uploaded_version_id
                or len(delete_markers) != 1
                or delete_markers[0].version_id != delete_marker_version_id
            ):
                raise RuntimeError("B2 key-only deletion did not retain one exact hidden version")
            _verify_remote_version_bytes(
                client,
                bucket=profile.bucket,
                key=key,
                version_id=uploaded_version_id,
                expected_byte_length=prepared.manifest.ciphertext_byte_length,
                expected_sha256=prepared.manifest.ciphertext_sha256,
            )
            readback_verified = True
        except BaseException as error:
            operation_error = error

        try:
            cleanup = _cleanup_exact_keys(
                client,
                backend,
                profile.bucket,
                (storage_object_id,),
            )[storage_object_id]
        except Exception as error:
            raise B2CanarySafetyError(
                f"exact retained-version cleanup could not be verified; recovery={recovery_path}"
            ) from error

        if operation_error is not None:
            _remove_private_json(recovery_path)
            if not isinstance(operation_error, Exception):
                raise operation_error
            raise B2CanarySafetyError(
                "B2 retained-version canary failed after verified cleanup: "
                f"{type(operation_error).__name__}"
            ) from operation_error
        if (
            not uploaded_version_id
            or not delete_marker_version_id
            or not head_absent
            or not readback_verified
            or len(retained_versions) != 2
            or cleanup.deleted_version_count != 1
            or cleanup.deleted_delete_marker_count != 1
        ):
            _remove_private_json(recovery_path)
            raise B2CanarySafetyError("B2 retained-version canary result was incomplete")

        receipt = B2RetainedVersionReceipt(
            format_version=RETAINED_VERSION_CANARY_FORMAT_VERSION,
            status="passed",
            created_at=started_at,
            completed_at=_now(),
            provider_profile=B2_S3_PROFILE,
            bucket_sha256=_sha256_text(profile.bucket),
            endpoint_sha256=_sha256_text(profile.endpoint_url),
            region_sha256=_sha256_text(profile.region),
            inspection=inspection,
            storage_object_id=storage_object_id,
            ciphertext_byte_length=prepared.manifest.ciphertext_byte_length,
            ciphertext_sha256=prepared.manifest.ciphertext_sha256,
            uploaded_version_id_sha256=_sha256_text(uploaded_version_id),
            delete_marker_version_id_sha256=_sha256_text(delete_marker_version_id),
            head_absent_after_key_delete=True,
            retained_object_version_count=1,
            delete_marker_count=1,
            retained_version_readback_verified=True,
            deleted_version_count=cleanup.deleted_version_count,
            deleted_delete_marker_count=cleanup.deleted_delete_marker_count,
            cleanup_verified=True,
        )
        _write_private_json(receipt_path, receipt.as_dict())
        _remove_private_json(recovery_path)
        return receipt


def load_b2_retained_version_receipt(
    receipt_path: Path,
    expected_sha256: str,
) -> tuple[B2CanaryCleanupTarget, str]:
    fields, observed = _load_private_receipt(receipt_path, expected_sha256)
    if set(fields) != {
        "format_version",
        "status",
        "created_at",
        "completed_at",
        "provider_profile",
        "bucket_sha256",
        "endpoint_sha256",
        "region_sha256",
        "inspection",
        "storage_object_id",
        "ciphertext_byte_length",
        "ciphertext_sha256",
        "uploaded_version_id_sha256",
        "delete_marker_version_id_sha256",
        "head_absent_after_key_delete",
        "retained_object_version_count",
        "delete_marker_count",
        "retained_version_readback_verified",
        "deleted_version_count",
        "deleted_delete_marker_count",
        "cleanup_verified",
    }:
        raise ValueError("B2 retained-version receipt fields are invalid")
    if fields.get("format_version") != RETAINED_VERSION_CANARY_FORMAT_VERSION:
        raise ValueError("unsupported B2 retained-version receipt format")
    if fields.get("status") != "passed" or fields.get("cleanup_verified") is not True:
        raise ValueError("B2 retained-version receipt did not pass cleanup")
    if fields.get("provider_profile") != B2_S3_PROFILE:
        raise ValueError("B2 retained-version provider profile is invalid")
    if fields.get("head_absent_after_key_delete") is not True:
        raise ValueError("B2 retained-version receipt did not hide the current object")
    if fields.get("retained_version_readback_verified") is not True:
        raise ValueError("B2 retained-version receipt did not verify hidden readback")
    for field in (
        "retained_object_version_count",
        "delete_marker_count",
        "deleted_version_count",
        "deleted_delete_marker_count",
    ):
        if fields.get(field) != 1:
            raise ValueError(f"B2 retained-version receipt has invalid {field}")
    _required_sha256(fields, "ciphertext_sha256")
    _required_sha256(fields, "uploaded_version_id_sha256")
    _required_sha256(fields, "delete_marker_version_id_sha256")
    byte_length = fields.get("ciphertext_byte_length")
    if isinstance(byte_length, bool) or not isinstance(byte_length, int) or byte_length <= 0:
        raise ValueError("B2 retained-version receipt ciphertext length is invalid")
    storage_object_id = _required_string(fields, "storage_object_id")
    _validate_storage_object_id(storage_object_id)
    return (
        B2CanaryCleanupTarget(
            bucket_sha256=_required_sha256(fields, "bucket_sha256"),
            endpoint_sha256=_required_sha256(fields, "endpoint_sha256"),
            region_sha256=_required_sha256(fields, "region_sha256"),
            storage_object_ids=(storage_object_id,),
        ),
        observed,
    )


def load_b2_canary_receipt(
    receipt_path: Path,
    expected_sha256: str,
) -> tuple[B2CanaryCleanupTarget, str]:
    fields, observed = _load_private_receipt(receipt_path, expected_sha256)
    if fields.get("format_version") != CANARY_FORMAT_VERSION:
        raise ValueError("unsupported B2 canary receipt format")
    if fields.get("status") != "passed" or fields.get("cleanup_verified") is not True:
        raise ValueError("B2 canary receipt did not pass cleanup")
    if fields.get("provider_profile") != B2_S3_PROFILE:
        raise ValueError("B2 canary provider profile is invalid")
    objects = _required_list(fields, "objects")
    if len(objects) != 2:
        raise ValueError("B2 canary receipt must contain two completed objects")
    transfers: set[str] = set()
    storage_object_ids: list[str] = []
    for value in objects:
        item = _required_mapping(value, "B2 canary object receipt")
        transfer = _required_string(item, "transfer")
        storage_object_id = _required_string(item, "storage_object_id")
        _validate_storage_object_id(storage_object_id)
        transfers.add(transfer)
        storage_object_ids.append(storage_object_id)
    if transfers != {"direct", "multipart"}:
        raise ValueError("B2 canary receipt transfer set is invalid")
    interrupted = _required_mapping(
        fields.get("interrupted_multipart"), "interrupted multipart receipt"
    )
    interrupted_id = _required_string(interrupted, "storage_object_id")
    _validate_storage_object_id(interrupted_id)
    storage_object_ids.append(interrupted_id)
    if len(set(storage_object_ids)) != 3:
        raise ValueError("B2 canary receipt object ids are not unique")
    return (
        B2CanaryCleanupTarget(
            bucket_sha256=_required_sha256(fields, "bucket_sha256"),
            endpoint_sha256=_required_sha256(fields, "endpoint_sha256"),
            region_sha256=_required_sha256(fields, "region_sha256"),
            storage_object_ids=tuple(storage_object_ids),
        ),
        observed,
    )


def verify_b2_canary_cleanup(
    client: S3Client,
    profile: B2S3Profile,
    target: B2CanaryCleanupTarget,
    receipt_sha256: str,
) -> B2CanaryCleanupVerification:
    if target.bucket_sha256 != _sha256_text(profile.bucket):
        raise ValueError("B2 canary receipt bucket does not match")
    if target.endpoint_sha256 != _sha256_text(profile.endpoint_url):
        raise ValueError("B2 canary receipt endpoint does not match")
    if target.region_sha256 != _sha256_text(profile.region):
        raise ValueError("B2 canary receipt region does not match")
    versions = 0
    delete_markers = 0
    uploads = 0
    head_present = 0
    backend = B2S3ObjectBackend(client, profile.bucket)
    for storage_object_id in target.storage_object_ids:
        key = _object_key(storage_object_id)
        exact_versions = _list_exact_versions(client, profile.bucket, key)
        versions += sum(not item.delete_marker for item in exact_versions)
        delete_markers += sum(item.delete_marker for item in exact_versions)
        uploads += len(_list_exact_multipart_uploads(client, profile.bucket, key))
        if backend.exists(storage_object_id):
            head_present += 1
    verified = versions == delete_markers == uploads == head_present == 0
    return B2CanaryCleanupVerification(
        receipt_sha256=receipt_sha256,
        object_version_count=versions,
        delete_marker_count=delete_markers,
        multipart_upload_count=uploads,
        head_present_count=head_present,
        verified_absent=verified,
    )


def _setting_receipt(name: str, setting: ProviderSetting) -> CanarySettingReceipt:
    return CanarySettingReceipt(
        name=name,
        state=setting.state.value,
        summary=setting.summary or "",
    )


def _prepare_object(root: Path, label: str, byte_length: int, transfer: str) -> _PreparedObject:
    source = root / f"{label}.synthetic"
    _write_synthetic_file(source, byte_length, label)
    capture = _CaptureBackend(root / f"{label}-capture")
    metadata_root = root / f"{label}-metadata"
    root_key = RootKey.generate()
    store = EncryptedObjectStore(metadata_root, capture, root_key)
    manifest = store.put_file(source, media_type="application/octet-stream")
    return _PreparedObject(
        transfer=transfer,
        manifest=manifest,
        metadata_root=metadata_root,
        ciphertext_path=capture.object_path(manifest.storage_object_id),
        root_key=root_key,
    )


def _upload_and_verify(
    prepared: _PreparedObject,
    backend: B2S3ObjectBackend,
) -> BackendObjectStat:
    backend.put_file(prepared.manifest.storage_object_id, prepared.ciphertext_path)
    remote_store = EncryptedObjectStore(prepared.metadata_root, backend, prepared.root_key)
    verified = remote_store.resume(prepared.manifest.source_object_id)
    if verified.ciphertext_sha256 != prepared.manifest.ciphertext_sha256:
        raise RuntimeError("remote encrypted object digest changed")
    stat = backend.stat(prepared.manifest.storage_object_id)
    if stat.byte_length != prepared.manifest.ciphertext_byte_length:
        raise RuntimeError("remote encrypted object length changed")
    return stat


def _verify_remote_version_bytes(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    version_id: str,
    expected_byte_length: int,
    expected_sha256: str,
) -> None:
    response = client.get_object(Bucket=bucket, Key=key, VersionId=version_id)
    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise RuntimeError("B2 retained version response does not contain a readable body")
    close = getattr(body, "close", None)
    if not callable(close):
        raise RuntimeError("B2 retained version response body cannot be closed")
    reader = cast(BinaryIO, body)
    remaining = expected_byte_length
    digest = hashlib.sha256()
    try:
        while remaining:
            chunk = reader.read(min(1024 * 1024, remaining))
            if not chunk:
                raise RuntimeError("B2 retained version readback ended early")
            if len(chunk) > remaining:
                raise RuntimeError("B2 retained version readback exceeded its bound")
            digest.update(chunk)
            remaining -= len(chunk)
        extra = reader.read(1)
        if extra:
            raise RuntimeError("B2 retained version readback length changed")
    finally:
        close()
    if digest.hexdigest() != expected_sha256:
        raise RuntimeError("B2 retained version readback digest changed")


def _preflight_exact_keys(
    client: S3Client,
    backend: B2S3ObjectBackend,
    bucket: str,
    storage_object_ids: tuple[str, ...],
) -> None:
    for storage_object_id in storage_object_ids:
        key = _object_key(storage_object_id)
        if backend.exists(storage_object_id):
            raise B2CanarySafetyError("generated canary key already exists")
        if _list_exact_versions(client, bucket, key):
            raise B2CanarySafetyError("generated canary key has existing versions")
        if _list_exact_multipart_uploads(client, bucket, key):
            raise B2CanarySafetyError("generated canary key has an existing multipart upload")


def _cleanup_exact_keys(
    client: S3Client,
    backend: B2S3ObjectBackend,
    bucket: str,
    storage_object_ids: tuple[str, ...],
) -> dict[str, _CleanupResult]:
    results: dict[str, _CleanupResult] = {}
    for storage_object_id in storage_object_ids:
        key = _object_key(storage_object_id)
        for upload_id in _list_exact_multipart_uploads(client, bucket, key):
            client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        if _list_exact_multipart_uploads(client, bucket, key):
            raise RuntimeError("exact multipart cleanup did not finish")
        versions = _list_exact_versions(client, bucket, key)
        deleted_versions = 0
        deleted_markers = 0
        for version in versions:
            client.delete_object(Bucket=bucket, Key=key, VersionId=version.version_id)
            if version.delete_marker:
                deleted_markers += 1
            else:
                deleted_versions += 1
        if _list_exact_versions(client, bucket, key):
            raise RuntimeError("exact version cleanup did not finish")
        if backend.exists(storage_object_id):
            raise RuntimeError("exact canary object remained after version cleanup")
        results[storage_object_id] = _CleanupResult(
            versions_before=versions,
            deleted_version_count=deleted_versions,
            deleted_delete_marker_count=deleted_markers,
        )
    return results


def _list_exact_versions(client: S3Client, bucket: str, key: str) -> tuple[_ExactVersion, ...]:
    results: list[_ExactVersion] = []
    key_marker: str | None = None
    version_marker: str | None = None
    while True:
        request: dict[str, object] = {
            "Bucket": bucket,
            "Prefix": key,
            "MaxKeys": MAX_EXACT_VERSIONS,
        }
        if key_marker is not None:
            request["KeyMarker"] = key_marker
        if version_marker is not None:
            request["VersionIdMarker"] = version_marker
        response = client.list_object_versions(**request)
        for field, delete_marker in (("Versions", False), ("DeleteMarkers", True)):
            for entry in _mapping_entries(response.get(field), f"B2 {field} list"):
                if entry.get("Key") != key:
                    continue
                version_id = entry.get("VersionId")
                if not isinstance(version_id, str) or not version_id:
                    raise RuntimeError("B2 exact version listing omitted a version id")
                results.append(_ExactVersion(version_id=version_id, delete_marker=delete_marker))
                if len(results) > MAX_EXACT_VERSIONS:
                    raise RuntimeError("B2 exact version listing exceeded the canary bound")
        if response.get("IsTruncated") is not True:
            break
        next_key = response.get("NextKeyMarker")
        next_version = response.get("NextVersionIdMarker")
        if not isinstance(next_key, str) or not isinstance(next_version, str):
            raise RuntimeError("B2 exact version listing omitted continuation markers")
        key_marker = next_key
        version_marker = next_version
    return tuple(results)


def _list_exact_multipart_uploads(
    client: S3Client,
    bucket: str,
    key: str,
) -> tuple[str, ...]:
    results: list[str] = []
    key_marker: str | None = None
    upload_marker: str | None = None
    while True:
        request: dict[str, object] = {
            "Bucket": bucket,
            "Prefix": key,
            "MaxUploads": MAX_EXACT_MULTIPART_UPLOADS,
        }
        if key_marker is not None:
            request["KeyMarker"] = key_marker
        if upload_marker is not None:
            request["UploadIdMarker"] = upload_marker
        response = client.list_multipart_uploads(**request)
        for entry in _mapping_entries(response.get("Uploads"), "B2 multipart upload list"):
            if entry.get("Key") != key:
                continue
            upload_id = entry.get("UploadId")
            if not isinstance(upload_id, str) or not upload_id:
                raise RuntimeError("B2 exact multipart listing omitted an upload id")
            results.append(upload_id)
            if len(results) > MAX_EXACT_MULTIPART_UPLOADS:
                raise RuntimeError("B2 exact multipart listing exceeded the canary bound")
        if response.get("IsTruncated") is not True:
            break
        next_key = response.get("NextKeyMarker")
        next_upload = response.get("NextUploadIdMarker")
        if not isinstance(next_key, str) or not isinstance(next_upload, str):
            raise RuntimeError("B2 exact multipart listing omitted continuation markers")
        key_marker = next_key
        upload_marker = next_upload
    return tuple(results)


def _object_receipt(
    prepared: _PreparedObject,
    stat: BackendObjectStat,
    cleanup: _CleanupResult,
) -> CanaryObjectReceipt:
    return CanaryObjectReceipt(
        transfer=prepared.transfer,
        storage_object_id=prepared.manifest.storage_object_id,
        plaintext_byte_length=prepared.manifest.plaintext_byte_length,
        plaintext_sha256=prepared.manifest.plaintext_sha256,
        ciphertext_byte_length=prepared.manifest.ciphertext_byte_length,
        ciphertext_sha256=prepared.manifest.ciphertext_sha256,
        head_byte_length=stat.byte_length,
        head_version_id=stat.version_id,
        listed_version_count=sum(not item.delete_marker for item in cleanup.versions_before),
        listed_delete_marker_count=sum(item.delete_marker for item in cleanup.versions_before),
        deleted_version_count=cleanup.deleted_version_count,
        deleted_delete_marker_count=cleanup.deleted_delete_marker_count,
        retry_attempts_observed=None,
    )


def _has_one_object_version(cleanup: _CleanupResult) -> bool:
    return (
        len(cleanup.versions_before) == 1
        and not cleanup.versions_before[0].delete_marker
        and cleanup.deleted_version_count == 1
        and cleanup.deleted_delete_marker_count == 0
    )


def _write_synthetic_file(path: Path, byte_length: int, label: str) -> None:
    if byte_length <= 0:
        raise ValueError("synthetic file byte length must be positive")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    remaining = byte_length
    counter = 0
    with os.fdopen(descriptor, "wb") as handle:
        while remaining:
            block = hashlib.sha256(
                f"cross-agent-memory:b2-canary:{label}:{counter}".encode()
            ).digest()
            payload = block[:remaining]
            handle.write(payload)
            remaining -= len(payload)
            counter += 1
        handle.flush()
        os.fsync(handle.fileno())


def _read_exact_part(path: Path) -> bytes:
    with path.open("rb") as handle:
        payload = handle.read(CANARY_MULTIPART_PART_BYTES)
    if len(payload) != CANARY_MULTIPART_PART_BYTES:
        raise RuntimeError("interrupted canary ciphertext is too short")
    return payload


def _mapping_entries(value: object, label: str) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuntimeError(f"{label} is invalid")
    result: list[dict[str, object]] = []
    for item in cast(list[object], value):
        if not isinstance(item, dict):
            raise RuntimeError(f"{label} is invalid")
        result.append({str(key): entry for key, entry in cast(dict[object, object], item).items()})
    return result


def _write_private_json(path: Path, value: Mapping[str, object], *, replace: bool = False) -> None:
    normalized = Path(os.path.abspath(path.expanduser()))
    if normalized.name in {"", ".", ".."}:
        raise ValueError("private receipt path is invalid")
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > MAX_CANARY_RECEIPT_BYTES:
        raise ValueError("private receipt exceeds its size limit")
    parent_descriptor = open_directory_no_symlinks(
        normalized.parent,
        "private receipt parent",
    )
    temporary_name = f".{normalized.name}.{uuid.uuid4().hex}.partial"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_descriptor)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            try:
                target = os.stat(
                    normalized.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ValueError("private receipt replacement target is invalid") from error
            if (
                not stat.S_ISREG(target.st_mode)
                or target.st_uid != os.geteuid()
                or target.st_nlink != 1
                or stat.S_IMODE(target.st_mode) != 0o600
            ):
                raise ValueError("private receipt replacement target is invalid")
            os.replace(
                temporary_name,
                normalized.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
        else:
            os.link(
                temporary_name,
                normalized.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def _remove_private_json(path: Path) -> None:
    normalized = Path(os.path.abspath(path.expanduser()))
    if normalized.name in {"", ".", ".."}:
        raise ValueError("private receipt path is invalid")
    parent_descriptor = open_directory_no_symlinks(
        normalized.parent,
        "private receipt parent",
    )
    try:
        try:
            metadata = os.stat(
                normalized.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            if error.errno == errno.ENOENT:
                return
            raise ValueError("private receipt could not be inspected") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("private receipt removal target is invalid")
        os.unlink(normalized.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _require_new_output(path: Path) -> None:
    normalized = Path(os.path.abspath(path.expanduser()))
    if normalized.name in {"", ".", ".."}:
        raise ValueError("private output path is invalid")
    parent_descriptor = open_directory_no_symlinks(
        normalized.parent,
        "private output parent",
    )
    try:
        try:
            os.stat(normalized.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return
            raise ValueError("private output path could not be inspected") from error
        raise ValueError(f"private output already exists: {normalized}")
    finally:
        os.close(parent_descriptor)


def _profile_from_environment(environment: Mapping[str, str]) -> B2S3Profile:
    bucket = _required_environment(environment, "CAM_B2_BUCKET")
    region = _required_environment(environment, "CAM_B2_REGION")
    endpoint_url = environment.get("CAM_B2_ENDPOINT_URL") or (
        f"https://s3.{region}.backblazeb2.com"
    )
    return B2S3Profile(
        bucket=bucket,
        endpoint_url=endpoint_url,
        region=region,
        multipart_threshold_bytes=CANARY_MULTIPART_THRESHOLD_BYTES,
        multipart_part_bytes=CANARY_MULTIPART_PART_BYTES,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verify-b2-provider")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("inspect", help="inspect normalized bucket settings without writing")
    run = subparsers.add_parser("run", help="run and clean the bounded encrypted B2 canary")
    run.add_argument("--receipt", type=Path, required=True)
    run.add_argument("--execute", action="store_true")
    verify = subparsers.add_parser(
        "verify-cleanup", help="independently prove exact canary keys are absent"
    )
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--receipt-sha256", required=True)
    retained = subparsers.add_parser(
        "retained-version-run",
        help="prove key-only deletion retains a readable version, then clean it",
    )
    retained.add_argument("--receipt", type=Path, required=True)
    retained.add_argument("--execute", action="store_true")
    retained_verify = subparsers.add_parser(
        "retained-version-verify-cleanup",
        help="independently prove the retained-version canary key is absent",
    )
    retained_verify.add_argument("--receipt", type=Path, required=True)
    retained_verify.add_argument("--receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    if args.command in {"run", "retained-version-run"} and not cast(bool, args.execute):
        if args.command == "retained-version-run":
            _emit_json(
                {
                    "status": "planned",
                    "network_access": False,
                    "completed_object_count": 1,
                    "key_only_delete_count": 1,
                    "retained_version_readback_count": 1,
                }
            )
            return
        _emit_json(
            {
                "status": "planned",
                "network_access": False,
                "completed_object_count": 2,
                "interrupted_multipart_count": 1,
            }
        )
        return
    try:
        profile = _profile_from_environment(os.environ)
        client = create_b2_s3_client(profile)
        if args.command == "inspect":
            inspection = inspect_b2_canary_settings(client, profile)
            _emit_json({"status": "inspected", **inspection.as_dict()})
            if not inspection.eligible:
                raise SystemExit(2)
            return
        if args.command == "run":
            receipt_path = Path(os.path.abspath(cast(Path, args.receipt).expanduser()))
            receipt = run_b2_canary(client, profile, receipt_path)
            digest = hashlib.sha256(_read_private_receipt_bytes(receipt_path)).hexdigest()
            _emit_json(
                {
                    "status": receipt.status,
                    "receipt_path": str(receipt_path),
                    "receipt_sha256": digest,
                    "cleanup_verified": receipt.cleanup_verified,
                }
            )
            return
        if args.command == "retained-version-run":
            receipt_path = Path(os.path.abspath(cast(Path, args.receipt).expanduser()))
            receipt = run_b2_retained_version_canary(client, profile, receipt_path)
            digest = hashlib.sha256(_read_private_receipt_bytes(receipt_path)).hexdigest()
            _emit_json(
                {
                    "status": receipt.status,
                    "receipt_path": str(receipt_path),
                    "receipt_sha256": digest,
                    "retained_version_readback_verified": (
                        receipt.retained_version_readback_verified
                    ),
                    "cleanup_verified": receipt.cleanup_verified,
                }
            )
            return
        if args.command == "verify-cleanup":
            receipt_path = Path(os.path.abspath(cast(Path, args.receipt).expanduser()))
            expected = cast(str, args.receipt_sha256)
            receipt, digest = load_b2_canary_receipt(receipt_path, expected)
            result = verify_b2_canary_cleanup(client, profile, receipt, digest)
            _emit_json({"status": "verified", **result.as_dict()})
            if not result.verified_absent:
                raise SystemExit(2)
            return
        if args.command == "retained-version-verify-cleanup":
            receipt_path = Path(os.path.abspath(cast(Path, args.receipt).expanduser()))
            expected = cast(str, args.receipt_sha256)
            receipt, digest = load_b2_retained_version_receipt(receipt_path, expected)
            result = verify_b2_canary_cleanup(client, profile, receipt, digest)
            _emit_json({"status": "verified", **result.as_dict()})
            if not result.verified_absent:
                raise SystemExit(2)
            return
        raise AssertionError(args.command)
    except B2CanarySafetyError as error:
        _emit_json(
            {
                "status": "failed_closed",
                "failure_type": type(error).__name__,
                "reason": str(error),
            }
        )
        raise SystemExit(2) from error
    except Exception as error:
        _emit_json({"status": "failed", "failure_type": type(error).__name__})
        raise SystemExit(1) from error


def _emit_json(value: Mapping[str, object]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def _required_environment(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if value is None or not value.strip():
        raise RuntimeError(f"required nonsecret environment variable is missing: {name}")
    return value


def _load_private_receipt(
    receipt_path: Path,
    expected_sha256: str,
) -> tuple[dict[str, object], str]:
    if len(expected_sha256) != 64 or any(
        value not in "0123456789abcdef" for value in expected_sha256
    ):
        raise ValueError("expected receipt SHA-256 is invalid")
    raw = _read_private_receipt_bytes(receipt_path)
    observed = hashlib.sha256(raw).hexdigest()
    if observed != expected_sha256:
        raise ValueError("B2 canary receipt SHA-256 does not match")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"B2 canary receipt contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("B2 canary receipt is not valid JSON") from error
    return _required_mapping(value, "B2 canary receipt"), observed


def _read_private_receipt_bytes(receipt_path: Path) -> bytes:
    normalized = Path(os.path.abspath(receipt_path.expanduser()))
    if normalized.name in {"", ".", ".."}:
        raise ValueError("B2 canary receipt path is invalid")
    parent_descriptor = open_directory_no_symlinks(
        normalized.parent,
        "B2 canary receipt parent",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(normalized.name, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise ValueError("B2 canary receipt must be a regular file without symlinks") from error
    finally:
        os.close(parent_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_CANARY_RECEIPT_BYTES
        ):
            raise ValueError("B2 canary receipt identity or permissions are invalid")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_CANARY_RECEIPT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_CANARY_RECEIPT_BYTES:
        raise ValueError("B2 canary receipt exceeds its size limit")
    return raw


def _response_string(response: Mapping[str, object], key: str) -> str:
    value = response.get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"provider response omitted {key}")
    return value


def _object_key(storage_object_id: str) -> str:
    _validate_storage_object_id(storage_object_id)
    return f"{B2_OBJECT_KEY_PREFIX}{storage_object_id}"


def _validate_storage_object_id(value: str) -> None:
    suffix = value.removeprefix(_STORAGE_OBJECT_ID_PREFIX)
    if (
        not value.startswith(_STORAGE_OBJECT_ID_PREFIX)
        or len(suffix) != 32
        or any(character not in "0123456789abcdef" for character in suffix)
    ):
        raise ValueError("canary storage object id is invalid")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _required_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return {str(key): item for key, item in cast(dict[object, object], value).items()}


def _required_list(fields: Mapping[str, object], key: str) -> list[object]:
    value = fields.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be an array")
    return cast(list[object], value)


def _required_string(fields: Mapping[str, object], key: str) -> str:
    value = fields.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a nonempty string")
    return value


def _required_sha256(fields: Mapping[str, object], key: str) -> str:
    value = _required_string(fields, key)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{key} must be a lowercase SHA-256 digest")
    return value


if __name__ == "__main__":
    main()
