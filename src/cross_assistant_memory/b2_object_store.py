from __future__ import annotations

import hashlib
import io
import json
import os
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib import import_module
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from cross_assistant_memory.object_store import (
    BackendObjectStat,
    IncompleteCleanupReport,
    ObjectPurgeInventory,
    ObjectVersion,
    ProviderSetting,
    ProviderSettingsReport,
    SettingState,
)

B2_S3_PROFILE = "backblaze-b2-s3-v1"
B2_OBJECT_KEY_PREFIX = "objects/"
MIN_MULTIPART_PART_BYTES = 5 * 1024 * 1024
MAX_MULTIPART_PART_BYTES = 5 * 1024 * 1024 * 1024
MAX_MULTIPART_PARTS = 10_000
MAX_B2_OBJECT_BYTES = 10 * 1000 * 1000 * 1000 * 1000
DEFAULT_MULTIPART_PART_BYTES = 64 * 1024 * 1024
DEFAULT_MULTIPART_THRESHOLD_BYTES = 128 * 1024 * 1024

_STORAGE_OBJECT_ID = re.compile(r"storage_[0-9a-f]{32}")
_ENVIRONMENT_VARIABLE = re.compile(r"[A-Z_][A-Z0-9_]*")
_B2_ENDPOINT = re.compile(r"https://s3\.[a-z0-9-]+\.backblazeb2\.com/?", re.ASCII | re.IGNORECASE)
_MISSING_OBJECT_CODES = frozenset({"404", "NoSuchKey", "NotFound"})
_PERMISSION_CODES = frozenset(
    {
        "401",
        "403",
        "AccessDenied",
        "InvalidAccessKeyId",
        "SignatureDoesNotMatch",
    }
)
_UNSUPPORTED_CODES = frozenset(
    {"405", "MethodNotAllowed", "NotImplemented", "NotImplementedException", "XNotImplemented"}
)


class S3Client(Protocol):
    def head_bucket(self, **kwargs: object) -> dict[str, object]: ...

    def head_object(self, **kwargs: object) -> dict[str, object]: ...

    def get_object(self, **kwargs: object) -> dict[str, object]: ...

    def put_object(self, **kwargs: object) -> dict[str, object]: ...

    def create_multipart_upload(self, **kwargs: object) -> dict[str, object]: ...

    def upload_part(self, **kwargs: object) -> dict[str, object]: ...

    def complete_multipart_upload(self, **kwargs: object) -> dict[str, object]: ...

    def abort_multipart_upload(self, **kwargs: object) -> dict[str, object]: ...

    def list_multipart_uploads(self, **kwargs: object) -> dict[str, object]: ...

    def list_object_versions(self, **kwargs: object) -> dict[str, object]: ...

    def delete_object(self, **kwargs: object) -> dict[str, object]: ...

    def get_bucket_versioning(self, **kwargs: object) -> dict[str, object]: ...

    def get_bucket_lifecycle_configuration(self, **kwargs: object) -> dict[str, object]: ...

    def get_object_lock_configuration(self, **kwargs: object) -> dict[str, object]: ...


class ReadableBody(Protocol):
    def read(self, size: int | None = -1) -> bytes: ...

    def close(self) -> None: ...


class RemoteObjectReader(io.BufferedIOBase):
    def __init__(self, body: ReadableBody) -> None:
        self._body = body
        self._closed = False

    def readable(self) -> bool:
        return True

    def read(self, size: int | None = -1) -> bytes:
        if self._closed:
            raise ValueError("I/O operation on closed remote object")
        return self._body.read(size)

    def close(self) -> None:
        if not self._closed:
            self._body.close()
            self._closed = True
        super().close()


@dataclass(frozen=True)
class B2S3Profile:
    bucket: str
    endpoint_url: str
    region: str
    application_key_id_env: str = "B2_APPLICATION_KEY_ID"
    application_key_env: str = "B2_APPLICATION_KEY"
    multipart_threshold_bytes: int = DEFAULT_MULTIPART_THRESHOLD_BYTES
    multipart_part_bytes: int = DEFAULT_MULTIPART_PART_BYTES
    cleanup_abort_limit: int = 100
    cleanup_scan_limit: int = 1_000
    total_max_attempts: int = 4
    connect_timeout_seconds: int = 10
    read_timeout_seconds: int = 60

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> B2S3Profile:
        environment = os.environ if environ is None else environ
        bucket = environment.get("CAM_B2_BUCKET", "")
        region = environment.get("CAM_B2_REGION", "")
        if not bucket.strip() or not region.strip():
            raise ValueError("CAM_B2_BUCKET and CAM_B2_REGION are required")
        endpoint = environment.get("CAM_B2_ENDPOINT_URL") or (
            f"https://s3.{region}.backblazeb2.com"
        )
        return cls(bucket=bucket, endpoint_url=endpoint, region=region)

    def __post_init__(self) -> None:
        if not self.bucket or "/" in self.bucket or len(self.bucket) > 255:
            raise ValueError("B2 bucket name is invalid")
        if not re.fullmatch(r"[a-z0-9-]+", self.region):
            raise ValueError("B2 region is invalid")
        endpoint = _canonical_b2_endpoint(self.endpoint_url)
        if endpoint != f"https://s3.{self.region}.backblazeb2.com":
            raise ValueError("B2 endpoint must be the HTTPS S3 endpoint for the configured region")
        for variable in (self.application_key_id_env, self.application_key_env):
            if not _ENVIRONMENT_VARIABLE.fullmatch(variable):
                raise ValueError("B2 credential environment variable name is invalid")
        _validate_multipart_configuration(
            threshold_bytes=self.multipart_threshold_bytes,
            part_bytes=self.multipart_part_bytes,
        )
        if not 1 <= self.cleanup_abort_limit <= self.cleanup_scan_limit <= 10_000:
            raise ValueError("B2 multipart cleanup bounds are invalid")
        if not 1 <= self.total_max_attempts <= 10:
            raise ValueError("B2 retry attempt bound is invalid")
        if self.connect_timeout_seconds <= 0 or self.read_timeout_seconds <= 0:
            raise ValueError("B2 timeout must be positive")


@dataclass(frozen=True)
class B2S3Bindings:
    backend: B2S3ObjectBackend
    settings: B2S3SettingsInspector


class B2S3ObjectBackend:
    def __init__(
        self,
        client: S3Client,
        bucket: str,
        *,
        endpoint_url: str | None = None,
        multipart_threshold_bytes: int = DEFAULT_MULTIPART_THRESHOLD_BYTES,
        multipart_part_bytes: int = DEFAULT_MULTIPART_PART_BYTES,
        cleanup_abort_limit: int = 100,
        cleanup_scan_limit: int = 1_000,
    ) -> None:
        if not bucket:
            raise ValueError("B2 bucket name is required")
        _validate_multipart_configuration(
            threshold_bytes=multipart_threshold_bytes,
            part_bytes=multipart_part_bytes,
        )
        if not 1 <= cleanup_abort_limit <= cleanup_scan_limit:
            raise ValueError("B2 multipart cleanup bounds are invalid")
        self._client = client
        self._bucket = bucket
        self._endpoint_url = (
            _canonical_b2_endpoint(endpoint_url) if endpoint_url is not None else None
        )
        self._multipart_threshold_bytes = multipart_threshold_bytes
        self._multipart_part_bytes = multipart_part_bytes
        self._cleanup_abort_limit = cleanup_abort_limit
        self._cleanup_scan_limit = cleanup_scan_limit

    @property
    def profile(self) -> str:
        return B2_S3_PROFILE

    @property
    def identity_sha256(self) -> str:
        if self._endpoint_url is None:
            raise ValueError("B2 endpoint is required for backend identity")
        identity = json.dumps(
            [self.profile, self._bucket, self._endpoint_url], separators=(",", ":")
        )
        return hashlib.sha256(identity.encode()).hexdigest()

    def exists(self, storage_object_id: str) -> bool:
        try:
            self.stat(storage_object_id)
        except KeyError:
            return False
        return True

    def inspect_object_purge(self, storage_object_id: str) -> ObjectPurgeInventory:
        _object_key(storage_object_id)
        scope = ObjectPurgeInventory(self.identity_sha256, storage_object_id)
        inventory = self._purge_inventory(scope)
        if inventory != self._purge_inventory(scope):
            raise RuntimeError("B2 object purge inventory changed during inspection")
        return inventory

    def purge_object(self, storage_object_id: str, expected: ObjectPurgeInventory) -> None:
        # The caller retains approval and exclusive durable ownership of this exact key.
        # Rechecks observe current state, not the absence of future late requests.
        key = _object_key(storage_object_id)
        if not isinstance(cast(object, expected), ObjectPurgeInventory):
            raise ValueError("B2 object purge requires a retained inventory")
        scope = ObjectPurgeInventory(self.identity_sha256, storage_object_id)
        scope.require_subset_of(expected)
        current = self.inspect_object_purge(storage_object_id)
        current.require_subset_of(expected)
        if len(current.incomplete_upload_ids) > self._cleanup_abort_limit:
            raise RuntimeError("B2 object purge exceeded its abort budget")
        for upload_id in current.incomplete_upload_ids:
            self._purge_request(
                scope,
                self._client.abort_multipart_upload,
                Bucket=self._bucket,
                Key=key,
                UploadId=upload_id,
            )
        current = self.inspect_object_purge(storage_object_id)
        current.require_subset_of(expected)
        if current.incomplete_upload_ids:
            raise RuntimeError("B2 object purge still has incomplete uploads")
        for version in current.versions:
            self._purge_request(
                scope,
                self._client.delete_object,
                Bucket=self._bucket,
                Key=key,
                VersionId=version.version_id,
            )
        if self.inspect_object_purge(storage_object_id) != scope:
            raise RuntimeError("B2 object purge inventory is not empty")
        self._check_purge_scope(scope)
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
        except Exception as error:
            if _provider_error_code(error) not in _MISSING_OBJECT_CODES:
                raise RuntimeError("B2 object purge current-key check failed") from None
            present = False
        else:
            present = True
        self._check_purge_scope(scope)
        if present:
            raise RuntimeError("B2 object purge current key is still present")

    def _check_purge_scope(self, scope: ObjectPurgeInventory) -> None:
        if self.identity_sha256 != scope.backend_identity_sha256:
            raise RuntimeError("B2 object purge backend identity changed")

    def _purge_request(
        self,
        scope: ObjectPurgeInventory,
        call: Callable[..., object],
        **request: object,
    ) -> dict[str, object]:
        self._check_purge_scope(scope)
        try:
            response = call(**request)
        except Exception:
            raise RuntimeError("B2 object purge provider request failed") from None
        self._check_purge_scope(scope)
        if not isinstance(response, dict):
            raise RuntimeError("B2 object purge provider response is invalid")
        return cast(dict[str, object], response)

    def _purge_inventory(self, scope: ObjectPurgeInventory) -> ObjectPurgeInventory:
        key = _object_key(scope.storage_object_id)
        versions: list[ObjectVersion] = []
        uploads: list[str] = []
        try:
            for entry, delete_marker in self._purge_entries(scope, multipart=False):
                size = entry.get("Size")
                if size is not None and type(size) is not int:
                    raise ValueError("invalid version size")
                version = ObjectVersion(
                    version_id=cast(str, entry["VersionId"]),
                    byte_length=size,
                    delete_marker=delete_marker,
                )
                if entry["Key"] == key:
                    versions.append(version)
            for entry, _ in self._purge_entries(scope, multipart=True):
                if entry["Key"] == key:
                    uploads.append(cast(str, entry["UploadId"]))
            return ObjectPurgeInventory(
                scope.backend_identity_sha256,
                scope.storage_object_id,
                tuple(versions),
                tuple(uploads),
            )
        except ValueError:
            raise RuntimeError("B2 object purge inventory contains invalid metadata") from None

    def _purge_entries(
        self, scope: ObjectPurgeInventory, *, multipart: bool
    ) -> Iterator[tuple[dict[str, object], bool]]:
        # Both listings share bounded exact-prefix pagination; only exact-key rows mutate.
        key = _object_key(scope.storage_object_id)
        call = (
            self._client.list_multipart_uploads if multipart else self._client.list_object_versions
        )
        fields = ("Uploads",) if multipart else ("Versions", "DeleteMarkers")
        id_field = "UploadId" if multipart else "VersionId"
        marker_field = "UploadIdMarker" if multipart else "VersionIdMarker"
        maximum_field = "MaxUploads" if multipart else "MaxKeys"
        marker: tuple[str, str] | None = None
        seen_markers: set[tuple[str, str]] = set()
        seen_entries: set[tuple[str, str]] = set()
        scanned = 0
        while scanned < self._cleanup_scan_limit:
            maximum = min(1_000, self._cleanup_scan_limit - scanned)
            request: dict[str, object] = {
                "Bucket": self._bucket,
                "Prefix": key,
                maximum_field: maximum,
            }
            if marker is not None:
                request["KeyMarker"], request[marker_field] = marker
            response = self._purge_request(scope, call, **request)
            if type(response.get("IsTruncated")) is not bool:
                raise RuntimeError("B2 object purge listing omitted a valid completeness flag")
            if response.get("CommonPrefixes", []) != []:
                raise RuntimeError("B2 object purge listing unexpectedly grouped keys")
            entries: list[tuple[dict[str, object], bool]] = []
            for field in fields:
                raw_entries = response.get(field, [])
                if not isinstance(raw_entries, list):
                    raise RuntimeError("B2 object purge listing contains an invalid entry list")
                listed_entries = cast(list[object], raw_entries)
                if len(listed_entries) > maximum - len(entries):
                    raise RuntimeError("B2 object purge inventory exceeded its scan budget")
                for raw_entry in listed_entries:
                    if not isinstance(raw_entry, dict):
                        raise RuntimeError("B2 object purge listing contains an invalid entry")
                    if any(
                        not isinstance(name, str) for name in cast(dict[object, object], raw_entry)
                    ):
                        raise RuntimeError("B2 object purge listing contains an invalid field")
                    entries.append((cast(dict[str, object], raw_entry), field == "DeleteMarkers"))
            for entry, delete_marker in entries:
                candidate_key = _purge_identifier(entry.get("Key"))
                entry_id = _purge_identifier(entry.get(id_field))
                if not candidate_key.startswith(key):
                    raise RuntimeError("B2 object purge listing returned an out-of-scope key")
                identity = (candidate_key, entry_id)
                if identity in seen_entries:
                    raise RuntimeError("B2 object purge listing repeated an identity")
                seen_entries.add(identity)
                yield entry, delete_marker
            scanned += len(entries)
            if not response["IsTruncated"]:
                return
            next_key = _purge_identifier(response.get("NextKeyMarker"))
            next_id = _purge_identifier(response.get(f"Next{marker_field}"))
            if not entries or not next_key.startswith(key):
                raise RuntimeError("B2 object purge listing omitted valid continuation markers")
            marker = (next_key, next_id)
            if marker in seen_markers:
                raise RuntimeError("B2 object purge listing repeated its continuation marker")
            seen_markers.add(marker)
        raise RuntimeError("B2 object purge inventory exceeded its scan budget")

    def put_file(self, storage_object_id: str, source: Path) -> None:
        key = _object_key(storage_object_id)
        source = source.expanduser()
        identity = _regular_file_identity(source)
        byte_length = identity[2]
        if byte_length > MAX_B2_OBJECT_BYTES:
            raise ValueError("encrypted object exceeds the B2 object-size limit")
        part_count = (byte_length + self._multipart_part_bytes - 1) // self._multipart_part_bytes
        if part_count > MAX_MULTIPART_PARTS:
            raise ValueError("encrypted object requires too many multipart parts")
        if self.exists(storage_object_id):
            return
        if byte_length < self._multipart_threshold_bytes:
            self._put_single(key, source, byte_length, identity)
            return
        self._put_multipart(storage_object_id, key, source, byte_length, identity)

    def put_recoverable_file(self, storage_object_id: str, source: Path) -> None:
        # The caller owns this random key through its durable package and holds the
        # single-writer lease. Listing also recovers IDs lost before create returned.
        _regular_file_identity(source.expanduser())
        self.reconcile_multipart(storage_object_id)
        self.put_file(storage_object_id, source)
        self.reconcile_multipart(storage_object_id)

    def reconcile_multipart(self, storage_object_id: str) -> int:
        key = _object_key(storage_object_id)
        uploads = self._multipart_for_key(key)
        if uploads != self._multipart_for_key(key):
            raise RuntimeError("B2 object multipart inventory changed; retry retained staging")
        if not uploads:
            return 0
        if len(uploads) > self._cleanup_abort_limit:
            raise RuntimeError("B2 object multipart abort budget exceeded")
        for upload_id in uploads:
            try:
                self._client.abort_multipart_upload(
                    Bucket=self._bucket,
                    Key=key,
                    UploadId=upload_id,
                )
            except Exception as error:
                if _provider_error_code(error) != "NoSuchUpload":
                    raise
        if self._multipart_for_key(key) or self._multipart_for_key(key):
            raise RuntimeError("B2 object still has incomplete uploads; retry retained staging")
        return len(uploads)

    def _multipart_for_key(self, key: str) -> tuple[str, ...]:
        marker: tuple[str, str] | None = None
        seen_markers: set[tuple[str, str]] = set()
        seen_uploads: set[tuple[str, str]] = set()
        matching: list[str] = []
        scanned = 0
        while scanned < self._cleanup_scan_limit:
            remaining = self._cleanup_scan_limit - scanned
            request: dict[str, object] = {
                "Bucket": self._bucket,
                "Prefix": key,
                "MaxUploads": min(1_000, remaining),
            }
            if marker is not None:
                request["KeyMarker"], request["UploadIdMarker"] = marker
            response = self._client.list_multipart_uploads(**request)
            if type(response.get("IsTruncated")) is not bool:
                raise RuntimeError("B2 multipart listing omitted a valid completeness flag")
            if response.get("CommonPrefixes"):
                raise RuntimeError("B2 object multipart listing unexpectedly grouped keys")
            uploads = _mapping_list(response.get("Uploads"), "B2 object multipart uploads")
            if len(uploads) > min(1_000, remaining):
                raise RuntimeError("B2 object multipart inventory exceeded its scan budget")
            for upload in uploads:
                candidate_key = upload.get("Key")
                upload_id = upload.get("UploadId")
                if (
                    not isinstance(candidate_key, str)
                    or not candidate_key.startswith(key)
                    or not isinstance(upload_id, str)
                    or not 1 <= len(upload_id) <= 1_024
                ):
                    raise RuntimeError("B2 multipart listing contains an invalid object identity")
                identity = (candidate_key, upload_id)
                if identity in seen_uploads:
                    raise RuntimeError("B2 multipart listing repeated an upload")
                seen_uploads.add(identity)
                if candidate_key == key:
                    matching.append(upload_id)
            scanned += len(uploads)
            if not response["IsTruncated"]:
                return tuple(sorted(matching))
            next_key, next_upload = (
                response.get("NextKeyMarker"),
                response.get("NextUploadIdMarker"),
            )
            if (
                not uploads
                or not isinstance(next_key, str)
                or not next_key.startswith(key)
                or not isinstance(next_upload, str)
                or not 1 <= len(next_upload) <= 1_024
            ):
                raise RuntimeError("B2 multipart listing omitted valid continuation markers")
            marker = (next_key, next_upload)
            if marker in seen_markers:
                raise RuntimeError("B2 multipart listing repeated its continuation marker")
            seen_markers.add(marker)
        raise RuntimeError("B2 object multipart inventory exceeded its scan budget")

    def open(self, storage_object_id: str) -> BinaryIO:
        key = _object_key(storage_object_id)
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
        except Exception as error:
            if _provider_error_code(error) in _MISSING_OBJECT_CODES:
                raise KeyError(
                    f"encrypted backend object is missing: {storage_object_id}"
                ) from error
            raise
        body = response.get("Body")
        if (
            body is None
            or not callable(getattr(body, "read", None))
            or not callable(getattr(body, "close", None))
        ):
            raise RuntimeError("B2 object response does not contain a readable body")
        return cast(BinaryIO, RemoteObjectReader(cast(ReadableBody, body)))

    def stat(self, storage_object_id: str) -> BackendObjectStat:
        key = _object_key(storage_object_id)
        try:
            response = self._client.head_object(Bucket=self._bucket, Key=key)
        except Exception as error:
            if _provider_error_code(error) in _MISSING_OBJECT_CODES:
                raise KeyError(
                    f"encrypted backend object is missing: {storage_object_id}"
                ) from error
            raise
        byte_length = response.get("ContentLength")
        if not isinstance(byte_length, int) or byte_length < 0:
            raise RuntimeError("B2 object response has an invalid content length")
        etag = response.get("ETag")
        version_id = response.get("VersionId")
        return BackendObjectStat(
            byte_length=byte_length,
            etag=etag if isinstance(etag, str) else None,
            version_id=version_id if isinstance(version_id, str) else None,
        )

    def cleanup_incomplete(self, *, older_than_epoch: float) -> IncompleteCleanupReport:
        removed: list[str] = []
        scanned = 0
        key_marker: str | None = None
        upload_id_marker: str | None = None
        truncated = False
        while scanned < self._cleanup_scan_limit:
            request: dict[str, object] = {
                "Bucket": self._bucket,
                "Prefix": B2_OBJECT_KEY_PREFIX,
                "MaxUploads": min(1_000, self._cleanup_scan_limit - scanned),
            }
            if key_marker is not None:
                request["KeyMarker"] = key_marker
            if upload_id_marker is not None:
                request["UploadIdMarker"] = upload_id_marker
            response = self._client.list_multipart_uploads(**request)
            uploads = _mapping_list(response.get("Uploads"), "B2 multipart upload list")
            for upload in uploads:
                if scanned >= self._cleanup_scan_limit:
                    truncated = True
                    break
                scanned += 1
                key = upload.get("Key")
                upload_id = upload.get("UploadId")
                initiated = _datetime_epoch(upload.get("Initiated"))
                storage_object_id = _storage_object_id_from_key(key)
                if (
                    storage_object_id is None
                    or not isinstance(upload_id, str)
                    or not upload_id
                    or initiated is None
                    or initiated > older_than_epoch
                ):
                    continue
                if len(removed) >= self._cleanup_abort_limit:
                    truncated = True
                    break
                self._client.abort_multipart_upload(
                    Bucket=self._bucket,
                    Key=key,
                    UploadId=upload_id,
                )
                removed.append(storage_object_id)
            if truncated:
                break
            is_truncated = response.get("IsTruncated") is True
            if not is_truncated:
                break
            next_key = response.get("NextKeyMarker")
            next_upload_id = response.get("NextUploadIdMarker")
            if not isinstance(next_key, str) or not isinstance(next_upload_id, str):
                raise RuntimeError("B2 multipart listing omitted continuation markers")
            key_marker = next_key
            upload_id_marker = next_upload_id
        else:
            truncated = True
        return IncompleteCleanupReport(
            removed_entries=tuple(removed),
            removed_count=len(removed),
            scanned_count=scanned,
            scan_truncated=truncated,
        )

    def _put_single(
        self,
        key: str,
        source: Path,
        byte_length: int,
        identity: tuple[int, int, int, int],
    ) -> None:
        try:
            with source.open("rb") as handle:
                self._client.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=handle,
                    ContentLength=byte_length,
                    ContentType="application/octet-stream",
                )
        except Exception:
            if self._key_exists(key):
                return
            raise
        _verify_file_identity(source, identity)

    def _put_multipart(
        self,
        storage_object_id: str,
        key: str,
        source: Path,
        byte_length: int,
        identity: tuple[int, int, int, int],
    ) -> None:
        created = self._client.create_multipart_upload(
            Bucket=self._bucket,
            Key=key,
            ContentType="application/octet-stream",
        )
        upload_id = created.get("UploadId")
        if not isinstance(upload_id, str) or not upload_id:
            raise RuntimeError("B2 multipart create response omitted the upload id")
        parts: list[dict[str, object]] = []
        bytes_read = 0
        try:
            with source.open("rb") as handle:
                for part_number in range(1, MAX_MULTIPART_PARTS + 1):
                    payload = handle.read(self._multipart_part_bytes)
                    if not payload:
                        break
                    bytes_read += len(payload)
                    uploaded = self._client.upload_part(
                        Bucket=self._bucket,
                        Key=key,
                        UploadId=upload_id,
                        PartNumber=part_number,
                        Body=payload,
                        ContentLength=len(payload),
                    )
                    etag = uploaded.get("ETag")
                    if not isinstance(etag, str) or not etag:
                        raise RuntimeError("B2 multipart part response omitted the ETag")
                    parts.append({"ETag": etag, "PartNumber": part_number})
            if bytes_read != byte_length or len(parts) < 2:
                raise RuntimeError("B2 multipart source size changed during upload")
            _verify_file_identity(source, identity)
            self._client.complete_multipart_upload(
                Bucket=self._bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except Exception:
            if self._key_exists(key):
                return
            try:
                self._client.abort_multipart_upload(
                    Bucket=self._bucket,
                    Key=key,
                    UploadId=upload_id,
                )
            except Exception as abort_error:
                raise RuntimeError(
                    "B2 multipart upload failed and abort also failed"
                ) from abort_error
            raise
        if not self.exists(storage_object_id):
            raise RuntimeError("B2 multipart completion did not create the object")

    def _key_exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
        except Exception as error:
            if _provider_error_code(error) in _MISSING_OBJECT_CODES:
                return False
            raise
        return True


class B2S3SettingsInspector:
    def __init__(self, client: S3Client, bucket: str) -> None:
        if not bucket:
            raise ValueError("B2 bucket name is required")
        self._client = client
        self._bucket = bucket

    @property
    def profile(self) -> str:
        return B2_S3_PROFILE

    def inspect(self) -> ProviderSettingsReport:
        access, _ = _inspect_setting(
            lambda: self._client.head_bucket(Bucket=self._bucket),
            lambda _: "reachable",
        )
        versioning, _ = _inspect_setting(
            lambda: self._client.get_bucket_versioning(Bucket=self._bucket),
            _versioning_summary,
        )
        lifecycle, _ = _inspect_setting(
            lambda: self._client.get_bucket_lifecycle_configuration(Bucket=self._bucket),
            _lifecycle_summary,
            not_configured=frozenset({"404", "NoSuchLifecycleConfiguration"}),
        )
        object_lock, lock_response = _inspect_setting(
            lambda: self._client.get_object_lock_configuration(Bucket=self._bucket),
            _object_lock_summary,
            not_configured=frozenset(
                {"404", "ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"}
            ),
        )
        retention = _retention_setting(object_lock, lock_response)
        replication = ProviderSetting(
            SettingState.UNSUPPORTED,
            "B2 S3 API does not expose bucket replication inspection",
        )
        consequences = [
            (
                "B2 buckets retain versions by default; deleting by key does not remove older "
                "versions."
            ),
            (
                "Lifecycle rules can hide or permanently delete versions and cancel unfinished "
                "uploads."
            ),
        ]
        if object_lock.summary == "status=Enabled":
            consequences.append(
                "Object Lock or legal hold can reject deletion until its protection permits it."
            )
        elif object_lock.state in {SettingState.PERMISSION_DENIED, SettingState.UNAVAILABLE}:
            consequences.append(
                "Object Lock could not be confirmed; destructive action must treat retention as "
                "unknown."
            )
        return ProviderSettingsReport(
            profile=self.profile,
            bucket_access=access,
            versioning=versioning,
            lifecycle=lifecycle,
            replication=replication,
            object_lock=object_lock,
            default_retention=retention,
            deletion_consequences=tuple(consequences),
        )


def create_b2_s3_bindings(
    profile: B2S3Profile,
    *,
    environ: Mapping[str, str] | None = None,
) -> B2S3Bindings:
    client = create_b2_s3_client(profile, environ=environ)
    return B2S3Bindings(
        backend=B2S3ObjectBackend(
            client,
            profile.bucket,
            endpoint_url=profile.endpoint_url,
            multipart_threshold_bytes=profile.multipart_threshold_bytes,
            multipart_part_bytes=profile.multipart_part_bytes,
            cleanup_abort_limit=profile.cleanup_abort_limit,
            cleanup_scan_limit=profile.cleanup_scan_limit,
        ),
        settings=B2S3SettingsInspector(client, profile.bucket),
    )


def create_b2_s3_client(
    profile: B2S3Profile,
    *,
    environ: Mapping[str, str] | None = None,
) -> S3Client:
    environment = os.environ if environ is None else environ
    key_id = _required_secret(environment, profile.application_key_id_env)
    application_key = _required_secret(environment, profile.application_key_env)
    config_factory = cast(Callable[..., object], import_module("botocore.config").Config)
    sdk_config = config_factory(
        signature_version="s3v4",
        retries={"mode": "standard", "total_max_attempts": profile.total_max_attempts},
        connect_timeout=profile.connect_timeout_seconds,
        read_timeout=profile.read_timeout_seconds,
        s3={"addressing_style": "path"},
    )
    client_factory = cast(Callable[..., object], import_module("boto3").client)
    return cast(
        S3Client,
        client_factory(
            "s3",
            endpoint_url=profile.endpoint_url,
            region_name=profile.region,
            aws_access_key_id=key_id,
            aws_secret_access_key=application_key,
            config=sdk_config,
        ),
    )


def _canonical_b2_endpoint(endpoint_url: str) -> str:
    if not _B2_ENDPOINT.fullmatch(endpoint_url):
        raise ValueError("B2 endpoint must be a canonical HTTPS S3 endpoint")
    return endpoint_url.removesuffix("/").lower()


def _validate_multipart_configuration(*, threshold_bytes: int, part_bytes: int) -> None:
    if not MIN_MULTIPART_PART_BYTES <= part_bytes <= MAX_MULTIPART_PART_BYTES:
        raise ValueError("B2 multipart part size is outside provider limits")
    if threshold_bytes < part_bytes * 2:
        raise ValueError("B2 multipart threshold must allow at least two full parts")


def _regular_file_identity(path: Path) -> tuple[int, int, int, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"encrypted object source is not a regular file: {path}")
    value = path.stat()
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def _verify_file_identity(path: Path, expected: tuple[int, int, int, int]) -> None:
    if _regular_file_identity(path) != expected:
        raise RuntimeError("encrypted object source changed during upload")


def _object_key(storage_object_id: str) -> str:
    if not _STORAGE_OBJECT_ID.fullmatch(storage_object_id):
        raise ValueError("storage object identifier is invalid")
    return f"{B2_OBJECT_KEY_PREFIX}{storage_object_id}"


def _storage_object_id_from_key(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith(B2_OBJECT_KEY_PREFIX):
        return None
    storage_object_id = value.removeprefix(B2_OBJECT_KEY_PREFIX)
    if not _STORAGE_OBJECT_ID.fullmatch(storage_object_id):
        return None
    return storage_object_id


def _provider_error_code(error: BaseException) -> str | None:
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return None
    error_value = cast(dict[object, object], response).get("Error")
    if not isinstance(error_value, dict):
        return None
    code = cast(dict[object, object], error_value).get("Code")
    return code if isinstance(code, str) else None


def _purge_identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1_024
        or not 1 <= len(value.encode()) <= 1_024
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("B2 object purge listing contains an invalid identity")
    return value


def _mapping_list(value: object, label: str) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuntimeError(f"{label} is invalid")
    result: list[dict[str, object]] = []
    for entry in cast(list[object], value):
        if not isinstance(entry, dict):
            raise RuntimeError(f"{label} is invalid")
        result.append({str(key): item for key, item in cast(dict[object, object], entry).items()})
    return result


def _datetime_epoch(value: object) -> float | None:
    if not isinstance(value, datetime):
        return None
    return value.timestamp()


def _inspect_setting(
    call: Callable[[], dict[str, object]],
    summarize: Callable[[dict[str, object]], str],
    *,
    not_configured: frozenset[str] = frozenset(),
) -> tuple[ProviderSetting, dict[str, object] | None]:
    try:
        response = call()
    except Exception as error:
        code = _provider_error_code(error)
        if code in not_configured:
            return ProviderSetting(SettingState.NOT_CONFIGURED, f"provider_code={code}"), None
        if code in _PERMISSION_CODES:
            return ProviderSetting(SettingState.PERMISSION_DENIED, f"provider_code={code}"), None
        if code in _UNSUPPORTED_CODES:
            return ProviderSetting(SettingState.UNSUPPORTED, f"provider_code={code}"), None
        label = code if code is not None else type(error).__name__
        return ProviderSetting(SettingState.UNAVAILABLE, f"provider_error={label}"), None
    try:
        summary = summarize(response)
    except (RuntimeError, TypeError, ValueError) as error:
        return ProviderSetting(SettingState.UNAVAILABLE, str(error)), None
    return ProviderSetting(SettingState.KNOWN, summary), response


def _versioning_summary(response: dict[str, object]) -> str:
    status = response.get("Status")
    if not isinstance(status, str) or not status:
        raise ValueError("versioning status missing from provider response")
    return f"status={status}"


def _lifecycle_summary(response: dict[str, object]) -> str:
    rules = _mapping_list(response.get("Rules"), "B2 lifecycle rule list")
    return f"rules={len(rules)}"


def _object_lock_summary(response: dict[str, object]) -> str:
    configuration = response.get("ObjectLockConfiguration")
    if not isinstance(configuration, dict):
        raise ValueError("Object Lock configuration missing from provider response")
    enabled = cast(dict[object, object], configuration).get("ObjectLockEnabled")
    if not isinstance(enabled, str) or not enabled:
        raise ValueError("Object Lock status missing from provider response")
    return f"status={enabled}"


def _retention_setting(
    object_lock: ProviderSetting,
    response: dict[str, object] | None,
) -> ProviderSetting:
    if response is None:
        if object_lock.state is SettingState.NOT_CONFIGURED:
            return ProviderSetting(SettingState.NOT_CONFIGURED, "Object Lock is not configured")
        return ProviderSetting(object_lock.state, object_lock.summary)
    configuration = response.get("ObjectLockConfiguration")
    if not isinstance(configuration, dict):
        return ProviderSetting(SettingState.UNAVAILABLE, "Object Lock configuration is invalid")
    rule = cast(dict[object, object], configuration).get("Rule")
    if not isinstance(rule, dict):
        return ProviderSetting(SettingState.NOT_CONFIGURED, "no default retention")
    default = cast(dict[object, object], rule).get("DefaultRetention")
    if not isinstance(default, dict):
        return ProviderSetting(SettingState.NOT_CONFIGURED, "no default retention")
    values = cast(dict[object, object], default)
    mode = values.get("Mode")
    days = values.get("Days")
    years = values.get("Years")
    if not isinstance(mode, str):
        return ProviderSetting(SettingState.UNAVAILABLE, "default retention mode is invalid")
    if isinstance(days, int) and days > 0 and years is None:
        return ProviderSetting(SettingState.KNOWN, f"mode={mode}; days={days}")
    if isinstance(years, int) and years > 0 and days is None:
        return ProviderSetting(SettingState.KNOWN, f"mode={mode}; years={years}")
    return ProviderSetting(SettingState.UNAVAILABLE, "default retention period is invalid")


def _required_secret(environment: Mapping[str, str], variable: str) -> str:
    value = environment.get(variable)
    if value is None or not value.strip():
        raise RuntimeError(f"required B2 credential environment variable is missing: {variable}")
    return value
