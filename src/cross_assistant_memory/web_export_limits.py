from __future__ import annotations

import hashlib
import os
import resource
import stat
import struct
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, cast

COPY_CHUNK_BYTES = 1024 * 1024
_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_MAX_EOCD_SEARCH_BYTES = 22 + 65535
_SUPPORTED_COMPRESSION_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_JSON_MEMORY_MULTIPLIER = 64
_SPAN_MEMORY_BYTES = 64
_MANIFEST_ENTRY_MEMORY_BYTES = 4096
_ZIP_INFO_MEMORY_BYTES = 1024
_SUPPLEMENTAL_MEMBER_MANIFEST_MEMORY_BYTES = 1024
_ATTACHMENT_REFERENCE_MEMORY_BYTES = 1024
_ATTACHMENT_PLAN_MEMBER_MEMORY_BYTES = 2048
_ATTACHMENT_MEDIA_TYPES = {
    ".csv": "text/csv",
    ".gif": "image/gif",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".json": "application/json",
    ".md": "text/markdown",
    ".mp3": "audio/mpeg",
    ".mp4": "video/mp4",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".txt": "text/plain",
    ".wav": "audio/wav",
    ".webp": "image/webp",
}


class WebExportLimitError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class WebExportLimits:
    max_archive_bytes: int
    max_member_count: int
    max_total_uncompressed_bytes: int
    max_member_uncompressed_bytes: int
    max_compression_ratio: int
    max_json_depth: int
    max_record_count: int
    max_json_string_bytes: int
    max_attachment_bytes: int
    max_cpu_seconds: int
    max_memory_bytes: int
    max_temp_disk_bytes: int
    max_elapsed_seconds: int

    def as_dict(self) -> dict[str, object]:
        return {
            "max_archive_bytes": self.max_archive_bytes,
            "max_member_count": self.max_member_count,
            "max_total_uncompressed_bytes": self.max_total_uncompressed_bytes,
            "max_member_uncompressed_bytes": self.max_member_uncompressed_bytes,
            "max_compression_ratio": self.max_compression_ratio,
            "supported_compression_methods": sorted(_SUPPORTED_COMPRESSION_METHODS),
            "max_json_depth": self.max_json_depth,
            "max_record_count": self.max_record_count,
            "max_json_string_bytes": self.max_json_string_bytes,
            "max_attachment_bytes": self.max_attachment_bytes,
            "max_cpu_seconds": self.max_cpu_seconds,
            "max_memory_bytes": self.max_memory_bytes,
            "max_temp_disk_bytes": self.max_temp_disk_bytes,
            "max_elapsed_seconds": self.max_elapsed_seconds,
        }


DEFAULT_WEB_EXPORT_LIMITS = WebExportLimits(
    max_archive_bytes=8 * 1024 * 1024 * 1024,
    max_member_count=100_000,
    max_total_uncompressed_bytes=32 * 1024 * 1024 * 1024,
    max_member_uncompressed_bytes=8 * 1024 * 1024 * 1024,
    max_compression_ratio=200,
    max_json_depth=128,
    max_record_count=5_000_000,
    max_json_string_bytes=32 * 1024 * 1024,
    max_attachment_bytes=24 * 1024 * 1024 * 1024,
    max_cpu_seconds=30 * 60,
    max_memory_bytes=2 * 1024 * 1024 * 1024,
    max_temp_disk_bytes=16 * 1024 * 1024 * 1024,
    max_elapsed_seconds=60 * 60,
)


@dataclass(frozen=True)
class SupplementalMemberInspection:
    archive_member_index: int
    member_name: str
    locator: str
    name_sha256: str
    content_sha256: str
    compressed_bytes: int
    byte_length: int
    compression_method: int
    media_type: str

    def as_dict(self) -> dict[str, object]:
        return {
            "archive_member_index": self.archive_member_index,
            "locator": self.locator,
            "name_sha256": self.name_sha256,
            "content_sha256": self.content_sha256,
            "compressed_bytes": self.compressed_bytes,
            "byte_length": self.byte_length,
            "compression_method": self.compression_method,
            "media_type": self.media_type,
            "classification_status": "unclassified_archive_member",
            "link_status": "unlinked",
            "extraction_status": "not_extracted",
            "diagnostic_code": "archive_member_requires_adapter_classification",
        }


@dataclass(frozen=True)
class ArchiveInspection:
    archive_size: int
    archive_sha256: str
    selected_member_index: int
    selected_member_size: int
    selected_member_sha256: str
    member_count: int
    regular_member_count: int
    total_uncompressed_bytes: int
    largest_member_uncompressed_bytes: int
    attachment_bytes: int
    compression_methods: tuple[int, ...]
    max_compression_ratio_milli: int
    supplemental_members: tuple[SupplementalMemberInspection, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "member_count": self.member_count,
            "regular_member_count": self.regular_member_count,
            "total_uncompressed_bytes": self.total_uncompressed_bytes,
            "largest_member_uncompressed_bytes": self.largest_member_uncompressed_bytes,
            "attachment_bytes": self.attachment_bytes,
            "compression_methods": list(self.compression_methods),
            "max_compression_ratio_milli": self.max_compression_ratio_milli,
            "crc_verified": True,
            "supplemental_members": [item.as_dict() for item in self.supplemental_members],
        }


class ResourceBudget:
    def __init__(self, limits: WebExportLimits) -> None:
        validate_limits(limits)
        self.limits = limits
        self._started_at = _elapsed_seconds()
        self._cpu_started_at = _cpu_seconds()
        self._rss_started_at = _peak_rss_bytes()
        self._rss_peak_growth = 0
        self._logical_memory_peak = 0
        self._disk_bytes = 0

    def checkpoint(self, *, logical_memory_bytes: int = 0) -> None:
        if logical_memory_bytes < 0:
            raise ValueError("logical memory usage must be non-negative")
        self._logical_memory_peak = max(self._logical_memory_peak, logical_memory_bytes)
        if _cpu_seconds() - self._cpu_started_at > self.limits.max_cpu_seconds:
            raise WebExportLimitError("cpu_time", "web export CPU budget exceeded")
        if _elapsed_seconds() - self._started_at > self.limits.max_elapsed_seconds:
            raise WebExportLimitError("elapsed_time", "web export elapsed-time budget exceeded")
        rss_growth = max(0, _peak_rss_bytes() - self._rss_started_at)
        self._rss_peak_growth = max(self._rss_peak_growth, rss_growth)
        if max(rss_growth, self._logical_memory_peak) > self.limits.max_memory_bytes:
            raise WebExportLimitError("memory_bytes", "web export memory budget exceeded")

    def add_disk_bytes(self, byte_count: int) -> None:
        if byte_count < 0:
            raise ValueError("disk usage must be non-negative")
        self._disk_bytes += byte_count
        if self._disk_bytes > self.limits.max_temp_disk_bytes:
            raise WebExportLimitError("temp_disk_bytes", "web export disk budget exceeded")
        self.checkpoint()

    def conversation_memory_bytes(self, raw_bytes: int, span_count: int) -> int:
        return (
            raw_bytes * _JSON_MEMORY_MULTIPLIER
            + span_count * _SPAN_MEMORY_BYTES
            + span_count * _MANIFEST_ENTRY_MEMORY_BYTES
        )

    def conversation_span_limit(self) -> int:
        per_span = _SPAN_MEMORY_BYTES + _MANIFEST_ENTRY_MEMORY_BYTES
        return max(1, self.limits.max_memory_bytes // (2 * per_span))

    def attachment_plan_memory_bytes(
        self,
        *,
        reference_utf8_bytes: int,
        reference_count: int,
        member_count: int,
    ) -> int:
        if min(reference_utf8_bytes, reference_count, member_count) < 0:
            raise ValueError("attachment plan memory inputs must be non-negative")
        return (
            reference_utf8_bytes
            + reference_count * _ATTACHMENT_REFERENCE_MEMORY_BYTES
            + member_count * _ATTACHMENT_PLAN_MEMBER_MEMORY_BYTES
        )

    def usage(self) -> dict[str, int]:
        self.checkpoint()
        return {
            "cpu_milliseconds": max(
                0,
                int((_cpu_seconds() - self._cpu_started_at) * 1000),
            ),
            "elapsed_milliseconds": max(
                0,
                int((_elapsed_seconds() - self._started_at) * 1000),
            ),
            "memory_budget_high_water_bytes": max(
                self._logical_memory_peak,
                self._rss_peak_growth,
            ),
            "logical_memory_peak_bytes": self._logical_memory_peak,
            "rss_peak_growth_bytes": self._rss_peak_growth,
            "disk_bytes": self._disk_bytes,
        }


def validate_limits(limits: WebExportLimits) -> None:
    for field_name, value in limits.__dict__.items():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"web export limit must be a positive integer: {field_name}")
        policy_value = cast(int, getattr(DEFAULT_WEB_EXPORT_LIMITS, field_name))
        if value > policy_value:
            raise ValueError(f"web export limit exceeds the built-in policy: {field_name}")


def limits_from_dict(value: object) -> WebExportLimits:
    if not isinstance(value, dict):
        raise ValueError("web export resource limits must be an object")
    loaded = cast(dict[str, object], value)
    expected = set(DEFAULT_WEB_EXPORT_LIMITS.__dict__) | {"supported_compression_methods"}
    if set(loaded) != expected:
        raise ValueError("web export resource limit keys are invalid")
    methods = loaded["supported_compression_methods"]
    if methods != sorted(_SUPPORTED_COMPRESSION_METHODS):
        raise ValueError("web export compression-method policy changed")
    numeric: dict[str, int] = {}
    for field_name in DEFAULT_WEB_EXPORT_LIMITS.__dict__:
        item = loaded[field_name]
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(f"web export resource limit is invalid: {field_name}")
        numeric[field_name] = item
    limits = WebExportLimits(**numeric)
    validate_limits(limits)
    return limits


def inspect_zip_archive(
    path: Path,
    selected_member_name: str,
    *,
    limits: WebExportLimits,
    budget: ResourceBudget,
    additional_conversation_member_names: frozenset[str] = frozenset(),
    additional_conversation_member_indices: frozenset[int] = frozenset(),
) -> ArchiveInspection:
    validate_limits(limits)
    _validate_member_name(selected_member_name)
    archive_digest = hashlib.sha256()
    selected_digest = hashlib.sha256()
    selected_size = 0
    supplemental_members: list[SupplementalMemberInspection] = []
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("web export archive must be a regular file")
        if before.st_size > limits.max_archive_bytes:
            raise WebExportLimitError(
                "archive_compressed_bytes",
                "web export archive compressed-byte budget exceeded",
            )
        expected_members, central_directory_bytes = _preflight_zip_directory(
            handle,
            archive_size=before.st_size,
            limits=limits,
            budget=budget,
        )
        handle.seek(0)
        archive_size = 0
        while chunk := handle.read(min(COPY_CHUNK_BYTES, before.st_size - archive_size + 1)):
            archive_size += len(chunk)
            if archive_size > before.st_size:
                raise RuntimeError("web export archive exceeded its inspected byte length")
            archive_digest.update(chunk)
            budget.checkpoint(logical_memory_bytes=central_directory_bytes + len(chunk))
        if archive_size != before.st_size:
            raise RuntimeError("web export archive changed while hashing")
        handle.seek(0)
        try:
            archive = zipfile.ZipFile(handle)
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise ValueError("web export archive format is invalid") from exc
        with archive:
            infos = archive.infolist()
            if len(infos) != expected_members:
                raise ValueError("web export archive member count changed during inspection")
            budget.checkpoint(
                logical_memory_bytes=(central_directory_bytes + len(infos) * _ZIP_INFO_MEMORY_BYTES)
            )
            _validate_archive_metadata(
                infos,
                selected_member_name,
                limits,
                additional_conversation_member_names=additional_conversation_member_names,
                additional_conversation_member_indices=additional_conversation_member_indices,
            )
            regular_infos = [item for item in infos if not item.is_dir()]
            selected_matches = [
                item for item in regular_infos if item.filename == selected_member_name
            ]
            if len(selected_matches) != 1:
                raise ValueError("archive must contain exactly one regular selected member")
            selected_member_index = infos.index(selected_matches[0])
            archive_sha256 = archive_digest.hexdigest()
            for index, item in enumerate(infos):
                item_size = 0
                item_digest = hashlib.sha256()
                item_header = bytearray()
                try:
                    with archive.open(item, "r") as member_handle:
                        while chunk := member_handle.read(
                            min(COPY_CHUNK_BYTES, item.file_size - item_size + 1)
                        ):
                            item_size += len(chunk)
                            if item_size > item.file_size:
                                raise WebExportLimitError(
                                    "archive_member_uncompressed_bytes",
                                    "web export member exceeded its declared byte length",
                                )
                            item_digest.update(chunk)
                            if len(item_header) < 512:
                                item_header.extend(chunk[: 512 - len(item_header)])
                            if item.filename == selected_member_name:
                                selected_digest.update(chunk)
                                selected_size += len(chunk)
                            budget.checkpoint(
                                logical_memory_bytes=(
                                    central_directory_bytes
                                    + len(chunk)
                                    + len(supplemental_members)
                                    * _SUPPLEMENTAL_MEMBER_MANIFEST_MEMORY_BYTES
                                )
                            )
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    raise WebExportLimitError(
                        "archive_crc",
                        "web export archive CRC verification failed",
                    ) from exc
                if item_size != item.file_size:
                    raise WebExportLimitError(
                        "archive_crc",
                        "web export archive member length verification failed",
                    )
                if not item.is_dir() and item.filename != selected_member_name:
                    name_sha256 = hashlib.sha256(item.filename.encode()).hexdigest()
                    supplemental_members.append(
                        SupplementalMemberInspection(
                            archive_member_index=index,
                            member_name=item.filename,
                            locator=(
                                f"zip+sha256:{archive_sha256}/member-name-sha256:{name_sha256}"
                            ),
                            name_sha256=name_sha256,
                            content_sha256=item_digest.hexdigest(),
                            compressed_bytes=item.compress_size,
                            byte_length=item.file_size,
                            compression_method=item.compress_type,
                            media_type=_attachment_media_type(item.filename, bytes(item_header)),
                        )
                    )
                    budget.checkpoint(
                        logical_memory_bytes=(
                            central_directory_bytes
                            + len(supplemental_members) * _SUPPLEMENTAL_MEMBER_MANIFEST_MEMORY_BYTES
                        )
                    )
        after = os.fstat(handle.fileno())
    if _stat_identity(before) != _stat_identity(after):
        raise RuntimeError("web export archive changed while inspecting")

    regular_infos = [item for item in infos if not item.is_dir()]
    total_uncompressed = sum(item.file_size for item in regular_infos)
    largest_member = max((item.file_size for item in regular_infos), default=0)
    attachment_bytes = sum(
        item.file_size
        for index, item in enumerate(infos)
        if not item.is_dir()
        and item.filename != selected_member_name
        and item.filename not in additional_conversation_member_names
        and index not in additional_conversation_member_indices
    )
    compression_methods = tuple(sorted({item.compress_type for item in regular_infos}))
    max_ratio_milli = max((_ratio_milli(item) for item in regular_infos), default=0)
    return ArchiveInspection(
        archive_size=archive_size,
        archive_sha256=archive_digest.hexdigest(),
        selected_member_index=selected_member_index,
        selected_member_size=selected_size,
        selected_member_sha256=selected_digest.hexdigest(),
        member_count=len(infos),
        regular_member_count=len(regular_infos),
        total_uncompressed_bytes=total_uncompressed,
        largest_member_uncompressed_bytes=largest_member,
        attachment_bytes=attachment_bytes,
        compression_methods=compression_methods,
        max_compression_ratio_milli=max_ratio_milli,
        supplemental_members=tuple(supplemental_members),
    )


def validate_json_limits(
    data: bytes | memoryview,
    *,
    max_depth: int,
    max_string_bytes: int,
    budget: ResourceBudget | None = None,
) -> None:
    if max_depth <= 0 or max_string_bytes <= 0:
        raise ValueError("JSON limits must be positive")
    depth = 0
    position = 0
    while position < len(data):
        if budget is not None and position % COPY_CHUNK_BYTES == 0:
            budget.checkpoint(logical_memory_bytes=min(len(data), COPY_CHUNK_BYTES))
        token = data[position]
        if token == ord('"'):
            position += 1
            string_bytes = 0
            next_checkpoint = COPY_CHUNK_BYTES
            while position < len(data):
                token = data[position]
                if token == ord('"'):
                    break
                if token == ord("\\"):
                    if position + 1 >= len(data):
                        raise ValueError("JSON string escape is incomplete")
                    position += 2
                    string_bytes += 2
                else:
                    position += 1
                    string_bytes += 1
                if string_bytes > max_string_bytes:
                    raise WebExportLimitError(
                        "json_string_bytes",
                        "web export JSON string-byte budget exceeded",
                    )
                if budget is not None and string_bytes >= next_checkpoint:
                    budget.checkpoint(logical_memory_bytes=min(len(data), COPY_CHUNK_BYTES))
                    next_checkpoint += COPY_CHUNK_BYTES
            if position >= len(data):
                raise ValueError("JSON string is unterminated")
        elif token in (ord("["), ord("{")):
            depth += 1
            if depth > max_depth:
                raise WebExportLimitError(
                    "json_depth",
                    "web export JSON nesting budget exceeded",
                )
        elif token in (ord("]"), ord("}")):
            depth -= 1
            if depth < 0:
                raise ValueError("JSON structure closes before it opens")
        position += 1
    if depth != 0:
        raise ValueError("JSON structure is incomplete")


def enforce_record_count(record_count: int, limits: WebExportLimits) -> None:
    if record_count > limits.max_record_count:
        raise WebExportLimitError(
            "record_count",
            "web export record-count budget exceeded",
        )


def _preflight_zip_directory(
    handle: BinaryIO,
    *,
    archive_size: int,
    limits: WebExportLimits,
    budget: ResourceBudget,
) -> tuple[int, int]:
    if archive_size < 22:
        raise ValueError("web export archive is too short")
    tail_size = min(archive_size, _MAX_EOCD_SEARCH_BYTES)
    budget.checkpoint(logical_memory_bytes=tail_size)
    handle.seek(archive_size - tail_size)
    tail = handle.read(tail_size)
    marker = tail.rfind(_EOCD_SIGNATURE)
    if marker < 0 or marker + 22 > len(tail):
        raise ValueError("web export archive end record is missing")
    absolute_marker = archive_size - tail_size + marker
    (
        signature,
        disk_number,
        central_disk,
        entries_on_disk,
        total_entries,
        central_size,
        central_offset,
        comment_length,
    ) = struct.unpack_from("<4sHHHHIIH", tail, marker)
    if signature != _EOCD_SIGNATURE or absolute_marker + 22 + comment_length != archive_size:
        raise ValueError("web export archive end record is invalid")
    if disk_number != 0 or central_disk != 0 or entries_on_disk != total_entries:
        raise ValueError("multi-disk web export archives are unsupported")

    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        locator_offset = absolute_marker - 20
        if locator_offset < 0:
            raise ValueError("web export ZIP64 locator is missing")
        handle.seek(locator_offset)
        locator = handle.read(20)
        if len(locator) != 20:
            raise ValueError("web export ZIP64 locator is incomplete")
        locator_signature, zip64_disk, zip64_offset, total_disks = struct.unpack("<4sIQI", locator)
        if locator_signature != _ZIP64_LOCATOR_SIGNATURE or zip64_disk != 0 or total_disks != 1:
            raise ValueError("web export ZIP64 locator is invalid")
        handle.seek(zip64_offset)
        fixed = handle.read(56)
        if len(fixed) != 56:
            raise ValueError("web export ZIP64 end record is incomplete")
        (
            zip64_signature,
            zip64_size,
            _made_by,
            _needed,
            zip64_disk_number,
            zip64_central_disk,
            zip64_entries_on_disk,
            zip64_total_entries,
            zip64_central_size,
            zip64_central_offset,
        ) = struct.unpack("<4sQHHIIQQQQ", fixed)
        if (
            zip64_signature != _ZIP64_EOCD_SIGNATURE
            or zip64_size < 44
            or zip64_offset + 12 + zip64_size != locator_offset
            or zip64_disk_number != 0
            or zip64_central_disk != 0
            or zip64_entries_on_disk != zip64_total_entries
        ):
            raise ValueError("web export ZIP64 end record is invalid")
        total_entries = zip64_total_entries
        central_size = zip64_central_size
        central_offset = zip64_central_offset

    if total_entries > limits.max_member_count:
        raise WebExportLimitError(
            "archive_member_count",
            "web export archive member-count budget exceeded",
        )
    if central_size > limits.max_memory_bytes:
        raise WebExportLimitError(
            "memory_bytes",
            "web export central directory exceeds the memory budget",
        )
    zip_metadata_memory = central_size + total_entries * _ZIP_INFO_MEMORY_BYTES
    if zip_metadata_memory > limits.max_memory_bytes:
        raise WebExportLimitError(
            "memory_bytes",
            "web export ZIP metadata exceeds the memory budget",
        )
    if central_offset + central_size > absolute_marker:
        raise ValueError("web export central directory bounds are invalid")
    actual_entries = _scan_central_directory(
        handle,
        offset=central_offset,
        byte_length=central_size,
        expected_entries=total_entries,
        limits=limits,
        budget=budget,
    )
    budget.checkpoint(logical_memory_bytes=zip_metadata_memory)
    return actual_entries, central_size


def _scan_central_directory(
    handle: BinaryIO,
    *,
    offset: int,
    byte_length: int,
    expected_entries: int,
    limits: WebExportLimits,
    budget: ResourceBudget,
) -> int:
    handle.seek(offset)
    consumed = 0
    entry_count = 0
    while consumed < byte_length:
        fixed = handle.read(46)
        if len(fixed) != 46 or fixed[:4] != b"PK\x01\x02":
            raise ValueError("web export central directory entry is invalid")
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", fixed, 28)
        variable_length = name_length + extra_length + comment_length
        consumed += 46 + variable_length
        if consumed > byte_length:
            raise ValueError("web export central directory entry exceeds its bounds")
        handle.seek(variable_length, os.SEEK_CUR)
        entry_count += 1
        if entry_count > limits.max_member_count:
            raise WebExportLimitError(
                "archive_member_count",
                "web export archive member-count budget exceeded",
            )
        budget.checkpoint(logical_memory_bytes=min(byte_length, COPY_CHUNK_BYTES))
    if consumed != byte_length or entry_count != expected_entries:
        raise ValueError("web export central directory count is inconsistent")
    return entry_count


def _validate_archive_metadata(
    infos: list[zipfile.ZipInfo],
    selected_member_name: str,
    limits: WebExportLimits,
    *,
    additional_conversation_member_names: frozenset[str],
    additional_conversation_member_indices: frozenset[int],
) -> None:
    names = [item.filename for item in infos]
    if len(set(names)) != len(names):
        raise WebExportLimitError(
            "archive_duplicate_name",
            "web export archive contains duplicate member names",
        )
    regular_infos: list[zipfile.ZipInfo] = []
    for item in infos:
        _validate_member_name(item.filename)
        mode = item.external_attr >> 16
        if item.flag_bits & 0x1:
            raise WebExportLimitError(
                "archive_encrypted_member",
                "web export archive contains an encrypted member",
            )
        if item.compress_type not in _SUPPORTED_COMPRESSION_METHODS:
            raise WebExportLimitError(
                "archive_compression_method",
                "web export archive uses an unsupported compression method",
            )
        if item.is_dir():
            if item.file_size != 0:
                raise ValueError("web export archive directory has a non-zero size")
            continue
        if stat.S_IFMT(mode) and not stat.S_ISREG(mode):
            raise ValueError("web export archive contains a non-regular member")
        if item.file_size > limits.max_member_uncompressed_bytes:
            raise WebExportLimitError(
                "archive_member_uncompressed_bytes",
                "web export member uncompressed-byte budget exceeded",
            )
        if item.file_size > limits.max_compression_ratio * max(item.compress_size, 1):
            raise WebExportLimitError(
                "archive_compression_ratio",
                "web export archive compression-ratio budget exceeded",
            )
        regular_infos.append(item)

    total_uncompressed = sum(item.file_size for item in regular_infos)
    if total_uncompressed > limits.max_total_uncompressed_bytes:
        raise WebExportLimitError(
            "archive_total_uncompressed_bytes",
            "web export archive total uncompressed-byte budget exceeded",
        )
    regular_names = {item.filename for item in regular_infos}
    if selected_member_name in additional_conversation_member_names:
        raise ValueError("selected member cannot also be an additional conversation member")
    if not additional_conversation_member_names.issubset(regular_names):
        raise ValueError("additional conversation member is absent from the archive")
    if any(
        index < 0 or index >= len(infos) or infos[index].is_dir()
        for index in additional_conversation_member_indices
    ):
        raise ValueError("additional conversation member index is invalid")
    selected_index = next(
        (index for index, item in enumerate(infos) if item.filename == selected_member_name),
        None,
    )
    if selected_index in additional_conversation_member_indices:
        raise ValueError("selected member cannot also be an additional conversation member")
    attachment_bytes = sum(
        item.file_size
        for index, item in enumerate(infos)
        if not item.is_dir()
        and item.filename != selected_member_name
        and item.filename not in additional_conversation_member_names
        and index not in additional_conversation_member_indices
    )
    if attachment_bytes > limits.max_attachment_bytes:
        raise WebExportLimitError(
            "attachment_bytes",
            "web export attachment-byte budget exceeded",
        )


def _validate_member_name(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ValueError("web export archive contains an unsafe member path")


def _ratio_milli(item: zipfile.ZipInfo) -> int:
    if item.file_size == 0:
        return 0
    return (item.file_size * 1000 + max(item.compress_size, 1) - 1) // max(
        item.compress_size,
        1,
    )


def _attachment_media_type(filename: str, header: bytes) -> str:
    suffix = PurePosixPath(filename).suffix.lower()
    suffix_type = _ATTACHMENT_MEDIA_TYPES.get(suffix)
    if suffix_type is not None:
        return suffix_type
    stripped = header.lstrip()
    if header.startswith(b"%PDF-"):
        return "application/pdf"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "image/webp"
    if len(header) >= 12 and header[4:8] == b"ftyp":
        return "video/mp4"
    if header.startswith(b"PK\x03\x04"):
        return "application/zip"
    if stripped[:1] in {b"{", b"["}:
        return "application/json"
    try:
        decoded = header.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    if decoded:
        printable = sum(character.isprintable() or character.isspace() for character in decoded)
        if printable / len(decoded) >= 0.9:
            return "text/plain"
    return "application/octet-stream"


def _peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def _cpu_seconds() -> float:
    return time.process_time()


def _elapsed_seconds() -> float:
    return time.monotonic()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
