from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, cast

from cross_assistant_memory.models import ParseResult, SourceKind, SourceSystem
from cross_assistant_memory.parsers.chatgpt_web import (
    PARSER_NAME as CHATGPT_WEB_PARSER_NAME,
)
from cross_assistant_memory.parsers.chatgpt_web import (
    PARSER_VERSION as CHATGPT_WEB_PARSER_VERSION,
)
from cross_assistant_memory.parsers.chatgpt_web import parse_chatgpt_web_records
from cross_assistant_memory.parsers.claude_code import (
    PARSER_NAME as CLAUDE_PARSER_NAME,
)
from cross_assistant_memory.parsers.claude_code import (
    PARSER_VERSION as CLAUDE_PARSER_VERSION,
)
from cross_assistant_memory.parsers.claude_code import (
    inspect_claude_code_metadata,
    inspect_claude_code_metadata_records,
    parse_claude_code_records,
)
from cross_assistant_memory.parsers.claude_web import PARSER_NAME as CLAUDE_WEB_PARSER_NAME
from cross_assistant_memory.parsers.claude_web import PARSER_VERSION as CLAUDE_WEB_PARSER_VERSION
from cross_assistant_memory.parsers.claude_web import parse_claude_web_records
from cross_assistant_memory.parsers.codex import (
    LEGACY_PARSER_NAME,
    LEGACY_PARSER_VERSION,
    CodexMetadata,
    inspect_codex_metadata,
    parse_codex_records,
)
from cross_assistant_memory.parsers.codex import PARSER_NAME as CODEX_PARSER_NAME
from cross_assistant_memory.parsers.codex import PARSER_VERSION as CODEX_PARSER_VERSION
from cross_assistant_memory.parsers.common import (
    json_schema_descriptors,
    native_jsonl_schema_fingerprint,
    schema_fingerprint_from_descriptors,
)
from cross_assistant_memory.parsers.grok_build import PARSER_NAME as GROK_BUILD_PARSER_NAME
from cross_assistant_memory.parsers.grok_build import (
    PARSER_VERSION as GROK_BUILD_PARSER_VERSION,
)
from cross_assistant_memory.parsers.grok_build import (
    inspect_grok_build_conversation_id,
    parse_grok_build_records,
)
from cross_assistant_memory.parsers.grok_web import PARSER_NAME as GROK_WEB_PARSER_NAME
from cross_assistant_memory.parsers.grok_web import PARSER_VERSION as GROK_WEB_PARSER_VERSION
from cross_assistant_memory.parsers.grok_web import parse_grok_web_records
from cross_assistant_memory.safe_files import open_regular_file_no_symlinks, secure_path_stat

if TYPE_CHECKING:
    from _hashlib import HASH

DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_METADATA_RECORD_BYTES = 1024 * 1024
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
NATIVE_SOURCE_SYSTEMS = frozenset(
    {SourceSystem.CODEX, SourceSystem.CLAUDE_CODE, SourceSystem.GROK_BUILD}
)


@dataclass(frozen=True)
class NativeFilePrefix:
    size: int
    sha256: str
    mtime_ns: int
    device: int
    inode: int

    def __post_init__(self) -> None:
        if type(self.sha256) is not str:
            raise ValueError("retained source prefix digest must be a string")
        _validate_digest(self.sha256, "retained source prefix digest")
        if any(
            type(value) is not int or value < 0
            for value in (
                self.size,
                self.mtime_ns,
                self.device,
                self.inode,
            )
        ):
            raise ValueError("retained source prefix metadata is invalid")


def parse_file(
    path: Path,
    source_system: SourceSystem,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    resource_checkpoint: Callable[[], None] | None = None,
    retained_prefix: NativeFilePrefix | None = None,
    segment_start: tuple[int, int, str] = (0, 0, EMPTY_SHA256),
) -> ParseResult:
    if retained_prefix is not None and source_system not in NATIVE_SOURCE_SYSTEMS:
        raise ValueError("retained prefixes apply only to native source files")
    path = Path(os.path.abspath(path.expanduser()))
    descriptor = _open_regular_file(path)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        size = before.st_size if retained_prefix is None else retained_prefix.size
        if retained_prefix is not None and (
            (before.st_dev, before.st_ino) != (retained_prefix.device, retained_prefix.inode)
            or before.st_size < size
        ):
            raise RuntimeError("retained source identity changed or source was truncated")
        if size > max_file_bytes:
            raise ValueError(
                f"source is {size} bytes, above the {max_file_bytes}-byte ingestion cap"
            )
        data = handle.read(max_file_bytes + 1 if retained_prefix is None else size)
        after = os.fstat(handle.fileno())
    if len(data) > max_file_bytes:
        raise ValueError(f"source exceeded the {max_file_bytes}-byte ingestion cap while reading")
    digest = hashlib.sha256(data).hexdigest()
    if retained_prefix is None:
        _verify_stable_file(path, before, after, expected_size=len(data))
    else:
        _verify_append_only_file(path, before, after, consumed_end=size)
        if len(data) != size or digest != retained_prefix.sha256:
            raise RuntimeError("retained source prefix bytes changed")
    if source_system in {SourceSystem.CODEX, SourceSystem.CLAUDE_CODE, SourceSystem.GROK_BUILD}:
        schema_fingerprint = native_jsonl_schema_fingerprint(data)
        schema_descriptors: tuple[str, ...] = ()
    else:
        schema_descriptors = json_schema_descriptors(
            data,
            dynamic_map_paths=(
                frozenset({("mapping",)})
                if source_system is SourceSystem.CHATGPT_WEB
                else frozenset()
            ),
            checkpoint=resource_checkpoint,
        )
        schema_fingerprint = schema_fingerprint_from_descriptors(schema_descriptors)

    if source_system is SourceSystem.CODEX:
        metadata, records, unknown_types, malformed = parse_codex_records(data, path)
        if (
            metadata.copied_history_start_ordinal is not None
            and data.count(b"\n") < metadata.copied_history_start_ordinal
        ):
            raise ValueError("copied Codex history has an incomplete inherited prefix")
        parser_name = LEGACY_PARSER_NAME if metadata.legacy_format else CODEX_PARSER_NAME
        parser_version = LEGACY_PARSER_VERSION if metadata.legacy_format else CODEX_PARSER_VERSION
        history_base = metadata.history_base
        source_kind = metadata.source_kind
        source_label = metadata.source_label
        parent_conversation_id = metadata.parent_conversation_id
        conversation_id = metadata.conversation_id
        branch_id = metadata.branch_id
        captured_at = metadata.captured_at
    elif source_system is SourceSystem.CLAUDE_CODE:
        metadata = inspect_claude_code_metadata(data, path)
        (
            conversation_id,
            branch_id,
            captured_at,
            records,
            unknown_types,
            malformed,
        ) = parse_claude_code_records(data, path, metadata=metadata)
        history_base = None
        parser_name = CLAUDE_PARSER_NAME
        parser_version = CLAUDE_PARSER_VERSION
        source_kind = metadata.source_kind
        source_label = metadata.source_label
        parent_conversation_id = metadata.parent_conversation_id
    elif source_system is SourceSystem.GROK_BUILD:
        (
            conversation_id,
            branch_id,
            captured_at,
            records,
            unknown_types,
            malformed,
        ) = parse_grok_build_records(data, path)
        history_base = None
        parser_name = GROK_BUILD_PARSER_NAME
        parser_version = GROK_BUILD_PARSER_VERSION
        source_kind = SourceKind.INTERACTIVE
        source_label = "grok_build"
        parent_conversation_id = None
    elif source_system in {
        SourceSystem.CHATGPT_WEB,
        SourceSystem.CLAUDE_WEB,
        SourceSystem.GROK_WEB,
    }:
        if source_system is SourceSystem.CHATGPT_WEB:
            parser = parse_chatgpt_web_records
            parser_name = CHATGPT_WEB_PARSER_NAME
            parser_version = CHATGPT_WEB_PARSER_VERSION
            source_label = "chatgpt_web_export"
        elif source_system is SourceSystem.CLAUDE_WEB:
            parser = parse_claude_web_records
            parser_name = CLAUDE_WEB_PARSER_NAME
            parser_version = CLAUDE_WEB_PARSER_VERSION
            source_label = "claude_web_export"
        else:
            parser = parse_grok_web_records
            parser_name = GROK_WEB_PARSER_NAME
            parser_version = GROK_WEB_PARSER_VERSION
            source_label = "grok_web_export"
        (
            conversation_id,
            branch_id,
            captured_at,
            records,
            unknown_types,
            malformed,
        ) = parser(data, path)
        history_base = None
        source_kind = SourceKind.INTERACTIVE
        parent_conversation_id = None
    else:  # pragma: no cover - exhaustive enum guard
        raise ValueError(f"unsupported source system: {source_system}")

    start_byte, start_ordinal, start_digest = segment_start
    if segment_start != (0, 0, EMPTY_SHA256):
        if source_system not in NATIVE_SOURCE_SYSTEMS:
            raise ValueError("file segment cursors apply only to native sources")
        if (
            type(start_byte) is not int
            or type(start_ordinal) is not int
            or not 0 <= start_byte <= len(data)
            or start_ordinal < 0
            or (start_byte > 0 and data[start_byte - 1 : start_byte] != b"\n")
            or data[:start_byte].count(b"\n") != start_ordinal
            or hashlib.sha256(data[:start_byte]).hexdigest() != start_digest
        ):
            raise RuntimeError("native source does not match its registered cursor")
        records = tuple(record for record in records if record.record_ordinal >= start_ordinal)

    return ParseResult(
        source_system=source_system,
        parser_name=parser_name,
        parser_version=parser_version,
        path=path,
        file_digest=digest,
        file_size=size,
        file_mtime_ns=before.st_mtime_ns if retained_prefix is None else retained_prefix.mtime_ns,
        conversation_id=conversation_id,
        branch_id=branch_id,
        captured_at=captured_at,
        history_base=history_base,
        records=records,
        unknown_record_types=unknown_types,
        malformed_records=malformed,
        source_kind=source_kind,
        source_label=source_label,
        parent_conversation_id=parent_conversation_id,
        segment_start_ordinal=start_ordinal,
        segment_start_byte=start_byte,
        segment_end_ordinal_exclusive=(
            max((record.record_ordinal for record in records), default=-1) + 1
            if source_system
            in {SourceSystem.CHATGPT_WEB, SourceSystem.CLAUDE_WEB, SourceSystem.GROK_WEB}
            else len(data.splitlines())
        ),
        segment_end_byte=len(data),
        start_prefix_digest=start_digest,
        end_prefix_digest=digest,
        observed_file_size=size,
        schema_fingerprint=schema_fingerprint,
        schema_descriptors=schema_descriptors,
    )


def parse_incremental_file(
    path: Path,
    source_system: SourceSystem,
    *,
    start_ordinal: int = 0,
    start_byte: int = 0,
    expected_prefix_digest: str | None = None,
    max_increment_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_source_bytes: int | None = None,
) -> ParseResult:
    if source_system not in NATIVE_SOURCE_SYSTEMS:
        raise ValueError("incremental parsing supports native JSONL sources only")
    if start_ordinal < 0 or start_byte < 0:
        raise ValueError("incremental cursor values must be non-negative")
    if max_increment_bytes <= 0:
        raise ValueError("max_increment_bytes must be positive")
    if max_source_bytes is not None and max_source_bytes < 0:
        raise ValueError("max_source_bytes must be non-negative")
    if start_byte == 0:
        if start_ordinal != 0:
            raise ValueError("a zero byte cursor requires a zero record ordinal")
        expected_prefix_digest = expected_prefix_digest or EMPTY_SHA256
    elif expected_prefix_digest is None:
        raise ValueError("a non-zero cursor requires an expected prefix digest")
    _validate_digest(expected_prefix_digest, "expected prefix digest")

    expanded = Path(os.path.abspath(path.expanduser()))
    descriptor = _open_regular_file(expanded)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if max_source_bytes is not None and before.st_size > max_source_bytes:
            raise RuntimeError("source grew beyond the reserved incremental read budget")
        if start_byte > before.st_size:
            raise RuntimeError("source is shorter than the requested incremental cursor")
        codex_metadata = None
        claude_metadata = None
        grok_conversation_id = None
        if source_system is SourceSystem.CODEX:
            codex_metadata = _read_codex_metadata(handle, expanded)
            if (
                start_byte == 0
                and codex_metadata.has_inherited_history
                and codex_metadata.referenced_history_ordinal_base is None
                and codex_metadata.copied_history_start_ordinal is None
            ):
                raise ValueError("forked Codex sources require an explicit replay boundary")
        elif source_system is SourceSystem.CLAUDE_CODE:
            claude_metadata = inspect_claude_code_metadata_records(
                _iter_complete_metadata_records(
                    handle,
                    before.st_size,
                    max_record_bytes=DEFAULT_MAX_FILE_BYTES,
                    reject_oversized=True,
                ),
                expanded,
            )
        else:
            grok_conversation_id = inspect_grok_build_conversation_id(
                _iter_complete_metadata_records(handle, before.st_size),
                expanded,
            )
        _verify_line_boundary(handle, start_byte)
        prefix_hash, prefix_records = _hash_prefix(handle, start_byte)
        actual_start_digest = prefix_hash.hexdigest()
        if actual_start_digest != expected_prefix_digest:
            raise RuntimeError("source prefix digest does not match the incremental cursor")
        if prefix_records != start_ordinal:
            raise RuntimeError("source record ordinal does not match the incremental cursor")

        remaining = before.st_size - start_byte
        handle.seek(start_byte)
        data = handle.read(min(remaining, max_increment_bytes))
        complete_end = len(data)
        if not data.endswith(b"\n"):
            final_newline = data.rfind(b"\n")
            complete_end = final_newline + 1 if final_newline >= 0 else 0
        data = data[:complete_end]
        end_byte = start_byte + len(data)
        # Extend the validated prefix, then independently re-read the consumed bytes.
        prefix_hash.update(data)
        end_digest = prefix_hash.hexdigest()
        end_records = prefix_records + data.count(b"\n")
        handle.seek(start_byte)
        if handle.read(len(data)) != data:
            raise RuntimeError("source changed while the incremental segment was being read")
        verified_end_hash, verified_end_records = _hash_prefix(handle, end_byte)
        after = os.fstat(handle.fileno())

    if end_digest != verified_end_hash.hexdigest() or end_records != verified_end_records:
        raise RuntimeError("source changed while the incremental prefix was being verified")
    if end_records != start_ordinal + data.count(b"\n"):
        raise RuntimeError("incremental source record count changed while reading")
    _verify_append_only_file(expanded, before, after, consumed_end=end_byte)

    if source_system is SourceSystem.CODEX:
        assert codex_metadata is not None
        if (
            codex_metadata.copied_history_start_ordinal is not None
            and remaining <= max_increment_bytes
            and end_records < codex_metadata.copied_history_start_ordinal
        ):
            raise ValueError("copied Codex history has an incomplete inherited prefix")
        _validate_referenced_codex_segment(data, expanded, codex_metadata, start_ordinal)
        metadata, records, unknown_types, malformed = parse_codex_records(
            data,
            expanded,
            ordinal_base=start_ordinal,
            byte_base=start_byte,
            metadata=codex_metadata,
        )
        parser_name = LEGACY_PARSER_NAME if metadata.legacy_format else CODEX_PARSER_NAME
        parser_version = LEGACY_PARSER_VERSION if metadata.legacy_format else CODEX_PARSER_VERSION
        conversation_id = metadata.conversation_id
        branch_id = metadata.branch_id
        captured_at = metadata.captured_at
        history_base = metadata.history_base
        source_kind = metadata.source_kind
        source_label = metadata.source_label
        parent_conversation_id = metadata.parent_conversation_id
    elif source_system is SourceSystem.CLAUDE_CODE:
        assert claude_metadata is not None
        (
            conversation_id,
            branch_id,
            captured_at,
            records,
            unknown_types,
            malformed,
        ) = parse_claude_code_records(
            data,
            expanded,
            metadata=claude_metadata,
            ordinal_base=start_ordinal,
            byte_base=start_byte,
        )
        parser_name = CLAUDE_PARSER_NAME
        parser_version = CLAUDE_PARSER_VERSION
        history_base = None
        source_kind = claude_metadata.source_kind
        source_label = claude_metadata.source_label
        parent_conversation_id = claude_metadata.parent_conversation_id
    else:
        assert grok_conversation_id is not None
        (
            conversation_id,
            branch_id,
            captured_at,
            records,
            unknown_types,
            malformed,
        ) = parse_grok_build_records(
            data,
            expanded,
            ordinal_base=start_ordinal,
            byte_base=start_byte,
            expected_conversation_id=grok_conversation_id,
        )
        parser_name = GROK_BUILD_PARSER_NAME
        parser_version = GROK_BUILD_PARSER_VERSION
        history_base = None
        source_kind = SourceKind.INTERACTIVE
        source_label = "grok_build"
        parent_conversation_id = None
    return ParseResult(
        source_system=source_system,
        parser_name=parser_name,
        parser_version=parser_version,
        path=expanded,
        file_digest=end_digest,
        file_size=end_byte,
        file_mtime_ns=before.st_mtime_ns,
        conversation_id=conversation_id,
        branch_id=branch_id,
        captured_at=captured_at,
        history_base=history_base,
        records=records,
        unknown_record_types=unknown_types,
        malformed_records=malformed,
        source_kind=source_kind,
        source_label=source_label,
        parent_conversation_id=parent_conversation_id,
        segment_start_ordinal=start_ordinal,
        segment_start_byte=start_byte,
        segment_end_ordinal_exclusive=end_records,
        segment_end_byte=end_byte,
        start_prefix_digest=actual_start_digest,
        end_prefix_digest=end_digest,
        observed_file_size=before.st_size,
        schema_fingerprint=native_jsonl_schema_fingerprint(data),
    )


def _validate_referenced_codex_segment(
    data: bytes, path: Path, metadata: CodexMetadata, start_ordinal: int
) -> None:
    native_base = metadata.referenced_history_ordinal_base
    if native_base is None:
        return
    # Cursors and evidence locators stay physical; only the producer's ordinals include the base.
    for physical_ordinal, raw in enumerate(data.splitlines(keepends=True), start=start_ordinal):
        try:
            loaded: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ValueError("referenced Codex history contains an invalid child record") from None
        if not isinstance(loaded, dict):
            raise ValueError("referenced Codex history contains an invalid child record")
        item = cast(dict[str, Any], loaded)
        ordinal = item.get("ordinal")
        if (
            not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or ordinal != native_base + physical_ordinal
            or ordinal >= 2**64
        ):
            raise ValueError("referenced Codex history has an invalid child ordinal sequence")
        if physical_ordinal == 0:
            if item.get("type") != "session_meta" or inspect_codex_metadata(raw, path) != metadata:
                raise ValueError("referenced Codex history changed its initial metadata")
        elif item.get("type") == "session_meta":
            raise ValueError("referenced Codex history contains copied session metadata")


def _iter_complete_metadata_records(
    handle: BinaryIO,
    byte_limit: int,
    *,
    max_record_bytes: int = MAX_METADATA_RECORD_BYTES,
    reject_oversized: bool = False,
) -> Iterator[bytes]:
    handle.seek(0)
    remaining = byte_limit
    while remaining > 0:
        raw = handle.readline(min(max_record_bytes + 1, remaining))
        if not raw:
            return
        remaining -= len(raw)
        # Claude fork boundaries use physical ordinals; dropping a large row shifts them.
        if reject_oversized and len(raw) > max_record_bytes:
            raise ValueError("source metadata record exceeds the complete identity scan limit")
        if not raw.endswith(b"\n"):
            if len(raw) <= max_record_bytes:
                return
            while remaining > 0 and not raw.endswith(b"\n"):
                raw = handle.readline(min(max_record_bytes + 1, remaining))
                if not raw:
                    return
                remaining -= len(raw)
            continue
        if len(raw) <= max_record_bytes:
            yield raw


def _open_regular_file(path: Path) -> int:
    descriptor, _normalized = open_regular_file_no_symlinks(path, "source")
    return descriptor


def _read_codex_metadata(handle: BinaryIO, path: Path) -> CodexMetadata:
    handle.seek(0)
    first_record = handle.readline(MAX_METADATA_RECORD_BYTES + 1)
    if len(first_record) > MAX_METADATA_RECORD_BYTES or not first_record.endswith(b"\n"):
        raise ValueError("Codex source metadata record is missing or oversized")
    try:
        loaded: object = json.loads(first_record)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("Codex source does not begin with valid session metadata") from exc
    if not isinstance(loaded, dict):
        raise ValueError("Codex source does not begin with session metadata")
    item = cast(dict[str, Any], loaded)
    metadata = inspect_codex_metadata(first_record, path)
    if metadata.legacy_format:
        return metadata
    payload = item.get("payload")
    if item.get("type") != "session_meta" or not isinstance(payload, dict):
        raise ValueError("Codex source does not begin with session metadata")
    return metadata


def _verify_line_boundary(handle: BinaryIO, byte_offset: int) -> None:
    if byte_offset == 0:
        return
    handle.seek(byte_offset - 1)
    if handle.read(1) != b"\n":
        raise ValueError("incremental byte cursor must begin after a complete JSONL record")


def _hash_prefix(handle: BinaryIO, byte_length: int) -> tuple[HASH, int]:
    digest = hashlib.sha256()
    records = 0
    remaining = byte_length
    handle.seek(0)
    while remaining:
        chunk = handle.read(min(1024 * 1024, remaining))
        if not chunk:
            raise RuntimeError("source became shorter while hashing its prefix")
        digest.update(chunk)
        records += chunk.count(b"\n")
        remaining -= len(chunk)
    return digest, records


def _verify_stable_file(
    path: Path,
    before: os.stat_result,
    after: os.stat_result,
    *,
    expected_size: int,
) -> None:
    path_after = secure_path_stat(path, "source")
    if (
        _file_identity(before) != _file_identity(after)
        or _file_identity(before) != _file_identity(path_after)
        or expected_size != before.st_size
    ):
        raise RuntimeError("source changed while it was being read")


def _verify_append_only_file(
    path: Path,
    before: os.stat_result,
    after: os.stat_result,
    *,
    consumed_end: int,
) -> None:
    path_after = secure_path_stat(path, "source")
    expected_identity = (before.st_dev, before.st_ino)
    if (after.st_dev, after.st_ino) != expected_identity or (
        path_after.st_dev,
        path_after.st_ino,
    ) != expected_identity:
        raise RuntimeError("source identity changed while it was being read")
    if after.st_size < before.st_size or path_after.st_size < consumed_end:
        raise RuntimeError("source was truncated while it was being read")


def _validate_digest(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
