from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from cross_assistant_memory.admission import classify_record, is_admission_exclusion_reason
from cross_assistant_memory.models import (
    CollectorProvenance,
    ExclusionReceipt,
    HistoryBase,
    ParsedRecord,
    ParseResult,
    SourceKind,
    SourceSystem,
    UploadReceipt,
)
from cross_assistant_memory.parsers.claude_code import (
    AUTOMATION_ENTRYPOINTS as CLAUDE_AUTOMATION_ENTRYPOINTS,
)
from cross_assistant_memory.parsers.claude_code import (
    INTERACTIVE_ENTRYPOINTS as CLAUDE_INTERACTIVE_ENTRYPOINTS,
)
from cross_assistant_memory.parsers.claude_code import PARSER_NAME as CLAUDE_PARSER_NAME
from cross_assistant_memory.parsers.claude_code import PARSER_VERSION as CLAUDE_PARSER_VERSION
from cross_assistant_memory.parsers.claude_code import (
    ClaudeCodeMetadata,
    parse_claude_code_records,
)
from cross_assistant_memory.parsers.codex import (
    AUTOMATION_SOURCE_LABELS as CODEX_AUTOMATION_SOURCE_LABELS,
)
from cross_assistant_memory.parsers.codex import (
    INTERACTIVE_SOURCE_LABELS as CODEX_INTERACTIVE_SOURCE_LABELS,
)
from cross_assistant_memory.parsers.codex import (
    LEGACY_PARSER_NAME,
    LEGACY_PARSER_VERSION,
    CodexMetadata,
    parse_codex_records,
)
from cross_assistant_memory.parsers.codex import PARSER_NAME as CODEX_PARSER_NAME
from cross_assistant_memory.parsers.codex import PARSER_VERSION as CODEX_PARSER_VERSION
from cross_assistant_memory.parsers.grok_build import PARSER_NAME as GROK_BUILD_PARSER_NAME
from cross_assistant_memory.parsers.grok_build import PARSER_VERSION as GROK_BUILD_PARSER_VERSION
from cross_assistant_memory.parsers.grok_build import parse_grok_build_records
from cross_assistant_memory.publication_work import MAX_UPLOAD_PUBLICATION_OBJECTS
from cross_assistant_memory.storage import DEFAULT_MAX_RECORD_BYTES

UPLOAD_BATCH_FORMAT_VERSION = 2
MAX_UPLOAD_REQUEST_BYTES = 8 * 1024 * 1024
MAX_UPLOAD_DECODED_BYTES = 4 * 1024 * 1024
MAX_UPLOAD_RECORDS = 512
MAX_UPLOAD_EXCLUSIONS = 4096
MAX_UPLOAD_IDENTITY_BYTES = 1024
MAX_SQLITE_INTEGER = 2**63 - 1
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
BATCH_ID = re.compile(r"batch:[0-9a-f]{64}")
SUPPORTED_NATIVE_PARSERS = {
    SourceSystem.CODEX: (CODEX_PARSER_NAME, CODEX_PARSER_VERSION),
    SourceSystem.CLAUDE_CODE: (CLAUDE_PARSER_NAME, CLAUDE_PARSER_VERSION),
    SourceSystem.GROK_BUILD: (GROK_BUILD_PARSER_NAME, GROK_BUILD_PARSER_VERSION),
}
SUPPORTED_NATIVE_COLLECTORS = {
    SourceSystem.CODEX: (
        "codex",
        "native-jsonl-history",
        "cross-memory-native-collector",
        "0.1.0",
    ),
    SourceSystem.CLAUDE_CODE: (
        "claude-code",
        "native-jsonl-history",
        "cross-memory-native-collector",
        "0.1.0",
    ),
    SourceSystem.GROK_BUILD: (
        "grok-build",
        "native-jsonl-history",
        "cross-memory-native-collector",
        "0.1.0",
    ),
}


@dataclass(frozen=True)
class UploadBatch:
    batch_id: str
    request_digest: str
    source_account_id: str
    source_path_hash: str
    provenance: CollectorProvenance
    parsed: ParseResult
    exclusion_receipts: tuple[ExclusionReceipt, ...]


@dataclass(frozen=True)
class UploadPublicationPending:
    batch_id: str
    completed_objects: int

    @classmethod
    def from_dict(cls, value: dict[str, object], batch: UploadBatch) -> UploadPublicationPending:
        if (
            set(value) != {"status", "batch_id", "completed_objects"}
            or value["status"] != "publication_pending"
            or value["batch_id"] != batch.batch_id
        ):
            raise ValueError("publication progress does not match the submitted batch")
        completed = _required_nonnegative_int(value, "completed_objects")
        if not 1 <= completed <= MAX_UPLOAD_PUBLICATION_OBJECTS:
            raise ValueError("publication progress exceeds the request work limit")
        return cls(batch.batch_id, completed)


@dataclass(frozen=True)
class UploadCursorGap:
    batch_id: str
    next_record_ordinal: int
    next_byte_offset: int
    prefix_sha256: str

    @classmethod
    def from_dict(cls, value: dict[str, object], batch: UploadBatch) -> UploadCursorGap:
        if (
            set(value)
            != {"status", "batch_id", "next_record_ordinal", "next_byte_offset", "prefix_sha256"}
            or value["status"] != "cursor_gap"
            or value["batch_id"] != batch.batch_id
        ):
            raise ValueError("cursor gap response does not match the submitted batch")
        ordinal = _required_nonnegative_int(value, "next_record_ordinal")
        offset = _required_nonnegative_int(value, "next_byte_offset")
        digest = _required_digest(value, "prefix_sha256")
        if (
            ordinal >= batch.parsed.segment_start_ordinal
            or offset >= batch.parsed.segment_start_byte
        ):
            raise ValueError("cursor gap response does not precede the submitted batch")
        return cls(batch.batch_id, ordinal, offset, digest)


def accepted_native_parsers(source_system: SourceSystem) -> tuple[tuple[str, str], ...]:
    current = SUPPORTED_NATIVE_PARSERS[source_system]
    # Older envelopes retain their declared parser identity and interpretation.
    if source_system is SourceSystem.CODEX:
        return (
            current,
            (CODEX_PARSER_NAME, "0.2.2"),
            (CODEX_PARSER_NAME, "0.2.1"),
            (CODEX_PARSER_NAME, "0.2.0"),
            (LEGACY_PARSER_NAME, LEGACY_PARSER_VERSION),
        )
    if source_system is SourceSystem.CLAUDE_CODE:
        return (current, (CLAUDE_PARSER_NAME, "0.4.1"), (CLAUDE_PARSER_NAME, "0.4.0"))
    return (current,)


def expected_upload_source_file_id(batch: UploadBatch) -> str:
    synthetic_source_path = (
        f"/collector/{hashlib.sha256(batch.source_account_id.encode()).hexdigest()}/"
        f"{batch.source_path_hash}.jsonl"
    )
    path_hash = hashlib.sha256(synthetic_source_path.encode()).hexdigest()
    source_stream_id = _protocol_id(
        "source_stream",
        batch.parsed.source_system.value,
        batch.source_account_id,
        path_hash,
    )
    return _protocol_id(
        "source_segment",
        source_stream_id,
        str(batch.parsed.segment_start_ordinal),
        str(batch.parsed.segment_start_byte),
        str(batch.parsed.segment_end_ordinal_exclusive),
        str(batch.parsed.segment_end_byte),
        batch.parsed.end_prefix_digest,
        batch.parsed.parser_version,
    )


def validate_upload_receipt(
    batch: UploadBatch,
    receipt: UploadReceipt,
    *,
    status_code: int,
) -> None:
    expected_status = {200: "already_applied", 201: "applied"}.get(status_code)
    expected_reasons = dict(Counter(item.reason for item in batch.exclusion_receipts))
    suppressed = receipt.quarantine_reasons.get("no_memory_tombstone", 0)
    if suppressed:
        expected_reasons["no_memory_tombstone"] = suppressed
    if (
        expected_status is None
        or receipt.batch_id != batch.batch_id
        or receipt.status != expected_status
        or receipt.source_file_id != expected_upload_source_file_id(batch)
        or receipt.conversation_id != batch.parsed.conversation_id
        or receipt.event_count + suppressed != len(batch.parsed.records)
        or receipt.quarantined_records != len(batch.exclusion_receipts) + suppressed
        or receipt.quarantine_reasons != expected_reasons
    ):
        raise ValueError("upload receipt does not match its submitted batch")


def build_upload_batch(
    parsed: ParseResult,
    *,
    source_account_id: str,
    provenance: CollectorProvenance,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
) -> bytes:
    if parsed.source_system not in SUPPORTED_NATIVE_PARSERS:
        raise ValueError("batch upload currently supports native sources only")
    if (parsed.parser_name, parsed.parser_version) not in accepted_native_parsers(
        parsed.source_system
    ):
        raise ValueError("source parser does not match the pinned upload parser")
    if parsed.unknown_record_types or parsed.malformed_records:
        raise ValueError("unknown or malformed source records cannot be uploaded")
    normalized_provenance = _validate_collector_provenance(provenance, parsed.source_system)
    if normalized_provenance.schema_fingerprint != parsed.schema_fingerprint:
        raise ValueError("collector schema fingerprint does not match the parsed source")
    source_account = _bounded_string(source_account_id, "source_account_id")
    source_path_hash = hashlib.sha256(str(parsed.path).encode()).hexdigest()
    records: list[dict[str, object]] = []
    exclusions: list[dict[str, object]] = []
    for record in parsed.records:
        decision = classify_record(
            parsed.source_system,
            record.content_text,
            record.raw_record,
            max_record_bytes=max_record_bytes,
        )
        if decision.accepted:
            records.append(
                {
                    "record_ordinal": record.record_ordinal,
                    "byte_start": record.byte_start,
                    "byte_end": record.byte_end,
                    "raw_sha256": hashlib.sha256(record.raw_record).hexdigest(),
                    "raw_base64": base64.b64encode(record.raw_record).decode("ascii"),
                }
            )
        else:
            exclusions.append(
                {
                    "record_ordinal": record.record_ordinal,
                    "byte_start": record.byte_start,
                    "byte_end": record.byte_end,
                    "reason": decision.reason,
                }
            )
    core: dict[str, object] = {
        "format_version": UPLOAD_BATCH_FORMAT_VERSION,
        "source_account_id": source_account,
        "source_system": parsed.source_system.value,
        "source_path_hash": source_path_hash,
        "parser": {
            "name": parsed.parser_name,
            "version": parsed.parser_version,
        },
        "collector": {
            "source_client": normalized_provenance.source_client,
            "source_client_version": normalized_provenance.source_client_version,
            "capture_capability": normalized_provenance.capture_capability,
            "adapter_name": normalized_provenance.adapter_name,
            "adapter_version": normalized_provenance.adapter_version,
            "schema_fingerprint": normalized_provenance.schema_fingerprint,
        },
        "source": {
            "conversation_id": parsed.conversation_id,
            "branch_id": parsed.branch_id,
            "parent_conversation_id": parsed.parent_conversation_id,
            "source_label": parsed.source_label,
            "captured_at": parsed.captured_at,
            "history_base": _history_base_value(parsed.history_base),
            "observed_file_size": parsed.observed_file_size,
        },
        "segment": {
            "start_record_ordinal": parsed.segment_start_ordinal,
            "start_byte_offset": parsed.segment_start_byte,
            "end_record_ordinal": parsed.segment_end_ordinal_exclusive,
            "end_byte_offset": parsed.segment_end_byte,
            "start_prefix_sha256": parsed.start_prefix_digest,
            "end_prefix_sha256": parsed.end_prefix_digest,
            "file_mtime_ns": parsed.file_mtime_ns,
        },
        "records": records,
        "exclusions": exclusions,
    }
    digest = hashlib.sha256(_canonical_json(core)).hexdigest()
    encoded = _canonical_json({"batch_id": f"batch:{digest}", **core})
    parse_upload_batch(encoded, max_record_bytes=max_record_bytes)
    return encoded


def parse_upload_batch(
    body: bytes,
    *,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
) -> UploadBatch:
    return _parse_upload_batch(body, max_record_bytes=max_record_bytes)


def reclassify_upload_batch(body: bytes) -> bytes:
    """Build a maintenance replacement, never admit an old incompatible envelope.

    Verify the original schema, identities, raw hashes, parser and locators before replacing
    newly denied records with text-free receipts. The ordinary decoder stays strict.
    """
    denied: list[ExclusionReceipt] = []
    _parse_upload_batch(
        body, max_record_bytes=DEFAULT_MAX_RECORD_BYTES, reclassified_exclusions=denied
    )
    if not denied:
        return body
    root = cast(dict[str, object], json.loads(body))
    ordinals = {item.record_ordinal for item in denied}
    root["records"] = [
        item
        for item in cast(list[dict[str, object]], root["records"])
        if item["record_ordinal"] not in ordinals
    ]
    root["exclusions"] = sorted(
        [
            *cast(list[dict[str, object]], root["exclusions"]),
            *[
                {
                    "record_ordinal": item.record_ordinal,
                    "byte_start": item.byte_start,
                    "byte_end": item.byte_end,
                    "reason": item.reason,
                }
                for item in denied
            ],
        ],
        key=lambda item: cast(int, item["record_ordinal"]),
    )
    del root["batch_id"]
    root["batch_id"] = f"batch:{hashlib.sha256(_canonical_json(root)).hexdigest()}"
    encoded = _canonical_json(root)
    parse_upload_batch(encoded)
    return encoded


def _parse_upload_batch(
    body: bytes,
    *,
    max_record_bytes: int,
    reclassified_exclusions: list[ExclusionReceipt] | None = None,
) -> UploadBatch:
    if not body or len(body) > MAX_UPLOAD_REQUEST_BYTES:
        raise ValueError("upload request exceeds its size limit")
    try:
        value: object = json.loads(body, object_pairs_hook=_unique_json_object)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("upload request must be valid JSON") from error
    root = _exact_object(
        value,
        {
            "batch_id",
            "format_version",
            "source_account_id",
            "source_system",
            "source_path_hash",
            "parser",
            "collector",
            "source",
            "segment",
            "records",
            "exclusions",
        },
        "upload request",
    )
    batch_id = _required_string(root, "batch_id")
    if BATCH_ID.fullmatch(batch_id) is None:
        raise ValueError("upload batch id is invalid")
    if _required_int(root, "format_version") != UPLOAD_BATCH_FORMAT_VERSION:
        raise ValueError("upload batch format version is unsupported")
    core = {key: item for key, item in root.items() if key != "batch_id"}
    request_digest = hashlib.sha256(_canonical_json(core)).hexdigest()
    if batch_id != f"batch:{request_digest}":
        raise ValueError("upload batch id does not match its canonical payload")

    source_account_id = _required_string(root, "source_account_id")
    source_path_hash = _required_digest(root, "source_path_hash")
    try:
        source_system = SourceSystem(_required_string(root, "source_system"))
    except ValueError as error:
        raise ValueError("upload source system is unsupported") from error
    if source_system not in SUPPORTED_NATIVE_PARSERS:
        raise ValueError("batch upload currently supports native sources only")
    parser = _exact_object(root["parser"], {"name", "version"}, "parser")
    parser_name = _required_string(parser, "name")
    parser_version = _required_string(parser, "version")
    if (parser_name, parser_version) not in accepted_native_parsers(source_system):
        raise ValueError("upload parser does not match the pinned node parser")
    collector = _exact_object(
        root["collector"],
        {
            "source_client",
            "source_client_version",
            "capture_capability",
            "adapter_name",
            "adapter_version",
            "schema_fingerprint",
        },
        "collector provenance",
    )
    provenance = _validate_collector_provenance(
        CollectorProvenance(
            source_client=_required_string(collector, "source_client"),
            source_client_version=_required_string(collector, "source_client_version"),
            capture_capability=_required_string(collector, "capture_capability"),
            adapter_name=_required_string(collector, "adapter_name"),
            adapter_version=_required_string(collector, "adapter_version"),
            schema_fingerprint=_required_digest(collector, "schema_fingerprint"),
        ),
        source_system,
    )

    source = _exact_object(
        root["source"],
        {
            "conversation_id",
            "branch_id",
            "parent_conversation_id",
            "source_label",
            "captured_at",
            "history_base",
            "observed_file_size",
        },
        "source descriptor",
    )
    conversation_id = _required_string(source, "conversation_id")
    branch_id = _optional_string(source, "branch_id")
    parent_conversation_id = _optional_string(source, "parent_conversation_id")
    source_label = _optional_string(source, "source_label")
    captured_at = _optional_string(source, "captured_at")
    history_base = _parse_history_base(source["history_base"])
    observed_file_size = _required_nonnegative_int(source, "observed_file_size")
    source_kind = _derive_source_kind(
        source_system,
        source_label=source_label,
        parent_conversation_id=parent_conversation_id,
    )
    if source_system is not SourceSystem.CODEX and history_base is not None:
        raise ValueError("only Codex uploads may carry a history base")

    segment = _exact_object(
        root["segment"],
        {
            "start_record_ordinal",
            "start_byte_offset",
            "end_record_ordinal",
            "end_byte_offset",
            "start_prefix_sha256",
            "end_prefix_sha256",
            "file_mtime_ns",
        },
        "source segment",
    )
    start_ordinal = _required_nonnegative_int(segment, "start_record_ordinal")
    start_byte = _required_nonnegative_int(segment, "start_byte_offset")
    end_ordinal = _required_nonnegative_int(segment, "end_record_ordinal")
    end_byte = _required_nonnegative_int(segment, "end_byte_offset")
    start_digest = _required_digest(segment, "start_prefix_sha256")
    end_digest = _required_digest(segment, "end_prefix_sha256")
    file_mtime_ns = _required_nonnegative_int(segment, "file_mtime_ns")
    if end_ordinal < start_ordinal or end_byte < start_byte:
        raise ValueError("upload source segment boundaries are invalid")
    if observed_file_size < end_byte:
        raise ValueError("upload observed file size is below the consumed segment")

    record_values = root["records"]
    exclusion_values = root["exclusions"]
    if not isinstance(record_values, list):
        raise ValueError("upload record count exceeds its limit")
    if not isinstance(exclusion_values, list):
        raise ValueError("upload exclusion count exceeds its limit")
    record_items = cast(list[object], record_values)
    exclusion_items = cast(list[object], exclusion_values)
    if len(record_items) > MAX_UPLOAD_RECORDS:
        raise ValueError("upload record count exceeds its limit")
    if len(exclusion_items) > MAX_UPLOAD_EXCLUSIONS:
        raise ValueError("upload exclusion count exceeds its limit")
    if (
        not record_items
        and not exclusion_items
        and (end_ordinal <= start_ordinal or end_byte <= start_byte)
    ):
        raise ValueError("metadata-only upload must advance the source cursor")

    synthetic_path = Path(f"/collector/{source_path_hash}/updates.jsonl")
    codex_metadata, claude_metadata = _parser_metadata(
        source_system,
        legacy_codex=parser_name == LEGACY_PARSER_NAME,
        conversation_id=conversation_id,
        branch_id=branch_id,
        parent_conversation_id=parent_conversation_id,
        captured_at=captured_at,
        history_base=history_base,
        source_kind=source_kind,
        source_label=source_label,
    )
    records: list[ParsedRecord] = []
    total_decoded_bytes = 0
    locators: list[tuple[int, int, int]] = []
    for item in record_items:
        record = _exact_object(
            item,
            {"record_ordinal", "byte_start", "byte_end", "raw_sha256", "raw_base64"},
            "upload record",
        )
        ordinal = _required_nonnegative_int(record, "record_ordinal")
        byte_start = _required_nonnegative_int(record, "byte_start")
        byte_end = _required_nonnegative_int(record, "byte_end")
        raw_digest = _required_digest(record, "raw_sha256")
        raw_encoded = _required_string(record, "raw_base64", max_bytes=2 * max_record_bytes)
        try:
            raw = base64.b64decode(raw_encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("upload record is not valid base64") from error
        if not raw or len(raw) > max_record_bytes:
            raise ValueError("upload record exceeds its decoded size limit")
        total_decoded_bytes += len(raw)
        if total_decoded_bytes > MAX_UPLOAD_DECODED_BYTES:
            raise ValueError("upload decoded records exceed their aggregate size limit")
        if byte_end <= byte_start or byte_end - byte_start != len(raw):
            raise ValueError("upload record byte locator does not match its raw bytes")
        if not (
            start_ordinal <= ordinal < end_ordinal
            and start_byte <= byte_start < byte_end <= end_byte
        ):
            raise ValueError("upload record locator is outside the source segment")
        if hashlib.sha256(raw).hexdigest() != raw_digest:
            raise ValueError("upload record digest does not match its raw bytes")
        parsed_record = _reparse_record(
            source_system,
            raw,
            path=synthetic_path,
            ordinal=ordinal,
            byte_start=byte_start,
            byte_end=byte_end,
            codex_metadata=codex_metadata,
            claude_metadata=claude_metadata,
            conversation_id=conversation_id,
            parser_version=parser_version,
        )
        decision = classify_record(
            source_system,
            parsed_record.content_text,
            raw,
            max_record_bytes=max_record_bytes,
        )
        if not decision.accepted:
            if reclassified_exclusions is None:
                raise ValueError(
                    f"uploaded admitted record failed node admission: {decision.reason}"
                )
            reclassified_exclusions.append(
                ExclusionReceipt(ordinal, byte_start, byte_end, decision.reason)
            )
        else:
            records.append(parsed_record)
        locators.append((ordinal, byte_start, byte_end))

    exclusions: list[ExclusionReceipt] = []
    for item in exclusion_items:
        receipt = _exact_object(
            item,
            {"record_ordinal", "byte_start", "byte_end", "reason"},
            "upload exclusion",
        )
        exclusion = ExclusionReceipt(
            record_ordinal=_required_nonnegative_int(receipt, "record_ordinal"),
            byte_start=_required_nonnegative_int(receipt, "byte_start"),
            byte_end=_required_nonnegative_int(receipt, "byte_end"),
            reason=_required_string(receipt, "reason"),
        )
        if not is_admission_exclusion_reason(exclusion.reason):
            raise ValueError("upload exclusion reason is invalid")
        if exclusion.byte_end <= exclusion.byte_start:
            raise ValueError("upload exclusion byte locator is invalid")
        if not (
            start_ordinal <= exclusion.record_ordinal < end_ordinal
            and start_byte <= exclusion.byte_start < exclusion.byte_end <= end_byte
        ):
            raise ValueError("upload exclusion locator is outside the source segment")
        exclusions.append(exclusion)
        locators.append((exclusion.record_ordinal, exclusion.byte_start, exclusion.byte_end))
    _validate_locators(locators)

    parsed = ParseResult(
        source_system=source_system,
        parser_name=parser_name,
        parser_version=parser_version,
        path=synthetic_path,
        file_digest=end_digest,
        file_size=end_byte,
        file_mtime_ns=file_mtime_ns,
        conversation_id=conversation_id,
        branch_id=branch_id,
        captured_at=captured_at,
        history_base=history_base,
        records=tuple(records),
        unknown_record_types=(),
        malformed_records=0,
        source_kind=source_kind,
        source_label=source_label,
        parent_conversation_id=parent_conversation_id,
        segment_start_ordinal=start_ordinal,
        segment_start_byte=start_byte,
        segment_end_ordinal_exclusive=end_ordinal,
        segment_end_byte=end_byte,
        start_prefix_digest=start_digest,
        end_prefix_digest=end_digest,
        observed_file_size=observed_file_size,
        schema_fingerprint=provenance.schema_fingerprint,
    )
    return UploadBatch(
        batch_id=batch_id,
        request_digest=request_digest,
        source_account_id=source_account_id,
        source_path_hash=source_path_hash,
        provenance=provenance,
        parsed=parsed,
        exclusion_receipts=tuple(exclusions),
    )


def _reparse_record(
    source_system: SourceSystem,
    raw: bytes,
    *,
    path: Path,
    ordinal: int,
    byte_start: int,
    byte_end: int,
    codex_metadata: CodexMetadata | None,
    claude_metadata: ClaudeCodeMetadata | None,
    conversation_id: str,
    parser_version: str,
) -> ParsedRecord:
    if source_system is SourceSystem.CODEX:
        assert codex_metadata is not None
        _metadata, records, unknown, malformed = parse_codex_records(
            raw,
            path,
            ordinal_base=ordinal,
            byte_base=byte_start,
            metadata=codex_metadata,
            parser_version=parser_version,
        )
        parsed_conversation_id = codex_metadata.conversation_id
    elif source_system is SourceSystem.CLAUDE_CODE:
        assert claude_metadata is not None
        parsed_conversation_id, _branch, _captured, records, unknown, malformed = (
            parse_claude_code_records(
                raw, path, metadata=claude_metadata, parser_version=parser_version
            )
        )
        records = tuple(
            replace(
                item,
                record_ordinal=ordinal,
                byte_start=byte_start,
                byte_end=byte_end,
            )
            for item in records
        )
    elif source_system is SourceSystem.GROK_BUILD:
        parsed_conversation_id, _branch, _captured, records, unknown, malformed = (
            parse_grok_build_records(raw, path)
        )
        records = tuple(
            replace(
                item,
                record_ordinal=ordinal,
                byte_start=byte_start,
                byte_end=byte_end,
            )
            for item in records
        )
    else:  # pragma: no cover - guarded before dispatch
        raise ValueError("upload source system is unsupported")
    if parsed_conversation_id != conversation_id:
        raise ValueError("upload record conversation identity changed during node parsing")
    if unknown or malformed or len(records) != 1:
        raise ValueError("upload record does not match the pinned parser schema")
    record = records[0]
    if (
        record.raw_record != raw
        or record.record_ordinal != ordinal
        or record.byte_start != byte_start
        or record.byte_end != byte_end
    ):
        raise ValueError("upload record locators changed during node parsing")
    return record


def _parser_metadata(
    source_system: SourceSystem,
    *,
    legacy_codex: bool = False,
    conversation_id: str,
    branch_id: str | None,
    parent_conversation_id: str | None,
    captured_at: str | None,
    history_base: HistoryBase | None,
    source_kind: SourceKind,
    source_label: str | None,
) -> tuple[CodexMetadata | None, ClaudeCodeMetadata | None]:
    if source_system is SourceSystem.CODEX:
        if branch_id is None:
            raise ValueError("Codex source branch identity is required")
        if legacy_codex and (
            source_kind is not SourceKind.UNKNOWN
            or source_label is not None
            or parent_conversation_id is not None
            or history_base is not None
            or branch_id != conversation_id
        ):
            raise ValueError("unwrapped Codex source provenance must remain unknown")
        return (
            CodexMetadata(
                conversation_id=conversation_id,
                branch_id=branch_id,
                parent_conversation_id=parent_conversation_id,
                captured_at=captured_at,
                history_base=history_base,
                source_kind=source_kind,
                source_label=source_label,
                legacy_format=legacy_codex,
            ),
            None,
        )
    if source_system is SourceSystem.CLAUDE_CODE:
        if branch_id is None or source_label is None:
            raise ValueError("Claude Code source branch and label are required")
        return (
            None,
            ClaudeCodeMetadata(
                conversation_id=conversation_id,
                branch_id=branch_id,
                parent_conversation_id=parent_conversation_id,
                captured_at=captured_at,
                source_kind=source_kind,
                source_label=source_label,
            ),
        )
    if source_system is SourceSystem.GROK_BUILD:
        if branch_id != conversation_id:
            raise ValueError("Grok Build source branch must match its conversation")
        return None, None
    raise ValueError("upload source system is unsupported")


def _derive_source_kind(
    source_system: SourceSystem,
    *,
    source_label: str | None,
    parent_conversation_id: str | None,
) -> SourceKind:
    if source_system is SourceSystem.CODEX:
        if source_label in CODEX_INTERACTIVE_SOURCE_LABELS:
            return SourceKind.INTERACTIVE
        if source_label in CODEX_AUTOMATION_SOURCE_LABELS:
            return SourceKind.AUTOMATION
        if source_label == "subagent":
            if parent_conversation_id is None:
                raise ValueError("Codex subagent source requires a parent conversation")
            return SourceKind.SUBAGENT
        return SourceKind.UNKNOWN
    if source_system is SourceSystem.CLAUDE_CODE:
        if source_label in CLAUDE_INTERACTIVE_ENTRYPOINTS:
            return SourceKind.INTERACTIVE
        if source_label in CLAUDE_AUTOMATION_ENTRYPOINTS or source_label == "claude_mem_observer":
            return SourceKind.AUTOMATION
        if source_label == "claude_code_subagent":
            if parent_conversation_id is None:
                raise ValueError("Claude Code subagent source requires a parent conversation")
            return SourceKind.SUBAGENT
        return SourceKind.UNKNOWN
    if source_system is SourceSystem.GROK_BUILD:
        if source_label != "grok_build" or parent_conversation_id is not None:
            raise ValueError("Grok Build source provenance is invalid")
        return SourceKind.INTERACTIVE
    raise ValueError("upload source system is unsupported")


def _validate_locators(locators: list[tuple[int, int, int]]) -> None:
    ordered = sorted(locators)
    ordinals: set[int] = set()
    previous_end = -1
    for ordinal, byte_start, byte_end in ordered:
        if ordinal in ordinals:
            raise ValueError("upload contains a duplicate source ordinal")
        if byte_start < previous_end:
            raise ValueError("upload source byte locators overlap")
        ordinals.add(ordinal)
        previous_end = byte_end


def _history_base_value(history_base: HistoryBase | None) -> dict[str, object] | None:
    if history_base is None:
        return None
    return {
        "thread_id": history_base.thread_id,
        "end_record_ordinal": history_base.end_ordinal_exclusive,
        "end_byte_offset": history_base.end_byte_offset,
    }


def _validate_collector_provenance(
    value: CollectorProvenance,
    source_system: SourceSystem,
) -> CollectorProvenance:
    normalized = CollectorProvenance(
        source_client=_bounded_string(value.source_client, "source_client"),
        source_client_version=_bounded_string(value.source_client_version, "source_client_version"),
        capture_capability=_bounded_string(value.capture_capability, "capture_capability"),
        adapter_name=_bounded_string(value.adapter_name, "adapter_name"),
        adapter_version=_bounded_string(value.adapter_version, "adapter_version"),
        schema_fingerprint=value.schema_fingerprint,
    )
    if SHA256_HEX.fullmatch(normalized.schema_fingerprint) is None:
        raise ValueError("schema_fingerprint is invalid")
    if (
        normalized.source_client,
        normalized.capture_capability,
        normalized.adapter_name,
        normalized.adapter_version,
    ) != SUPPORTED_NATIVE_COLLECTORS[source_system]:
        raise ValueError("collector provenance does not match the pinned native adapter")
    return normalized


def _parse_history_base(value: object) -> HistoryBase | None:
    if value is None:
        return None
    item = _exact_object(
        value,
        {"thread_id", "end_record_ordinal", "end_byte_offset"},
        "history base",
    )
    return HistoryBase(
        thread_id=_required_string(item, "thread_id"),
        end_ordinal_exclusive=_required_nonnegative_int(item, "end_record_ordinal"),
        end_byte_offset=_required_nonnegative_int(item, "end_byte_offset"),
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _protocol_id(kind: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join((kind, *parts)).encode()).hexdigest()
    return f"{kind}:{digest}"


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object field")
        value[key] = item
    return value


def _exact_object(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    raw = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw) or set(raw) != fields:
        raise ValueError(f"{label} fields are invalid")
    return cast(dict[str, object], raw)


def _required_string(
    value: dict[str, object],
    field: str,
    *,
    max_bytes: int = MAX_UPLOAD_IDENTITY_BYTES,
) -> str:
    item = value[field]
    if (
        not isinstance(item, str)
        or not item
        or item.strip() != item
        or len(item.encode()) > max_bytes
    ):
        raise ValueError(f"{field} is invalid")
    return item


def _bounded_string(value: str, field: str) -> str:
    if not value or value.strip() != value or len(value.encode()) > MAX_UPLOAD_IDENTITY_BYTES:
        raise ValueError(f"{field} is invalid")
    return value


def _optional_string(value: dict[str, object], field: str) -> str | None:
    item = value[field]
    if item is None:
        return None
    if (
        not isinstance(item, str)
        or not item
        or item.strip() != item
        or len(item.encode()) > MAX_UPLOAD_IDENTITY_BYTES
    ):
        raise ValueError(f"{field} is invalid")
    return item


def _required_int(value: dict[str, object], field: str) -> int:
    item = value[field]
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"{field} is invalid")
    return item


def _required_nonnegative_int(value: dict[str, object], field: str) -> int:
    item = _required_int(value, field)
    if item < 0 or item > MAX_SQLITE_INTEGER:
        raise ValueError(f"{field} is invalid")
    return item


def _required_digest(value: dict[str, object], field: str) -> str:
    digest = _required_string(value, field)
    if SHA256_HEX.fullmatch(digest) is None:
        raise ValueError(f"{field} is invalid")
    return digest
