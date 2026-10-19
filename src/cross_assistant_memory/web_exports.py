from __future__ import annotations

import hashlib
import json
import mmap
import os
import re
import shutil
import stat
import tempfile
import uuid
import zipfile
from collections import Counter
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict, cast

from cross_assistant_memory.admission import (
    TEXT_ATTACHMENT_MEDIA_TYPES,
    classify_attachment,
    classify_record,
)
from cross_assistant_memory.backup import (
    OFFLINE_CLONE_MARKER,
    SNAPSHOT_MANIFEST,
    WEB_SOURCE_CONFIGURATION_RECEIPT,
    verify_offline_clone_marker,
    verify_snapshot,
)
from cross_assistant_memory.config import Settings, default_data_root
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.ingest import DEFAULT_MAX_FILE_BYTES, parse_file
from cross_assistant_memory.models import (
    ParsedRecord,
    ParseResult,
    Scope,
    SourceSchemaProvenance,
    SourceSystem,
    WebExportArchiveMemberProvenance,
    WebExportAttachmentReferenceProvenance,
    WebExportBatchProvenance,
    WebExportConversationObservation,
)
from cross_assistant_memory.object_writes import ObjectWriteScope
from cross_assistant_memory.parsers.json_bytes import (
    JsonSpan,
    JsonValueCountLimitError,
    object_array_value_spans,
    object_item_spans,
    top_level_array_value_spans,
)
from cross_assistant_memory.publication_work import (
    EvidencePublicationPending,
    EvidencePublicationPolicy,
    publication_key_sha256,
)
from cross_assistant_memory.runtime_provenance import (
    require_runtime_code_revision as require_runtime_code_revision,
)
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
    secure_path_stat,
)
from cross_assistant_memory.storage import (
    DEFAULT_MAX_RECORD_BYTES,
    MAX_WEB_EXPORT_RECEIPT_BYTES,
    Ledger,
    exclusive_ledger_writer,
)
from cross_assistant_memory.web_export_limits import (
    DEFAULT_WEB_EXPORT_LIMITS,
    ArchiveInspection,
    ResourceBudget,
    WebExportLimitError,
    WebExportLimits,
    enforce_record_count,
    inspect_zip_archive,
    limits_from_dict,
    validate_json_limits,
    validate_limits,
)

WEB_EXPORT_PLAN_VERSION = 11
WEB_EXPORT_EXTRACTOR_VERSION = "0.11.0"
WEB_SOURCE_SYSTEMS = frozenset(
    {SourceSystem.CHATGPT_WEB, SourceSystem.CLAUDE_WEB, SourceSystem.GROK_WEB}
)
COPY_CHUNK_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
WEB_EXPORT_RECEIPT_VERSION = 3
_IMPORT_RECEIPT_COUNTS = (
    "source_observations",
    "new_source_files",
    "existing_source_files",
    "inserted_events",
    "reconciled_events",
    "observed_quarantined_records",
    "new_quarantined_records",
    "new_batches",
    "existing_batches",
)
MAX_WEB_EXPORT_BATCH_PLANS = 16
WEB_EXPORT_CAPTURE_CAPABILITY = "official-data-export"
WEB_EXPORT_ADAPTER_NAME = "cross-agent-memory-web-export"
DEFAULT_WEB_SOURCE_CLIENT_VERSION = "official-export-unversioned"
WEB_SOURCE_CLIENTS = {
    SourceSystem.CHATGPT_WEB: "chatgpt-web",
    SourceSystem.CLAUDE_WEB: "claude-web",
    SourceSystem.GROK_WEB: "grok-web",
}
WEB_SOURCE_ADAPTER_VERSIONS = {
    SourceSystem.CHATGPT_WEB: "0.9.1",
    SourceSystem.CLAUDE_WEB: "0.8.0",
    SourceSystem.GROK_WEB: "0.8.0",
}
DEFAULT_MAX_EXTRACTED_ATTACHMENT_BYTES = 64 * 1024 * 1024
_ATTACHMENT_PLAN_CHECKPOINT_INTERVAL = 1024
_CHATGPT_CONVERSATION_SHARD = re.compile(r"conversations-(\d{3,})\.json")
DEFAULT_EXTRACTED_ATTACHMENT_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/pdf",
        "application/zip",
        "image/gif",
        "image/jpeg",
        "image/png",
        "image/webp",
        "text/csv",
        "text/markdown",
        "text/plain",
        "video/mp4",
    }
)


class _SchemaSource(TypedDict):
    source_account_id: str
    source_system: SourceSystem
    scope: Scope
    project_id: str | None


@dataclass(frozen=True)
class _AttachmentReference:
    conversation_index: int
    source_record_ordinal: int
    reference_ordinal: int
    value: str
    reference_sha256: str


@dataclass(frozen=True)
class _AttachmentPlan:
    member_manifests: tuple[dict[str, object], ...]
    references: tuple[WebExportAttachmentReferenceProvenance, ...]
    extracted_indices: tuple[int, ...]
    summary: dict[str, object]


@dataclass(frozen=True)
class _ConversationMember:
    path: Path
    archive_member: str
    archive_member_index: int
    name_sha256: str
    content_sha256: str
    byte_length: int


@dataclass(frozen=True)
class VerifiedConversation:
    path: Path
    conversation_id: str
    source_path: str
    source_locator: str
    conversation_index: int
    source_byte_start: int
    source_byte_end: int
    conversation_sha256: str
    byte_length: int
    planned_ingest: bool
    entry: dict[str, Any]


@dataclass(frozen=True)
class VerifiedWebExportPlan:
    manifest_path: Path
    manifest_sha256: str
    archive_path: Path
    member_path: Path
    source_system: SourceSystem
    source_account: str
    scope: Scope
    project_id: str | None
    expected_ledger_generation: str
    code_revision: str
    max_record_bytes: int
    source_provenance: SourceSchemaProvenance
    batch_provenance: WebExportBatchProvenance
    limits: WebExportLimits
    resource_usage: dict[str, int]
    manifest: dict[str, Any]
    conversations: tuple[VerifiedConversation, ...]
    attachment_paths: tuple[tuple[int, Path], ...]


def extract_web_export_member(
    *,
    archive_path: Path,
    archive_member: str,
    expected_archive_sha256: str,
    output: Path,
    limits: WebExportLimits = DEFAULT_WEB_EXPORT_LIMITS,
) -> dict[str, object]:
    _validate_digest(expected_archive_sha256, "expected archive SHA-256")
    validate_limits(limits)
    budget = ResourceBudget(limits)
    archive = _regular_file(archive_path, "export archive")
    destination = output.expanduser()
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"web export member output already exists: {destination}")
    archive_identity = _stat_identity(archive.lstat())

    inspection = inspect_zip_archive(
        archive,
        archive_member,
        limits=limits,
        budget=budget,
    )
    if _stat_identity(archive.lstat()) != archive_identity:
        raise RuntimeError("web export archive changed after inspection")
    if inspection.archive_sha256 != expected_archive_sha256:
        raise RuntimeError("web export archive does not match the expected SHA-256")
    budget.add_disk_bytes(inspection.selected_member_size)
    _prepare_private_output_directory(destination.parent)

    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    output_descriptor = os.open(temporary, flags, 0o400)
    digest = hashlib.sha256()
    byte_length = 0
    published = False
    try:
        archive_descriptor = os.open(
            archive,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        with os.fdopen(archive_descriptor, "rb") as archive_handle:
            before = os.fstat(archive_handle.fileno())
            if _stat_identity(before) != archive_identity:
                raise RuntimeError("web export archive changed before extraction")
            with zipfile.ZipFile(archive_handle) as zip_archive:
                matches = [
                    item
                    for item in zip_archive.infolist()
                    if not item.is_dir() and item.filename == archive_member
                ]
                if len(matches) != 1:
                    raise RuntimeError("selected web export member changed after inspection")
                with os.fdopen(output_descriptor, "wb") as output_handle:
                    with zip_archive.open(matches[0], "r") as member_handle:
                        while chunk := member_handle.read(
                            min(
                                COPY_CHUNK_BYTES,
                                inspection.selected_member_size - byte_length + 1,
                            )
                        ):
                            byte_length += len(chunk)
                            if byte_length > inspection.selected_member_size:
                                raise RuntimeError(
                                    "selected web export member exceeded its inspected length"
                                )
                            digest.update(chunk)
                            output_handle.write(chunk)
                            budget.checkpoint(logical_memory_bytes=len(chunk))
                    output_handle.flush()
                    os.fsync(output_handle.fileno())
            after = os.fstat(archive_handle.fileno())
        if _stat_identity(after) != archive_identity:
            raise RuntimeError("web export archive changed while extracting")
        if (byte_length, digest.hexdigest()) != (
            inspection.selected_member_size,
            inspection.selected_member_sha256,
        ):
            raise RuntimeError("extracted web export member failed exact verification")
        resource_usage = budget.usage()
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as exc:
            raise ValueError(f"web export member output already exists: {destination}") from exc
        published = True
        temporary.unlink()
        directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        with suppress(OSError):
            os.close(output_descriptor)
        temporary.unlink(missing_ok=True)
        if published:
            destination.unlink(missing_ok=True)
        raise

    return {
        "status": "extracted",
        "archive_path": str(archive.resolve()),
        "archive_member": archive_member,
        "archive_sha256": inspection.archive_sha256,
        "member_path": str(destination.resolve()),
        "member_sha256": inspection.selected_member_sha256,
        "member_byte_length": inspection.selected_member_size,
        "member_interpreted": False,
        "content_emitted": False,
        "archive_inspection": inspection.as_dict(),
        "resource_usage": resource_usage,
    }


def _record_attachment_references(
    record: ParsedRecord,
    *,
    source_system: SourceSystem,
    conversation_index: int,
) -> tuple[tuple[_AttachmentReference, ...], int]:
    if source_system is not SourceSystem.GROK_WEB:
        return (), 0
    try:
        loaded: object = json.loads(record.raw_record)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return (), 1
    if not isinstance(loaded, dict):
        return (), 1
    attachments_value = cast(dict[str, object], loaded).get("file_attachments")
    if attachments_value is None:
        return (), 0
    if not isinstance(attachments_value, list):
        return (), 1
    references: list[_AttachmentReference] = []
    malformed = 0
    for reference_ordinal, reference_value in enumerate(cast(list[object], attachments_value)):
        if not isinstance(reference_value, str) or not reference_value:
            malformed += 1
            continue
        references.append(
            _AttachmentReference(
                conversation_index=conversation_index,
                source_record_ordinal=record.record_ordinal,
                reference_ordinal=reference_ordinal,
                value=reference_value,
                reference_sha256=hashlib.sha256(reference_value.encode()).hexdigest(),
            )
        )
    return tuple(references), malformed


def _plan_attachments(
    inspection: ArchiveInspection,
    references: list[_AttachmentReference],
    *,
    archive_path: Path,
    archive_identity: tuple[int, int, int, int, int],
    source_system: SourceSystem,
    conversation_member_indices: frozenset[int],
    malformed_references: int,
    max_extracted_bytes: int,
    extracted_media_types: frozenset[str],
    budget: ResourceBudget,
    logical_memory_bytes: int,
) -> _AttachmentPlan:
    budget.checkpoint(logical_memory_bytes=logical_memory_bytes)
    reference_members: dict[str, set[int]] = {reference.value: set() for reference in references}
    for ordinal, member in enumerate(inspection.supplemental_members):
        if ordinal % _ATTACHMENT_PLAN_CHECKPOINT_INTERVAL == 0:
            budget.checkpoint(logical_memory_bytes=logical_memory_bytes)
        if member.archive_member_index in conversation_member_indices:
            continue
        for segment in set(PurePosixPath(member.member_name).parts):
            if segment in reference_members:
                reference_members[segment].add(member.archive_member_index)

    links_by_member: dict[int, list[WebExportAttachmentReferenceProvenance]] = {}
    unmatched = 0
    ambiguous = 0
    linked_references = 0
    for ordinal, reference in enumerate(references):
        if ordinal % _ATTACHMENT_PLAN_CHECKPOINT_INTERVAL == 0:
            budget.checkpoint(logical_memory_bytes=logical_memory_bytes)
        candidates = reference_members[reference.value]
        if not candidates:
            unmatched += 1
            continue
        if len(candidates) != 1:
            ambiguous += 1
            continue
        archive_member_index = next(iter(candidates))
        links_by_member.setdefault(archive_member_index, []).append(
            WebExportAttachmentReferenceProvenance(
                archive_member_index=archive_member_index,
                conversation_index=reference.conversation_index,
                source_record_ordinal=reference.source_record_ordinal,
                reference_ordinal=reference.reference_ordinal,
                reference_sha256=reference.reference_sha256,
            )
        )
        linked_references += 1

    manifests: list[dict[str, object]] = []
    extracted_indices: list[int] = []
    linked_conversations: set[int] = set()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(archive_path, flags), "rb") as archive_handle:
        if _stat_identity(os.fstat(archive_handle.fileno())) != archive_identity:
            raise RuntimeError("web export archive changed before attachment admission")
        with zipfile.ZipFile(archive_handle) as archive:
            archive_infos = archive.infolist()
            for ordinal, member in enumerate(inspection.supplemental_members):
                if ordinal % _ATTACHMENT_PLAN_CHECKPOINT_INTERVAL == 0:
                    budget.checkpoint(logical_memory_bytes=logical_memory_bytes)
                manifest = member.as_dict()
                links = tuple(
                    sorted(
                        links_by_member.get(member.archive_member_index, []),
                        key=lambda item: (
                            item.conversation_index,
                            item.source_record_ordinal,
                            item.reference_ordinal,
                            item.reference_sha256,
                        ),
                    )
                )
                manifest["links"] = [
                    {
                        "conversation_index": link.conversation_index,
                        "source_record_ordinal": link.source_record_ordinal,
                        "reference_ordinal": link.reference_ordinal,
                        "reference_sha256": link.reference_sha256,
                    }
                    for link in links
                ]
                manifest["relative_path"] = None
                if member.archive_member_index in conversation_member_indices:
                    manifest["classification_status"] = "conversation_payload"
                    manifest["link_status"] = "not_applicable"
                    manifest["diagnostic_code"] = "selected_conversation_payload"
                elif links:
                    linked_conversations.update(link.conversation_index for link in links)
                    manifest["classification_status"] = "provider_attachment"
                    manifest["link_status"] = "linked"
                    if member.byte_length > max_extracted_bytes:
                        manifest["diagnostic_code"] = "attachment_exceeds_extraction_size_policy"
                    elif member.media_type not in extracted_media_types:
                        manifest["diagnostic_code"] = "attachment_media_type_not_extracted"
                    elif member.media_type not in TEXT_ATTACHMENT_MEDIA_TYPES:
                        manifest["diagnostic_code"] = "attachment_content_not_inspectable"
                    elif member.byte_length > DEFAULT_MAX_RECORD_BYTES:
                        manifest["diagnostic_code"] = "attachment_exceeds_admission_size_policy"
                    else:
                        budget.checkpoint(
                            logical_memory_bytes=logical_memory_bytes
                            + budget.conversation_memory_bytes(member.byte_length, 0)
                        )
                        info = archive_infos[member.archive_member_index]
                        if info.filename != member.member_name or info.is_dir():
                            raise RuntimeError("attachment member changed before admission")
                        with archive.open(info) as handle:
                            raw = handle.read(member.byte_length + 1)
                        if (
                            len(raw) != member.byte_length
                            or hashlib.sha256(raw).hexdigest() != member.content_sha256
                        ):
                            raise RuntimeError("attachment changed before admission")
                        decision = classify_attachment(
                            source_system,
                            member.media_type,
                            raw,
                            max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
                        )
                        del raw
                        budget.checkpoint(logical_memory_bytes=logical_memory_bytes)
                        if decision.accepted:
                            manifest["extraction_status"] = "extracted"
                            manifest["diagnostic_code"] = "provider_attachment_extracted"
                            manifest["relative_path"] = (
                                f"attachments/{member.archive_member_index:08d}.bin"
                            )
                            extracted_indices.append(member.archive_member_index)
                        else:
                            manifest["diagnostic_code"] = f"attachment_admission:{decision.reason}"
                manifests.append(manifest)
        if _stat_identity(os.fstat(archive_handle.fileno())) != archive_identity:
            raise RuntimeError("web export archive changed during attachment admission")

    references_flat = tuple(
        link
        for member_index in sorted(links_by_member)
        for link in sorted(
            links_by_member[member_index],
            key=lambda item: (
                item.conversation_index,
                item.source_record_ordinal,
                item.reference_ordinal,
                item.reference_sha256,
            ),
        )
    )
    summary: dict[str, object] = {
        "adapter": (
            "grok-response-file-attachments-exact-segment-v1"
            if source_system is SourceSystem.GROK_WEB
            else "no-provider-archive-linkage"
        ),
        "reference_count": len(references),
        "linked_reference_count": linked_references,
        "unmatched_reference_count": unmatched,
        "ambiguous_reference_count": ambiguous,
        "malformed_reference_count": malformed_references,
        "linked_member_count": len(links_by_member),
        "linked_conversation_count": len(linked_conversations),
        "extracted_member_count": len(extracted_indices),
        "unclassified_member_count": (
            len(inspection.supplemental_members)
            - len(links_by_member)
            - len(conversation_member_indices)
        ),
    }
    return _AttachmentPlan(
        member_manifests=tuple(manifests),
        references=references_flat,
        extracted_indices=tuple(sorted(extracted_indices)),
        summary=summary,
    )


def _extract_planned_attachments(
    archive_path: Path,
    plan_root: Path,
    inspection: ArchiveInspection,
    extracted_indices: tuple[int, ...],
    *,
    archive_identity: tuple[int, int, int, int, int],
    budget: ResourceBudget,
) -> None:
    if not extracted_indices:
        return
    attachment_root = plan_root / "attachments"
    attachment_root.mkdir(mode=0o700)
    member_by_index = {
        member.archive_member_index: member for member in inspection.supplemental_members
    }
    archive_descriptor = os.open(
        archive_path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    with os.fdopen(archive_descriptor, "rb") as archive_handle:
        if _stat_identity(os.fstat(archive_handle.fileno())) != archive_identity:
            raise RuntimeError("web export archive changed before attachment extraction")
        with zipfile.ZipFile(archive_handle) as archive:
            infos = archive.infolist()
            for archive_member_index in extracted_indices:
                member = member_by_index[archive_member_index]
                info = infos[archive_member_index]
                if info.is_dir() or info.filename != member.member_name:
                    raise RuntimeError("attachment archive member changed before extraction")
                target = attachment_root / f"{archive_member_index:08d}.bin"
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target, flags, 0o400)
                digest = hashlib.sha256()
                byte_length = 0
                try:
                    with os.fdopen(descriptor, "wb") as output_handle:
                        with archive.open(info, "r") as input_handle:
                            while chunk := input_handle.read(
                                min(COPY_CHUNK_BYTES, member.byte_length - byte_length + 1)
                            ):
                                byte_length += len(chunk)
                                if byte_length > member.byte_length:
                                    raise RuntimeError(
                                        "attachment exceeded its inspected byte length"
                                    )
                                budget.add_disk_bytes(len(chunk))
                                output_handle.write(chunk)
                                digest.update(chunk)
                        output_handle.flush()
                        os.fsync(output_handle.fileno())
                except BaseException:
                    target.unlink(missing_ok=True)
                    raise
                if (byte_length, digest.hexdigest()) != (
                    member.byte_length,
                    member.content_sha256,
                ):
                    target.unlink(missing_ok=True)
                    raise RuntimeError("extracted attachment changed from its archive manifest")
        if _stat_identity(os.fstat(archive_handle.fileno())) != archive_identity:
            raise RuntimeError("web export archive changed during attachment extraction")


def _resolve_conversation_members(
    *,
    source_system: SourceSystem,
    primary_path: Path,
    primary_archive_member: str,
    additional_paths: tuple[Path, ...],
    additional_archive_members: tuple[str, ...],
    inspection: ArchiveInspection,
    budget: ResourceBudget,
) -> tuple[_ConversationMember, ...]:
    if len(additional_paths) != len(additional_archive_members):
        raise ValueError("each additional member path requires one archive member name")
    archive_members = (primary_archive_member, *additional_archive_members)
    if len(set(archive_members)) != len(archive_members):
        raise ValueError("conversation archive member names must be unique")
    if additional_archive_members and source_system is not SourceSystem.CHATGPT_WEB:
        raise ValueError("multipart web exports are supported only for ChatGPT")
    if source_system is SourceSystem.CHATGPT_WEB:
        indexed_archive_members = [
            (inspection.selected_member_index, primary_archive_member),
            *(
                (member.archive_member_index, member.member_name)
                for member in inspection.supplemental_members
            ),
        ]
        detected_shards = tuple(
            name
            for _, name in sorted(indexed_archive_members)
            if _CHATGPT_CONVERSATION_SHARD.fullmatch(name) is not None
        )
        if additional_archive_members or detected_shards:
            shard_numbers: list[int] = []
            for name in detected_shards:
                match = cast(re.Match[str], _CHATGPT_CONVERSATION_SHARD.fullmatch(name))
                number = int(match.group(1))
                if name != f"conversations-{number:03d}.json":
                    raise ValueError("ChatGPT conversation shard names must be canonical")
                shard_numbers.append(number)
            if shard_numbers != list(range(len(shard_numbers))):
                raise ValueError("archive ChatGPT members must be contiguous from shard 000")
            if archive_members != detected_shards:
                raise ValueError(
                    "ChatGPT planning must include every conversation shard in archive order"
                )

    paths = (primary_path, *additional_paths)
    resolved_paths = [path.expanduser().resolve() for path in paths]
    if len(set(resolved_paths)) != len(resolved_paths):
        raise ValueError("conversation member paths must be unique")

    supplemental_by_name = {
        member.member_name: member for member in inspection.supplemental_members
    }
    members: list[_ConversationMember] = []
    for ordinal, (path, archive_member) in enumerate(zip(paths, archive_members, strict=True)):
        source = _regular_file(path, "export member")
        if ordinal == 0:
            archive_member_index = inspection.selected_member_index
            expected = (
                inspection.selected_member_size,
                inspection.selected_member_sha256,
            )
        else:
            supplemental = supplemental_by_name.get(archive_member)
            if supplemental is None:
                raise RuntimeError("additional conversation member is absent from the archive")
            archive_member_index = supplemental.archive_member_index
            expected = (supplemental.byte_length, supplemental.content_sha256)
        byte_length, content_sha256 = _hash_file(
            source,
            expected_size=expected[0],
            budget=budget,
        )
        if (byte_length, content_sha256) != expected:
            raise RuntimeError("extracted member does not match its named archive member")
        members.append(
            _ConversationMember(
                path=source,
                archive_member=archive_member,
                archive_member_index=archive_member_index,
                name_sha256=hashlib.sha256(archive_member.encode()).hexdigest(),
                content_sha256=content_sha256,
                byte_length=byte_length,
            )
        )
    indices = [member.archive_member_index for member in members]
    if indices != sorted(indices):
        raise ValueError("conversation members must follow their order in the archive")
    return tuple(members)


def prepare_web_export_plan(
    *,
    source_system: SourceSystem,
    source_account: str,
    member_path: Path,
    archive_path: Path,
    archive_member: str,
    output: Path,
    scope: Scope,
    project_id: str | None,
    expected_ledger_generation: str,
    code_revision: str,
    additional_member_paths: tuple[Path, ...] = (),
    additional_archive_members: tuple[str, ...] = (),
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
    limits: WebExportLimits = DEFAULT_WEB_EXPORT_LIMITS,
    source_client_version: str = DEFAULT_WEB_SOURCE_CLIENT_VERSION,
    max_extracted_attachment_bytes: int | None = None,
    extracted_attachment_media_types: frozenset[str] = DEFAULT_EXTRACTED_ATTACHMENT_MEDIA_TYPES,
) -> dict[str, Any]:
    if source_system not in WEB_SOURCE_SYSTEMS:
        raise ValueError("web export preparation requires a web source system")
    if not source_account:
        raise ValueError("source_account must not be empty")
    if scope is Scope.PROJECT and not project_id:
        raise ValueError("project_id is required for project-scoped preparation")
    if scope is not Scope.PROJECT and project_id is not None:
        raise ValueError("only project-scoped preparation may carry project_id")
    _validate_digest(expected_ledger_generation, "expected ledger generation")
    _validate_code_revision(code_revision)
    require_runtime_code_revision(code_revision)
    if max_record_bytes <= 0:
        raise ValueError("max_record_bytes must be positive")
    if max_extracted_attachment_bytes is None:
        max_extracted_attachment_bytes = min(
            DEFAULT_MAX_EXTRACTED_ATTACHMENT_BYTES,
            limits.max_member_uncompressed_bytes,
        )
    if max_extracted_attachment_bytes <= 0:
        raise ValueError("max_extracted_attachment_bytes must be positive")
    if max_extracted_attachment_bytes > limits.max_member_uncompressed_bytes:
        raise ValueError("attachment extraction limit exceeds the archive member limit")
    if not extracted_attachment_media_types or any(
        not value or len(value) > 127 for value in extracted_attachment_media_types
    ):
        raise ValueError("attachment extraction media types are invalid")
    source_client_version = _bounded_manifest_label(
        source_client_version,
        "source client version",
    )
    validate_limits(limits)
    budget = ResourceBudget(limits)

    archive = _regular_file(archive_path, "export archive")
    archive_identity = _stat_identity(archive.lstat())
    destination = output.expanduser()
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"web export plan output already exists: {destination}")

    inspection = inspect_zip_archive(
        archive,
        archive_member,
        limits=limits,
        budget=budget,
        additional_conversation_member_names=frozenset(additional_archive_members),
    )
    if _stat_identity(archive.lstat()) != archive_identity:
        raise RuntimeError("web export archive changed after inspection")
    conversation_members = _resolve_conversation_members(
        source_system=source_system,
        primary_path=member_path,
        primary_archive_member=archive_member,
        additional_paths=additional_member_paths,
        additional_archive_members=additional_archive_members,
        inspection=inspection,
        budget=budget,
    )
    if _stat_identity(archive.lstat()) != archive_identity:
        raise RuntimeError("web export archive changed while binding conversation members")
    primary_member = conversation_members[0]
    additional_conversation_member_indices = frozenset(
        member.archive_member_index for member in conversation_members[1:]
    )
    budget.add_disk_bytes(
        inspection.archive_size + sum(member.byte_length for member in conversation_members)
    )

    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    temporary.chmod(0o700)
    conversation_root = temporary / "conversations"
    conversation_root.mkdir(mode=0o700)
    entries: list[dict[str, Any]] = []
    aggregate_roles: Counter[str] = Counter()
    aggregate_admission: Counter[str] = Counter()
    aggregate_unknown: Counter[str] = Counter()
    malformed_records = 0
    total_record_count = 0
    total_source_record_count = 0
    schema_descriptors: set[str] = set()
    parser_versions: dict[str, str] = {}
    attachment_references: list[_AttachmentReference] = []
    attachment_reference_utf8_bytes = 0
    malformed_attachment_references = 0

    try:
        for conversation_member in conversation_members:
            descriptor = os.open(
                conversation_member.path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            with os.fdopen(descriptor, "rb") as handle:
                before = os.fstat(handle.fileno())
                with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    view = memoryview(mapped)
                    try:
                        if (
                            len(view) != conversation_member.byte_length
                            or _hash_view(view, budget) != conversation_member.content_sha256
                        ):
                            raise RuntimeError("export member changed before split planning")
                        validate_json_limits(
                            view,
                            max_depth=limits.max_json_depth,
                            max_string_bytes=limits.max_json_string_bytes,
                            budget=budget,
                        )
                        remaining_records = limits.max_record_count - len(entries)
                        span_limit = min(
                            remaining_records + 1,
                            budget.conversation_span_limit(),
                        )
                        spans = _conversation_spans(
                            view,
                            source_system,
                            max_records=span_limit,
                            limit_code=(
                                "memory_bytes"
                                if span_limit < remaining_records + 1
                                else "record_count"
                            ),
                        )
                        enforce_record_count(len(entries) + len(spans), limits)
                        member_final_conversation_count = len(entries) + len(spans)
                        for member_conversation_index, span in enumerate(spans):
                            index = len(entries)
                            budget.checkpoint(
                                logical_memory_bytes=budget.conversation_memory_bytes(
                                    span.end - span.start,
                                    member_final_conversation_count,
                                )
                            )
                            raw = span.bytes(view)
                            source_record_count = _web_conversation_record_count(
                                raw,
                                source_system,
                                max_records=(
                                    limits.max_record_count - total_source_record_count + 1
                                ),
                            )
                            total_source_record_count += source_record_count
                            enforce_record_count(total_source_record_count, limits)
                            digest = hashlib.sha256(raw).hexdigest()
                            relative = Path("conversations") / f"{index:06d}-{digest[:16]}.json"
                            planned_path = temporary / relative
                            budget.add_disk_bytes(len(raw))
                            _write_private_file(planned_path, raw)
                            parsed = parse_file(
                                planned_path,
                                source_system,
                                max_file_bytes=max(DEFAULT_MAX_FILE_BYTES, len(raw)),
                                resource_checkpoint=budget.checkpoint,
                            )
                            role_counts = Counter(record.actor_kind for record in parsed.records)
                            admission_counts: Counter[str] = Counter()
                            conversation_references: list[_AttachmentReference] = []
                            for record in parsed.records:
                                decision = classify_record(
                                    source_system,
                                    record.content_text,
                                    record.raw_record,
                                    max_record_bytes=max_record_bytes,
                                )
                                admission_counts[decision.reason] += 1
                                if decision.accepted:
                                    references, malformed_references = (
                                        _record_attachment_references(
                                            record,
                                            source_system=source_system,
                                            conversation_index=index,
                                        )
                                    )
                                    conversation_references.extend(references)
                                    malformed_attachment_references += malformed_references
                            attachment_references.extend(conversation_references)
                            attachment_reference_utf8_bytes += sum(
                                len(reference.value.encode())
                                for reference in conversation_references
                            )
                            enforce_record_count(len(attachment_references), limits)
                            budget.checkpoint(
                                logical_memory_bytes=budget.conversation_memory_bytes(
                                    span.end - span.start,
                                    member_final_conversation_count,
                                )
                                + budget.attachment_plan_memory_bytes(
                                    reference_utf8_bytes=attachment_reference_utf8_bytes,
                                    reference_count=len(attachment_references),
                                    member_count=0,
                                )
                            )
                            aggregate_roles.update(role_counts)
                            aggregate_admission.update(admission_counts)
                            aggregate_unknown.update(
                                _text_sha256(value) for value in parsed.unknown_record_types
                            )
                            malformed_records += parsed.malformed_records
                            total_record_count += len(parsed.records)
                            enforce_record_count(total_record_count, limits)
                            schema_descriptors.update(parsed.schema_descriptors)
                            existing_parser_version = parser_versions.setdefault(
                                parsed.parser_name,
                                parsed.parser_version,
                            )
                            if existing_parser_version != parsed.parser_version:
                                raise RuntimeError("one parser name produced conflicting versions")
                            entries.append(
                                {
                                    "index": index,
                                    "archive_member_index": (
                                        conversation_member.archive_member_index
                                    ),
                                    "member_conversation_index": member_conversation_index,
                                    "relative_path": relative.as_posix(),
                                    "source_path": _conversation_source_path(
                                        source_system=source_system,
                                        source_account=source_account,
                                        archive_sha256=inspection.archive_sha256,
                                        conversation_id=parsed.conversation_id,
                                        digest=digest,
                                    ),
                                    "source_locator": _conversation_source_locator(
                                        archive_sha256=inspection.archive_sha256,
                                        archive_member=conversation_member.archive_member,
                                        index=member_conversation_index,
                                        span=span,
                                        digest=digest,
                                    ),
                                    "source_byte_start": span.start,
                                    "source_byte_end": span.end,
                                    "sha256": digest,
                                    "byte_length": len(raw),
                                    "conversation_id_sha256": _text_sha256(parsed.conversation_id),
                                    "branch_id_sha256": _optional_text_sha256(parsed.branch_id),
                                    "captured_at_sha256": _optional_text_sha256(parsed.captured_at),
                                    "parser_name": parsed.parser_name,
                                    "parser_version": parsed.parser_version,
                                    "schema_fingerprint": parsed.schema_fingerprint,
                                    "source_record_count": source_record_count,
                                    "record_count": len(parsed.records),
                                    "role_counts": dict(sorted(role_counts.items())),
                                    "admission_counts": dict(sorted(admission_counts.items())),
                                    "unknown_record_type_sha256s": sorted(
                                        _text_sha256(value) for value in parsed.unknown_record_types
                                    ),
                                    "malformed_records": parsed.malformed_records,
                                    "planned_ingest": bool(parsed.records),
                                }
                            )
                    finally:
                        view.release()
                after = os.fstat(handle.fileno())
            if _stat_identity(before) != _stat_identity(after):
                raise RuntimeError("export member changed while preparing the plan")

        attachment_plan_memory_bytes = budget.conversation_memory_bytes(0, len(entries)) + (
            budget.attachment_plan_memory_bytes(
                reference_utf8_bytes=attachment_reference_utf8_bytes,
                reference_count=len(attachment_references),
                member_count=len(inspection.supplemental_members),
            )
        )
        attachment_plan = _plan_attachments(
            inspection,
            attachment_references,
            archive_path=archive,
            archive_identity=archive_identity,
            source_system=source_system,
            conversation_member_indices=additional_conversation_member_indices,
            malformed_references=malformed_attachment_references,
            max_extracted_bytes=max_extracted_attachment_bytes,
            extracted_media_types=extracted_attachment_media_types,
            budget=budget,
            logical_memory_bytes=attachment_plan_memory_bytes,
        )
        _extract_planned_attachments(
            archive,
            temporary,
            inspection,
            attachment_plan.extracted_indices,
            archive_identity=archive_identity,
            budget=budget,
        )

        final_conversation_root = destination / "conversations"
        schema_fingerprint = _aggregate_web_schema_fingerprint(
            source_system,
            schema_descriptors,
        )
        schema_status = (
            "recognized"
            if not aggregate_unknown
            and malformed_records == 0
            and malformed_attachment_references == 0
            else "review_required"
        )
        archive_inspection_manifest = inspection.as_dict()
        archive_inspection_manifest["supplemental_members"] = list(attachment_plan.member_manifests)
        manifest = {
            "web_export_plan_version": WEB_EXPORT_PLAN_VERSION,
            "extractor_version": WEB_EXPORT_EXTRACTOR_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "source_system": source_system.value,
            "source_account": source_account,
            "source_capture": {
                "source_client": WEB_SOURCE_CLIENTS[source_system],
                "source_client_version": source_client_version,
                "capture_capability": WEB_EXPORT_CAPTURE_CAPABILITY,
                "adapter_name": WEB_EXPORT_ADAPTER_NAME,
                "adapter_version": WEB_SOURCE_ADAPTER_VERSIONS[source_system],
                "schema_fingerprint": schema_fingerprint,
                "parser_versions": dict(sorted(parser_versions.items())),
            },
            "code_revision": code_revision,
            "max_record_bytes": max_record_bytes,
            "scope": scope.value,
            "project_id": project_id,
            "expected_ledger_generation": expected_ledger_generation,
            "archive": {
                "path": str(archive.resolve()),
                "sha256": inspection.archive_sha256,
                "byte_length": inspection.archive_size,
                "member_name": archive_member,
            },
            "member": {
                "path": str(primary_member.path.resolve()),
                "sha256": primary_member.content_sha256,
                "byte_length": primary_member.byte_length,
            },
            "additional_members": [
                {
                    "path": str(member.path.resolve()),
                    "archive_member_index": member.archive_member_index,
                    "name_sha256": member.name_sha256,
                    "sha256": member.content_sha256,
                    "byte_length": member.byte_length,
                }
                for member in conversation_members[1:]
            ],
            "resource_limits": limits.as_dict(),
            "attachment_policy": {
                "max_extracted_attachment_bytes": max_extracted_attachment_bytes,
                "extracted_media_types": sorted(extracted_attachment_media_types),
            },
            "attachment_linkage": attachment_plan.summary,
            "archive_inspection": archive_inspection_manifest,
            "conversation_root": str(final_conversation_root.resolve()),
            "conversation_count": len(entries),
            "planned_ingest_count": sum(bool(item["planned_ingest"]) for item in entries),
            "source_record_count": total_source_record_count,
            "record_count": total_record_count,
            "role_counts": dict(sorted(aggregate_roles.items())),
            "admission_counts": dict(sorted(aggregate_admission.items())),
            "unknown_record_type_conversation_counts": dict(sorted(aggregate_unknown.items())),
            "malformed_records": malformed_records,
            "schema_status": schema_status,
            "conversations": entries,
        }
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise WebExportLimitError(
                "memory_bytes",
                "web export manifest exceeds its bounded size",
            )
        budget.add_disk_bytes(len(manifest_bytes))
        temporary_manifest = temporary / "manifest.json"
        _write_private_file(temporary_manifest, manifest_bytes)
        manifest_size, manifest_digest = _hash_file(
            temporary_manifest,
            expected_size=len(manifest_bytes),
            budget=budget,
        )
        if (manifest_size, manifest_digest) != (
            len(manifest_bytes),
            hashlib.sha256(manifest_bytes).hexdigest(),
        ):
            raise RuntimeError("web export manifest changed before publication")
        resource_usage = budget.usage()
        temporary.rename(destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    manifest_path = destination / "manifest.json"
    return {
        "status": "planned",
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_digest,
        "source_system": source_system.value,
        "source_capture": manifest["source_capture"],
        "conversation_member_count": len(conversation_members),
        "supplemental_member_count": len(inspection.supplemental_members),
        "attachment_linkage": manifest["attachment_linkage"],
        "conversation_count": len(entries),
        "planned_ingest_count": sum(bool(item["planned_ingest"]) for item in entries),
        "source_record_count": total_source_record_count,
        "record_count": total_record_count,
        "role_counts": dict(sorted(aggregate_roles.items())),
        "admission_counts": dict(sorted(aggregate_admission.items())),
        "unknown_record_type_conversation_counts": dict(sorted(aggregate_unknown.items())),
        "malformed_records": malformed_records,
        "resource_usage": resource_usage,
    }


def verify_web_export_plan(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    code_revision: str,
) -> dict[str, Any]:
    require_runtime_code_revision(code_revision)
    verified = _verify_web_export_plan(
        manifest_path=manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
        code_revision=code_revision,
    )
    return {"status": "verified", **_public_plan_summary(verified)}


def authorize_web_export_schema(
    settings: Settings,
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    code_revision: str,
    authorized_by: str,
    execute: bool,
    offline_clone: bool,
    authoritative_node: Path | None = None,
    reviewed_clone: Path | None = None,
    review_code_revision: str | None = None,
    expected_ledger_generation: str | None = None,
) -> dict[str, Any]:
    require_runtime_code_revision(code_revision)
    if authoritative_node is not None:
        if offline_clone or reviewed_clone is None or expected_ledger_generation is None:
            raise ValueError("node authorization requires an isolated review and a live generation")
        return _transfer_reviewed_web_schema(
            settings,
            authoritative_node=authoritative_node,
            reviewed_clone=reviewed_clone,
            manifest_path=manifest_path,
            expected_manifest_sha256=expected_manifest_sha256,
            code_revision=code_revision,
            review_code_revision=(
                code_revision if review_code_revision is None else review_code_revision
            ),
            expected_ledger_generation=expected_ledger_generation,
            authorized_by=authorized_by,
            execute=execute,
        )
    if any(
        value is not None
        for value in (reviewed_clone, review_code_revision, expected_ledger_generation)
    ):
        raise ValueError("review transfer arguments require an explicit authoritative node")
    verified = _verify_web_export_plan(
        manifest_path=manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
        code_revision=code_revision,
    )
    preview = {
        "status": "authorization_preview",
        "execute": execute,
        "offline_clone": offline_clone,
        "authorization_eligible": verified.manifest["schema_status"] == "recognized",
        "authorized_by": _bounded_manifest_label(authorized_by, "schema authorizer"),
        **_public_plan_summary(verified),
    }
    if not execute:
        if offline_clone:
            clone_marker = verify_offline_clone_marker(
                settings,
                expected_ledger_generation=verified.expected_ledger_generation,
            )
            preview["offline_clone_marker_sha256"] = clone_marker["marker_sha256"]
        return preview
    if verified.manifest["schema_status"] != "recognized":
        raise RuntimeError(
            "web export schema requires adapter review before standing authorization"
        )
    if not offline_clone:
        raise ValueError("web export schema authorization requires the offline-clone gate")
    if settings.data_root.expanduser().resolve() == default_data_root().resolve():
        raise ValueError("web export schema authorization is forbidden against the live data root")
    clone_marker = verify_offline_clone_marker(
        settings,
        expected_ledger_generation=verified.expected_ledger_generation,
    )
    with exclusive_ledger_writer(settings) as writer_token:
        clone_marker = verify_offline_clone_marker(
            settings,
            expected_ledger_generation=verified.expected_ledger_generation,
        )
        read_only_ledger = Ledger(settings, read_only=True, require_checkpointed=False)
        before_generation = read_only_ledger.generation_digest()
        if before_generation != verified.expected_ledger_generation:
            raise RuntimeError(
                "ledger generation does not match the schema-authorization manifest; "
                "replan required"
            )
        read_only_ledger.verify_source_account_registration(
            source_account_id=verified.source_account,
            source_system=verified.source_system,
            scope=verified.scope,
            project_id=verified.project_id,
        )
        ledger = Ledger(settings, exclusive_writer_token=writer_token)
        authorization = ledger.authorize_source_schema(
            source_account_id=verified.source_account,
            source_system=verified.source_system,
            scope=verified.scope,
            project_id=verified.project_id,
            provenance=verified.source_provenance,
            authorized_by=authorized_by,
            expected_ledger_generation=verified.expected_ledger_generation,
        )
        after_generation = ledger.generation_digest()
    return {
        **preview,
        "status": "authorized",
        "execute": True,
        "authorization": authorization,
        "previous_ledger_generation": before_generation,
        "result_ledger_generation": after_generation,
        "replan_required": after_generation != before_generation,
        "offline_clone_marker_sha256": clone_marker["marker_sha256"],
    }


def _review_json(path: Path) -> tuple[dict[str, Any], str]:
    descriptor, _ = open_regular_file_no_symlinks(path, "schema review metadata")
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077:
            raise ValueError("schema review metadata must be private")
        if before.st_nlink != 1 or before.st_size > 64 * 1024:
            raise ValueError("schema review metadata exceeds its file limits")
        data = handle.read(64 * 1024 + 1)
        if len(data) != before.st_size or any(
            _stat_identity(before) != _stat_identity(after)
            or before.st_ctime_ns != after.st_ctime_ns
            for after in (os.fstat(handle.fileno()), path.lstat())
        ):
            raise RuntimeError("schema review metadata changed while reading")
    try:
        value: object = json.loads(data, object_pairs_hook=_reject_duplicate_json_keys)
    except ValueError:
        raise ValueError("schema review metadata is not valid unique-key JSON") from None
    if not isinstance(value, dict):
        raise ValueError("schema review metadata must be an object")
    return cast(dict[str, Any], value), hashlib.sha256(data).hexdigest()


def _review_source_snapshot(
    clone: Settings, expected_generation: str, *, authorized: bool, target: Path
) -> tuple[Ledger, dict[str, Any], str]:
    marker = verify_offline_clone_marker(clone, expected_ledger_generation=expected_generation)
    loaded, digest = _review_json(clone.data_root / OFFLINE_CLONE_MARKER)
    if digest != marker["marker_sha256"]:
        raise RuntimeError("schema review clone marker changed")
    path = Path(_required_string(loaded, "source_snapshot_path"))
    if (
        not path.is_absolute()
        or path != path.resolve()
        or path.is_relative_to(target)
        or target.is_relative_to(path)
    ):
        raise ValueError("schema review snapshot must be separate from the authoritative node")
    source = Settings(path)
    _authoritative_node_identity(source)
    manifest, manifest_digest = _review_json(path / SNAPSHOT_MANIFEST)
    if manifest_digest != marker["source_snapshot_manifest_sha256"]:
        raise RuntimeError("schema review snapshot does not match the clone marker")
    entries = manifest.get("files")
    expected = {"ledger.sqlite3", WEB_SOURCE_CONFIGURATION_RECEIPT.as_posix()}
    if authorized:
        expected.add(OFFLINE_CLONE_MARKER.as_posix())
    if not isinstance(entries, list):
        raise ValueError("schema review requires a configuration-only snapshot")
    files = cast(list[object], entries)
    if len(files) != len(expected):
        raise ValueError("schema review requires a configuration-only snapshot")
    if any(not isinstance(item, dict) for item in files):
        raise ValueError("schema review snapshot entries are invalid")
    typed = cast(list[dict[str, Any]], files)
    if any(not isinstance(item.get("path"), str) for item in typed):
        raise ValueError("schema review snapshot entries are invalid")
    if (
        {item.get("path") for item in typed} != expected
        or any(
            type(item.get("size")) is not int or not 0 <= item["size"] <= 64 * 1024 * 1024
            for item in typed
        )
        or sum(item["size"] for item in typed) > 64 * 1024 * 1024
    ):
        raise ValueError("schema review snapshot exceeds its configuration boundary")
    verified = verify_snapshot(path)
    if verified["snapshot_manifest_sha256"] != manifest_digest:
        raise RuntimeError("schema review snapshot changed during verification")
    counts = cast(dict[str, int], verified["database_counts"])
    required_counts = {
        "installations": 1,
        "devices": 1,
        "source_accounts": 1,
        "source_account_policies": 1,
        "source_schema_authorizations": int(authorized),
    }
    if not required_counts.keys() <= counts.keys() or any(
        count != required_counts.get(table, 0) for table, count in counts.items()
    ):
        raise ValueError("schema review snapshot contains more than the selected registration")
    ledger = Ledger(source, read_only=True)
    if ledger.generation_digest() != expected_generation:
        raise RuntimeError("schema review snapshot generation does not match its clone")
    purpose, _ = _review_json(path / WEB_SOURCE_CONFIGURATION_RECEIPT)
    _require_exact_keys(
        purpose,
        {
            "configuration_only",
            "purpose",
            "source_account_id",
            "source_system",
            "scope",
            "project_id",
            "source_ledger_generation",
            "snapshot_ledger_generation",
        },
        "schema review purpose",
    )
    if (
        purpose["configuration_only"] is not True
        or purpose["purpose"] != "offline_web_schema_validation"
    ):
        raise ValueError("snapshot was not captured for isolated schema review")
    _required_digest(purpose, "source_ledger_generation")
    _required_digest(purpose, "snapshot_ledger_generation")
    return ledger, purpose, manifest_digest


def _verified_schema_review(
    reviewed: Settings, plan: VerifiedWebExportPlan, target: Path
) -> tuple[str, dict[str, str | None], dict[str, Any], dict[str, Any]]:
    authorization_snapshot, purpose, authorized_digest = _review_source_snapshot(
        reviewed, plan.expected_ledger_generation, authorized=True, target=target
    )
    configuration, seed_purpose, seed_digest = _review_source_snapshot(
        authorization_snapshot.settings,
        _required_digest(purpose, "snapshot_ledger_generation"),
        authorized=False,
        target=target,
    )
    clone_purpose, _ = _review_json(reviewed.data_root / WEB_SOURCE_CONFIGURATION_RECEIPT)
    if purpose != seed_purpose or purpose != clone_purpose:
        raise RuntimeError("schema review configuration lineage changed")
    identity = {
        "source_account_id": plan.source_account,
        "source_system": plan.source_system.value,
        "scope": plan.scope.value,
        "project_id": plan.project_id,
    }
    if any(purpose[key] != value for key, value in identity.items()):
        raise RuntimeError("schema review purpose does not match the manifest source")
    kwargs: _SchemaSource = {
        "source_account_id": plan.source_account,
        "source_system": plan.source_system,
        "scope": plan.scope,
        "project_id": plan.project_id,
    }
    ledger = Ledger(reviewed, read_only=True, require_checkpointed=False)
    registration = ledger.verify_source_account_registration(**kwargs)
    installation = ledger.installation_id()
    for source in (configuration, authorization_snapshot):
        if (
            source.installation_id() != installation
            or source.verify_source_account_registration(**kwargs) != registration
        ):
            raise RuntimeError("schema review source registration changed")
    grant = ledger.verify_source_schema_authorization(**kwargs, provenance=plan.source_provenance)
    if (
        authorization_snapshot.verify_source_schema_authorization(
            **kwargs, provenance=plan.source_provenance
        )
        != grant
    ):
        raise RuntimeError("schema review authorization changed after validation")
    batch = hashlib.sha256((plan.manifest_sha256 + "\n").encode()).hexdigest()
    committed = ledger.committed_web_export_receipt(batch)
    if committed is None:
        raise RuntimeError("schema transfer requires a committed isolated import")
    receipt = _verified_import_receipt(committed, [plan], [(registration, grant)], batch, None)
    _verify_published_import_receipt(
        reviewed.run_root / "private/web-export-imports" / f"{batch}.json", committed.encode()
    )
    generation = ledger.generation_digest()
    if generation != receipt["result_ledger_generation"]:
        raise RuntimeError("reviewed clone changed after its isolated import")
    return (
        installation,
        registration,
        grant,
        {
            "review_code_revision": plan.code_revision,
            "review_manifest_sha256": plan.manifest_sha256,
            "configuration_snapshot_manifest_sha256": seed_digest,
            "authorized_snapshot_manifest_sha256": authorized_digest,
            "isolated_receipt_sha256": hashlib.sha256(committed.encode()).hexdigest(),
            "reviewed_ledger_generation": generation,
        },
    )


def _transfer_reviewed_web_schema(
    settings: Settings,
    *,
    authoritative_node: Path,
    reviewed_clone: Path,
    manifest_path: Path,
    expected_manifest_sha256: str,
    code_revision: str,
    review_code_revision: str,
    expected_ledger_generation: str,
    authorized_by: str,
    execute: bool,
) -> dict[str, Any]:
    target = authoritative_node.expanduser()
    reviewed = Settings(reviewed_clone.expanduser())
    if not target.is_absolute() or target != settings.data_root.expanduser().absolute():
        raise ValueError("authoritative node must match the explicit absolute data root")
    if not reviewed.data_root.is_absolute() or reviewed.data_root != reviewed.data_root.resolve():
        raise ValueError("reviewed clone must be an explicit canonical absolute path")
    if reviewed.data_root.is_relative_to(target) or target.is_relative_to(reviewed.data_root):
        raise ValueError("reviewed clone and authoritative node must be separate")
    target_identity = _authoritative_node_identity(settings)
    review_identity = _authoritative_node_identity(reviewed)
    if target_identity[2:] == review_identity[2:]:
        raise ValueError("reviewed clone must not share the authoritative database")
    _validate_digest(expected_ledger_generation, "expected live ledger generation")
    authorizer = _bounded_manifest_label(authorized_by, "schema authorizer")
    # Revalidate old review bytes with the current parser; retain their original code identity.
    plan = _verify_web_export_plan(
        manifest_path=manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
        code_revision=review_code_revision,
    )
    if plan.manifest["schema_status"] != "recognized":
        raise RuntimeError("schema transfer requires a recognized reviewed schema")
    with ExitStack() as locks:
        writer = None
        if execute:
            for item in sorted((settings, reviewed), key=lambda item: str(item.data_root)):
                token = locks.enter_context(exclusive_ledger_writer(item))
                if item == settings:
                    writer = token
        if (
            _authoritative_node_identity(settings) != target_identity
            or _authoritative_node_identity(reviewed) != review_identity
        ):
            raise RuntimeError("schema authorization target identity changed")
        installation, registration, grant, proof = _verified_schema_review(reviewed, plan, target)
        current = Ledger(settings, read_only=True, require_checkpointed=False)
        kwargs: _SchemaSource = {
            "source_account_id": plan.source_account,
            "source_system": plan.source_system,
            "scope": plan.scope,
            "project_id": plan.project_id,
        }
        if (
            current.installation_id() != installation
            or current.verify_source_account_registration(**kwargs) != registration
        ):
            raise RuntimeError("live source identity does not match the isolated review")
        existing = current.inspect_source_schema_authorization(
            source_account_id=plan.source_account,
            authorization_id=grant["authorization_id"],
        )
        if existing is not None and existing["status"] != "active":
            raise PermissionError("source schema authorization is revoked")
        before = current.generation_digest()
        if existing is None and before != expected_ledger_generation:
            raise RuntimeError("live ledger generation changed; replan schema transfer")
        result = {
            "status": "authorization_transfer_preview",
            "execute": execute,
            "code_revision": code_revision,
            "authoritative_node": str(target),
            "source_account_id": plan.source_account,
            "authorization_id": grant["authorization_id"],
            "previous_ledger_generation": before,
            "authorization_created": False,
            "already_authorized": existing is not None,
            **proof,
        }
        if not execute:
            return result
        if existing is None:
            ledger = Ledger(settings, exclusive_writer_token=writer)
            ledger.authorize_source_schema(
                **kwargs,
                provenance=plan.source_provenance,
                authorized_by=authorizer,
                expected_ledger_generation=expected_ledger_generation,
            )
            result["authorization_created"] = True
        return {
            **result,
            "status": "authorized_authoritative",
            "replayed": existing is not None,
            "result_ledger_generation": current.generation_digest(),
        }


def revoke_web_schema_authorization(
    settings: Settings,
    *,
    authoritative_node: Path,
    source_account_id: str,
    authorization_id: str,
    expected_ledger_generation: str,
    code_revision: str,
    execute: bool,
) -> dict[str, Any]:
    require_runtime_code_revision(code_revision)
    target = authoritative_node.expanduser()
    if not target.is_absolute() or target != settings.data_root.expanduser().absolute():
        raise ValueError("schema revocation requires an explicit absolute authoritative node")
    identity = _authoritative_node_identity(settings)
    _validate_digest(expected_ledger_generation, "expected live ledger generation")
    current = Ledger(settings, read_only=True, require_checkpointed=False)
    grant = current.inspect_source_schema_authorization(
        source_account_id=source_account_id, authorization_id=authorization_id
    )
    if grant is None:
        raise PermissionError("source schema authorization not found for exact account")
    before = current.generation_digest()
    result = {
        "status": "schema_revocation_preview",
        "execute": execute,
        "source_account_id": source_account_id,
        "authorization_id": authorization_id,
        "authorization_status": grant["status"],
        "current_ledger_generation": before,
    }
    if not execute:
        if grant["status"] == "active" and before != expected_ledger_generation:
            raise RuntimeError("live ledger generation changed; replan schema revocation")
        return result
    with exclusive_ledger_writer(settings) as writer:
        if _authoritative_node_identity(settings) != identity:
            raise RuntimeError("schema revocation target identity changed")
        return {
            "status": "schema_authorization_revoked",
            "execute": True,
            **Ledger(settings, exclusive_writer_token=writer).revoke_source_schema_authorization(
                source_account_id=source_account_id,
                authorization_id=authorization_id,
                expected_ledger_generation=expected_ledger_generation,
            ),
        }


def apply_web_export_plans(
    settings: Settings,
    *,
    manifest_paths: list[Path],
    expected_manifest_sha256s: list[str],
    code_revision: str,
    execute: bool,
    offline_clone: bool,
    authoritative_node: Path | None = None,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    evidence_publication_policy: EvidencePublicationPolicy | None = None,
) -> dict[str, Any]:
    require_runtime_code_revision(code_revision)
    if authoritative_node is not None:
        authoritative_node = authoritative_node.expanduser()
        if offline_clone:
            raise ValueError("select either an offline-clone or an authoritative node, not both")
        if not authoritative_node.is_absolute():
            raise ValueError("authoritative node must be an explicit absolute data-root path")
        if authoritative_node.absolute() != settings.data_root.expanduser().absolute():
            raise ValueError("authoritative node does not match the selected data root")
    if not manifest_paths:
        raise ValueError("at least one web export manifest is required")
    if len(manifest_paths) > MAX_WEB_EXPORT_BATCH_PLANS:
        raise ValueError(
            f"web export batches support at most {MAX_WEB_EXPORT_BATCH_PLANS} manifests"
        )
    if len(manifest_paths) != len(expected_manifest_sha256s):
        raise ValueError("each web export manifest requires one approved SHA-256 digest")
    if len(set(expected_manifest_sha256s)) != len(expected_manifest_sha256s):
        raise ValueError("web export manifest digests must be unique")

    verified_plans = [
        _verify_web_export_plan(
            manifest_path=manifest_path,
            expected_manifest_sha256=manifest_sha256,
            code_revision=code_revision,
        )
        for manifest_path, manifest_sha256 in zip(
            manifest_paths, expected_manifest_sha256s, strict=True
        )
    ]
    source_keys = [(item.source_system.value, item.source_account) for item in verified_plans]
    if len(set(source_keys)) != len(source_keys):
        raise ValueError("a web export batch cannot repeat a source system and account")
    expected_generations = {item.expected_ledger_generation for item in verified_plans}
    if len(expected_generations) != 1:
        raise ValueError("every web export manifest in a batch must bind the same ledger state")
    expected_generation = next(iter(expected_generations))

    batch_digest = hashlib.sha256(
        ("\n".join(item.manifest_sha256 for item in verified_plans) + "\n").encode()
    ).hexdigest()
    preview = {
        "status": "preview",
        "execute": execute,
        "offline_clone": offline_clone,
        **({"authoritative_node": str(authoritative_node)} if authoritative_node else {}),
        "batch_approval_sha256": batch_digest,
        "expected_ledger_generation": expected_generation,
        "manifest_count": len(verified_plans),
        "planned_source_files": sum(
            cast(int, item.manifest["planned_ingest_count"]) for item in verified_plans
        ),
        "parsed_records": sum(cast(int, item.manifest["record_count"]) for item in verified_plans),
        "accepted_records": sum(
            _manifest_admission_count(item.manifest, "included") for item in verified_plans
        ),
        "quarantined_records": sum(
            _manifest_quarantine_count(item.manifest) for item in verified_plans
        ),
        "plans": [_public_plan_summary(item) for item in verified_plans],
    }
    if not execute:
        return preview
    publication_binding = None
    if evidence_publication_policy is not None:
        if encrypted_evidence_reader is None:
            raise ValueError("web export publication requires explicit encrypted evidence access")
        publication_binding = {
            "backend_identity_sha256": encrypted_evidence_reader.backend.identity_sha256,
            "root_key_sha256": publication_key_sha256(encrypted_evidence_reader),
        }
    if any(item.manifest["schema_status"] != "recognized" for item in verified_plans):
        raise RuntimeError("web export schema requires adapter review before execution")
    target_identity = None
    clone_marker = None
    if authoritative_node is not None:
        target_identity = _authoritative_node_identity(settings)
    else:
        if not offline_clone:
            raise ValueError(
                "web export execution requires --offline-clone or an explicit --authoritative-node"
            )
        if settings.data_root.expanduser().resolve() == default_data_root().resolve():
            raise ValueError("web export execution is forbidden against the default live data root")
        clone_marker = verify_offline_clone_marker(
            settings, expected_ledger_generation=expected_generation
        )
    receipt_path = settings.run_root / "private" / "web-export-imports" / f"{batch_digest}.json"
    planned_objects = max(
        1,
        sum(
            _manifest_admission_count(item.manifest, "included") + len(item.attachment_paths)
            for item in verified_plans
        ),
    )
    write_scope = ObjectWriteScope(
        operation_sha256=batch_digest,
        binding_sha256=hashlib.sha256(
            json.dumps(publication_binding, sort_keys=True).encode()
        ).hexdigest(),
        max_objects=min(planned_objects, evidence_publication_policy.max_pending_objects)
        if evidence_publication_policy
        else planned_objects,
        max_bytes=min(
            DEFAULT_WEB_EXPORT_LIMITS.max_temp_disk_bytes,
            evidence_publication_policy.max_pending_bytes,
        )
        if evidence_publication_policy
        else DEFAULT_WEB_EXPORT_LIMITS.max_temp_disk_bytes,
    )
    publication_error = False
    with exclusive_ledger_writer(settings) as writer_token:
        if authoritative_node is not None:
            if _authoritative_node_identity(settings) != target_identity:
                raise RuntimeError("authoritative node identity changed before execution")
        else:
            clone_marker = verify_offline_clone_marker(
                settings, expected_ledger_generation=expected_generation
            )
        read_only_ledger = Ledger(
            settings,
            read_only=True,
            require_checkpointed=False,
            encrypted_evidence_reader=encrypted_evidence_reader,
        )
        source_authorizations: list[tuple[dict[str, str | None], dict[str, Any]]] = []
        for item in verified_plans:
            registration = read_only_ledger.verify_source_account_registration(
                source_account_id=item.source_account,
                source_system=item.source_system,
                scope=item.scope,
                project_id=item.project_id,
            )
            schema_authorization = read_only_ledger.verify_source_schema_authorization(
                source_account_id=item.source_account,
                source_system=item.source_system,
                scope=item.scope,
                project_id=item.project_id,
                provenance=item.source_provenance,
            )
            source_authorizations.append((registration, schema_authorization))
        before = read_only_ledger.status()
        stored_receipt = read_only_ledger.committed_web_export_receipt(batch_digest)
        replayed = stored_receipt is not None
        if stored_receipt is None:
            if receipt_path.exists() or receipt_path.is_symlink():
                raise ValueError("web export receipt has no committed batch outcome")
            if before["generation_digest"] != expected_generation:
                raise RuntimeError(
                    "selected ledger generation does not match the approved manifests; "
                    "replan required"
                )
            ledger = Ledger(
                settings,
                exclusive_writer_token=writer_token,
                encrypted_evidence_reader=encrypted_evidence_reader,
                evidence_publication_policy=evidence_publication_policy,
                object_write_scope=write_scope,
            )
            try:
                receipt_json = _admit_web_export_plans(
                    ledger,
                    verified_plans,
                    source_authorizations,
                    before,
                    batch_digest,
                    code_revision,
                    expected_generation,
                    publication_binding,
                )
            except EvidencePublicationPending as error:
                raise EvidencePublicationPending(
                    f"{error}; web admission did not commit. Inspect evidence-publish; finish "
                    "previously admitted publication with evidence-publish --execute, then "
                    "regenerate plans against the current generation. An empty queue cannot "
                    "make a batch larger than its configured limits fit."
                ) from error
        else:
            receipt_json = stored_receipt
        receipt = _verified_import_receipt(
            receipt_json, verified_plans, source_authorizations, batch_digest, publication_binding
        )
        receipt_bytes = receipt_json.encode()
        receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
        if receipt_path.exists() or receipt_path.is_symlink():
            _verify_published_import_receipt(receipt_path, receipt_bytes)
        finisher = Ledger(
            settings,
            exclusive_writer_token=writer_token,
            encrypted_evidence_reader=encrypted_evidence_reader,
            evidence_publication_policy=evidence_publication_policy,
            object_write_scope=write_scope,
        )
        finisher.finish_object_write_attempt()
        current_generation = (
            before["generation_digest"] if replayed else receipt["result_ledger_generation"]
        )
        publication: dict[str, Any] = {"mode": "not_configured", "status": "not_requested"}
        if evidence_publication_policy is not None:
            publisher = Ledger(
                settings,
                exclusive_writer_token=writer_token,
                encrypted_evidence_reader=encrypted_evidence_reader,
                evidence_publication_policy=evidence_publication_policy,
            )
            try:
                publication = {
                    "mode": "remote-primary",
                    "status": "complete",
                    **publisher.drain_evidence_publications(),
                }
            except EvidencePublicationPending:
                publication_error = True
            current_generation = publisher.generation_digest()
        response = {
            **preview,
            "status": "applied_authoritative" if authoritative_node else "applied_offline",
            "execute": True,
            "replayed": replayed,
            "source_observations": receipt["source_observations"],
            "new_source_files": receipt["new_source_files"],
            "existing_source_files": receipt["existing_source_files"],
            "inserted_events": receipt["inserted_events"],
            "reconciled_events": receipt["reconciled_events"],
            "observed_quarantined_records": receipt["observed_quarantined_records"],
            "new_quarantined_records": receipt["new_quarantined_records"],
            "result_ledger_generation": receipt["result_ledger_generation"],
            "current_ledger_generation": current_generation,
            "evidence_publication": publication,
            "receipt_path": str(receipt_path),
            "receipt_sha256": receipt_sha256,
            **(
                {
                    "offline_clone_marker_sha256": clone_marker["marker_sha256"],
                    "source_snapshot_manifest_sha256": clone_marker[
                        "source_snapshot_manifest_sha256"
                    ],
                }
                if clone_marker is not None
                else {}
            ),
        }
    _publish_import_receipt(receipt_path, receipt_bytes)
    if publication_error:
        raise EvidencePublicationPending(
            "web export admission committed; encrypted evidence publication is pending; "
            "retry the same command with its retained evidence configuration"
        )
    return response


def _authoritative_node_identity(settings: Settings) -> tuple[int, int, int, int]:
    descriptor = open_directory_no_symlinks(settings.data_root, "authoritative node root")
    try:
        root = os.fstat(descriptor)
        if root.st_uid != os.geteuid() or stat.S_IMODE(root.st_mode) != 0o700:
            raise ValueError("authoritative node root must be owned and private")
        database = secure_path_stat(settings.database_path, "authoritative node database")
        if (
            database.st_uid != os.geteuid()
            or database.st_nlink != 1
            or stat.S_IMODE(database.st_mode) != 0o600
        ):
            raise ValueError("authoritative node database must be owned, private and single-link")
        return root.st_dev, root.st_ino, database.st_dev, database.st_ino
    finally:
        os.close(descriptor)


def _admit_web_export_plans(
    ledger: Ledger,
    verified_plans: list[VerifiedWebExportPlan],
    source_authorizations: list[tuple[dict[str, str | None], dict[str, Any]]],
    before: dict[str, Any],
    batch_digest: str,
    code_revision: str,
    expected_generation: str,
    publication_binding: dict[str, str] | None,
) -> str:
    inserted_events = 0
    reconciled_events = 0
    observed_quarantined_records = 0
    new_quarantined_records = 0
    source_observations = 0
    new_source_files = 0
    existing_source_files = 0
    new_batches = 0
    existing_batches = 0
    per_source: list[dict[str, Any]] = []
    with ledger.web_export_transaction(expected_generation=expected_generation):
        for verified, authorization_pair in zip(
            verified_plans,
            source_authorizations,
            strict=True,
        ):
            registration, schema_authorization = authorization_pair
            batch = ledger.register_web_export_batch(
                source_account_id=verified.source_account,
                source_system=verified.source_system,
                scope=verified.scope,
                project_id=verified.project_id,
                source_provenance=verified.source_provenance,
                batch_provenance=verified.batch_provenance,
                archive_path=verified.archive_path,
                selected_member_path=verified.member_path,
                conversation_ids=tuple(item.conversation_id for item in verified.conversations),
                attachment_paths=verified.attachment_paths,
                defer_attachment_objects=True,
            )
            new_batches += int(cast(bool, batch["inserted"]))
            existing_batches += int(not cast(bool, batch["inserted"]))
            source_inserted = 0
            source_reconciled = 0
            source_observed_quarantined = 0
            source_new_quarantined = 0
            source_observation_count = 0
            source_new_files = 0
            source_existing_files = 0
            source_erased_records = 0
            for conversation in verified.conversations:
                if not conversation.planned_ingest:
                    continue
                if conversation.path.stat().st_size != conversation.byte_length:
                    raise RuntimeError(
                        "conversation split no longer matches its approved byte length"
                    )
                parsed = parse_file(
                    conversation.path,
                    verified.source_system,
                    max_file_bytes=conversation.byte_length,
                )
                _verify_parsed_file_binding(conversation.entry, parsed)
                _verify_entry_parse(
                    conversation.entry,
                    parsed,
                    max_record_bytes=verified.max_record_bytes,
                )
                report = ledger.ingest(
                    parsed,
                    source_account=verified.source_account,
                    scope=verified.scope,
                    project_id=verified.project_id,
                    source_path=conversation.source_path,
                    max_record_bytes=verified.max_record_bytes,
                    require_registered_source_account=True,
                    required_source_schema_provenance=verified.source_provenance,
                    web_export_observation=WebExportConversationObservation(
                        batch_id=cast(str, batch["batch_id"]),
                        conversation_index=conversation.conversation_index,
                        source_byte_start=conversation.source_byte_start,
                        source_byte_end=conversation.source_byte_end,
                        conversation_sha256=conversation.conversation_sha256,
                        source_locator=conversation.source_locator,
                    ),
                )
                if report.status not in {"ingested", "already_ingested"}:
                    raise RuntimeError("web export ingestion returned an unsupported status")
                source_observation_count += 1
                source_inserted += report.inserted_events
                source_reconciled += report.existing_events
                source_observed_quarantined += report.quarantined_records
                source_erased_records += report.quarantine_reasons.get("no_memory_tombstone", 0)
                if report.status == "ingested":
                    source_new_files += 1
                    source_new_quarantined += report.quarantined_records
                else:
                    source_existing_files += 1

            # Attachment eligibility is now backed by the admitted message observations.
            ledger.register_web_export_batch(
                source_account_id=verified.source_account,
                source_system=verified.source_system,
                scope=verified.scope,
                project_id=verified.project_id,
                source_provenance=verified.source_provenance,
                batch_provenance=verified.batch_provenance,
                archive_path=verified.archive_path,
                selected_member_path=verified.member_path,
                conversation_ids=tuple(item.conversation_id for item in verified.conversations),
                attachment_paths=verified.attachment_paths,
            )
            expected_accepted = (
                _manifest_admission_count(verified.manifest, "included") - source_erased_records
            )
            expected_quarantined = (
                _manifest_quarantine_count(verified.manifest) + source_erased_records
            )
            if source_observation_count != cast(int, verified.manifest["planned_ingest_count"]):
                raise RuntimeError("web export source-observation count changed during execution")
            if source_inserted + source_reconciled != expected_accepted:
                raise RuntimeError("web export accepted-record count changed during execution")
            if source_observed_quarantined != expected_quarantined:
                raise RuntimeError("web export quarantine count changed during execution")
            inserted_events += source_inserted
            reconciled_events += source_reconciled
            observed_quarantined_records += source_observed_quarantined
            new_quarantined_records += source_new_quarantined
            source_observations += source_observation_count
            new_source_files += source_new_files
            existing_source_files += source_existing_files
            per_source.append(
                {
                    "source_system": verified.source_system.value,
                    "source_account": verified.source_account,
                    "source_device_id": registration["device_id"],
                    "schema_authorization_id": schema_authorization["authorization_id"],
                    "batch_id": batch["batch_id"],
                    "batch_inserted": batch["inserted"],
                    "manifest_sha256": verified.manifest_sha256,
                    "source_observations": source_observation_count,
                    "new_source_files": source_new_files,
                    "existing_source_files": source_existing_files,
                    "inserted_events": source_inserted,
                    "reconciled_events": source_reconciled,
                    "observed_quarantined_records": source_observed_quarantined,
                    "new_quarantined_records": source_new_quarantined,
                }
            )

        after = ledger.web_export_status()
        source_file_delta = cast(int, after["source_files"]) - cast(int, before["source_files"])
        if source_file_delta != new_source_files:
            raise RuntimeError("offline ledger source-file delta does not match the approved batch")
        if cast(int, after["events"]) - cast(int, before["events"]) != inserted_events:
            raise RuntimeError("offline ledger event delta does not match the approved batch")
        if (
            cast(int, after["quarantined_records"]) - cast(int, before["quarantined_records"])
            != new_quarantined_records
        ):
            raise RuntimeError("offline ledger quarantine delta does not match the approved batch")

        receipt = {
            "web_export_receipt_version": WEB_EXPORT_RECEIPT_VERSION,
            "publication_binding": publication_binding,
            "created_at": datetime.now(UTC).isoformat(),
            "batch_approval_sha256": batch_digest,
            "code_revision": code_revision,
            "expected_ledger_generation": expected_generation,
            "result_ledger_generation": after["generation_digest"],
            "source_observations": source_observations,
            "new_source_files": new_source_files,
            "existing_source_files": existing_source_files,
            "inserted_events": inserted_events,
            "reconciled_events": reconciled_events,
            "observed_quarantined_records": observed_quarantined_records,
            "new_quarantined_records": new_quarantined_records,
            "new_batches": new_batches,
            "existing_batches": existing_batches,
            "sources": per_source,
        }
        receipt_json = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        _verified_import_receipt(
            receipt_json, verified_plans, source_authorizations, batch_digest, publication_binding
        )
        ledger.record_web_export_receipt(batch_sha256=batch_digest, receipt_json=receipt_json)
    return receipt_json


def _verified_import_receipt(
    serialized: str,
    plans: list[VerifiedWebExportPlan],
    authorizations: list[tuple[dict[str, str | None], dict[str, Any]]],
    batch_digest: str,
    publication_binding: dict[str, str] | None,
) -> dict[str, Any]:
    if len(serialized.encode()) > MAX_WEB_EXPORT_RECEIPT_BYTES:
        raise RuntimeError("committed web export receipt exceeds its size limit")
    loaded: object = json.loads(serialized)
    if not isinstance(loaded, dict):
        raise RuntimeError("committed web export receipt must be an object")
    receipt = cast(dict[str, Any], loaded)
    expected_keys = set(_IMPORT_RECEIPT_COUNTS) | {
        "web_export_receipt_version",
        "created_at",
        "batch_approval_sha256",
        "code_revision",
        "expected_ledger_generation",
        "result_ledger_generation",
        "sources",
        "publication_binding",
    }
    if set(receipt) != expected_keys or (
        type(receipt["web_export_receipt_version"]) is not int
        or receipt["web_export_receipt_version"] != WEB_EXPORT_RECEIPT_VERSION
        or receipt["batch_approval_sha256"] != batch_digest
        or receipt["code_revision"] != plans[0].code_revision
        or receipt["expected_ledger_generation"] != plans[0].expected_ledger_generation
    ):
        raise RuntimeError("committed web export receipt does not match this operation")
    if receipt["publication_binding"] != publication_binding:
        raise RuntimeError("committed web export publication configuration changed")
    _validate_digest(_required_string(receipt, "result_ledger_generation"), "receipt generation")
    timestamp = _required_string(receipt, "created_at")
    if len(timestamp) > 64 or datetime.fromisoformat(timestamp).tzinfo is None:
        raise RuntimeError("committed web export receipt timestamp is invalid")
    sources = receipt["sources"]
    if not isinstance(sources, list) or len(cast(list[object], sources)) != len(plans):
        raise RuntimeError("committed web export receipt source count is invalid")
    source_counts = _IMPORT_RECEIPT_COUNTS[:7]
    for source, plan, (registration, authorization) in zip(
        cast(list[object], sources), plans, authorizations, strict=True
    ):
        if not isinstance(source, dict):
            raise RuntimeError("committed web export source receipt is invalid")
        item = cast(dict[str, Any], source)
        identity = {
            "source_system": plan.source_system.value,
            "source_account": plan.source_account,
            "source_device_id": registration["device_id"],
            "schema_authorization_id": authorization["authorization_id"],
            "manifest_sha256": plan.manifest_sha256,
        }
        if set(item) != set(identity) | set(source_counts) | {"batch_id", "batch_inserted"}:
            raise RuntimeError("committed web export source receipt fields are invalid")
        if any(item[key] != value for key, value in identity.items()):
            raise RuntimeError("committed web export receipt source authorization changed")
        if (
            not isinstance(item["batch_id"], str)
            or re.fullmatch(r"web_export_batch:[0-9a-f]{64}", item["batch_id"]) is None
            or not isinstance(item["batch_inserted"], bool)
        ):
            raise RuntimeError("committed web export batch identity is invalid")
        for key in source_counts:
            if type(item[key]) is not int or not 0 <= item[key] < 2**63:
                raise RuntimeError("committed web export source counts are invalid")
        if (
            item["source_observations"] != plan.manifest["planned_ingest_count"]
            or item["new_source_files"] + item["existing_source_files"]
            != item["source_observations"]
        ):
            raise RuntimeError("committed web export source observations are inconsistent")
    typed_sources = cast(list[dict[str, Any]], sources)
    totals = {key: sum(item[key] for item in typed_sources) for key in source_counts}
    totals["new_batches"] = sum(item["batch_inserted"] for item in typed_sources)
    totals["existing_batches"] = len(plans) - totals["new_batches"]
    for key in _IMPORT_RECEIPT_COUNTS:
        if type(receipt[key]) is not int or receipt[key] != totals[key]:
            raise RuntimeError("committed web export receipt totals are inconsistent")
    if serialized != json.dumps(receipt, indent=2, sort_keys=True) + "\n":
        raise RuntimeError("committed web export receipt encoding is invalid")
    return receipt


def _verify_published_import_receipt(path: Path, data: bytes) -> None:
    _regular_file(path, "web export receipt")
    _require_private_file(path, "web export receipt")
    if _read_stable_file(path, max_bytes=MAX_WEB_EXPORT_RECEIPT_BYTES) != data:
        raise RuntimeError("web export receipt conflicts with its committed outcome")


def _publish_import_receipt(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        _verify_published_import_receipt(path, data)
    else:
        try:
            _publish_private_file(path, data)
        except ValueError:
            # Another retry may have published the same committed outcome after writer teardown.
            if not path.exists() and not path.is_symlink():
                raise
            _verify_published_import_receipt(path, data)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_web_export_plan(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    code_revision: str,
) -> VerifiedWebExportPlan:
    _validate_digest(expected_manifest_sha256, "approved manifest SHA-256")
    _validate_code_revision(code_revision)
    path = _regular_file(manifest_path, "web export manifest")
    _require_private_file(path, "web export manifest")
    manifest_bytes = _read_stable_file(path, max_bytes=MAX_MANIFEST_BYTES)
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_digest != expected_manifest_sha256:
        raise RuntimeError("web export manifest does not match the approved SHA-256")
    manifest_budget = ResourceBudget(DEFAULT_WEB_EXPORT_LIMITS)
    manifest_budget.checkpoint(
        logical_memory_bytes=manifest_budget.conversation_memory_bytes(
            len(manifest_bytes),
            0,
        )
    )
    validate_json_limits(
        manifest_bytes,
        max_depth=DEFAULT_WEB_EXPORT_LIMITS.max_json_depth,
        max_string_bytes=DEFAULT_WEB_EXPORT_LIMITS.max_json_string_bytes,
        budget=manifest_budget,
    )
    loaded: object = json.loads(
        manifest_bytes,
        object_pairs_hook=_reject_duplicate_json_keys,
    )
    manifest_budget.checkpoint()
    if not isinstance(loaded, dict):
        raise ValueError("web export manifest must contain a JSON object")
    manifest = cast(dict[str, Any], loaded)
    _require_exact_keys(
        manifest,
        {
            "web_export_plan_version",
            "extractor_version",
            "created_at",
            "source_system",
            "source_account",
            "source_capture",
            "code_revision",
            "max_record_bytes",
            "scope",
            "project_id",
            "expected_ledger_generation",
            "archive",
            "member",
            "additional_members",
            "resource_limits",
            "attachment_policy",
            "attachment_linkage",
            "archive_inspection",
            "conversation_root",
            "conversation_count",
            "planned_ingest_count",
            "source_record_count",
            "record_count",
            "role_counts",
            "admission_counts",
            "unknown_record_type_conversation_counts",
            "malformed_records",
            "schema_status",
            "conversations",
        },
        "web export manifest",
    )
    if manifest.get("web_export_plan_version") != WEB_EXPORT_PLAN_VERSION:
        raise ValueError("unsupported web export plan version")
    if manifest.get("extractor_version") != WEB_EXPORT_EXTRACTOR_VERSION:
        raise ValueError("web export extractor version does not match this code")
    if _required_string(manifest, "code_revision") != code_revision:
        raise RuntimeError("web export manifest code revision does not match this checkout")

    source_system = SourceSystem(_required_string(manifest, "source_system"))
    if source_system not in WEB_SOURCE_SYSTEMS:
        raise ValueError("web export manifest names a non-web source system")
    source_account = _required_string(manifest, "source_account")
    source_capture = _required_object(manifest, "source_capture")
    _require_exact_keys(
        source_capture,
        {
            "source_client",
            "source_client_version",
            "capture_capability",
            "adapter_name",
            "adapter_version",
            "schema_fingerprint",
            "parser_versions",
        },
        "web export source capture",
    )
    if _required_string(source_capture, "source_client") != WEB_SOURCE_CLIENTS[source_system]:
        raise ValueError("web export source client does not match its source system")
    _bounded_manifest_label(
        _required_string(source_capture, "source_client_version"),
        "source client version",
    )
    if _required_string(source_capture, "capture_capability") != WEB_EXPORT_CAPTURE_CAPABILITY:
        raise ValueError("web export capture capability does not match this workflow")
    if _required_string(source_capture, "adapter_name") != WEB_EXPORT_ADAPTER_NAME:
        raise ValueError("web export adapter name does not match this code")
    if (
        _required_string(source_capture, "adapter_version")
        != WEB_SOURCE_ADAPTER_VERSIONS[source_system]
    ):
        raise ValueError("web export adapter version does not match this code")
    expected_schema_fingerprint = _required_digest(source_capture, "schema_fingerprint")
    expected_parser_versions = _required_string_map(source_capture, "parser_versions")
    source_provenance = SourceSchemaProvenance(
        source_client=_required_string(source_capture, "source_client"),
        source_client_version=_required_string(source_capture, "source_client_version"),
        capture_capability=_required_string(source_capture, "capture_capability"),
        adapter_name=_required_string(source_capture, "adapter_name"),
        adapter_version=_required_string(source_capture, "adapter_version"),
        schema_fingerprint=expected_schema_fingerprint,
        parser_versions=tuple(sorted(expected_parser_versions.items())),
    )
    scope = Scope(_required_string(manifest, "scope"))
    project_id = _optional_string(manifest.get("project_id"))
    if scope is Scope.PROJECT and not project_id:
        raise ValueError("project-scoped web exports require project_id")
    if scope is not Scope.PROJECT and project_id is not None:
        raise ValueError("only project-scoped web exports may carry project_id")
    expected_generation = _required_digest(manifest, "expected_ledger_generation")
    max_record_bytes = _required_positive_int(manifest, "max_record_bytes")
    limits = limits_from_dict(manifest.get("resource_limits"))
    attachment_policy = _required_object(manifest, "attachment_policy")
    _require_exact_keys(
        attachment_policy,
        {"max_extracted_attachment_bytes", "extracted_media_types"},
        "web export attachment policy",
    )
    max_extracted_attachment_bytes = _required_positive_int(
        attachment_policy,
        "max_extracted_attachment_bytes",
    )
    if max_extracted_attachment_bytes > limits.max_member_uncompressed_bytes:
        raise ValueError("attachment extraction limit exceeds the archive member limit")
    media_types_value = attachment_policy.get("extracted_media_types")
    if not isinstance(media_types_value, list) or not media_types_value:
        raise ValueError("attachment extraction media types must be a non-empty array")
    extracted_media_types_list: list[str] = []
    for value in cast(list[object], media_types_value):
        if not isinstance(value, str) or not value or len(value) > 127:
            raise ValueError("attachment extraction media types are invalid")
        extracted_media_types_list.append(value)
    if extracted_media_types_list != sorted(set(extracted_media_types_list)):
        raise ValueError("attachment extraction media types must be unique and sorted")
    extracted_media_types = frozenset(extracted_media_types_list)
    budget = ResourceBudget(limits)
    budget.add_disk_bytes(len(manifest_bytes))

    archive_manifest = _required_object(manifest, "archive")
    member_manifest = _required_object(manifest, "member")
    _require_exact_keys(
        archive_manifest,
        {"path", "sha256", "byte_length", "member_name"},
        "web export archive manifest",
    )
    _require_exact_keys(
        member_manifest,
        {"path", "sha256", "byte_length"},
        "web export member manifest",
    )
    archive_path = _absolute_regular_file(archive_manifest, "path", "export archive")
    archive_identity = _stat_identity(archive_path.lstat())
    member_path = _absolute_regular_file(member_manifest, "path", "export member")
    _require_private_file(archive_path, "export archive")
    _require_private_file(member_path, "export member")
    archive_member = _required_string(archive_manifest, "member_name")
    additional_value = manifest.get("additional_members")
    if not isinstance(additional_value, list):
        raise ValueError("web export additional members must be an array")
    additional_manifests: list[dict[str, Any]] = []
    additional_archive_member_indices: list[int] = []
    for item in cast(list[object], additional_value):
        if not isinstance(item, dict):
            raise ValueError("web export additional member must be an object")
        additional_manifest = cast(dict[str, Any], item)
        _require_exact_keys(
            additional_manifest,
            {
                "path",
                "archive_member_index",
                "name_sha256",
                "sha256",
                "byte_length",
            },
            "web export additional member manifest",
        )
        additional_manifests.append(additional_manifest)
        additional_archive_member_indices.append(
            _required_int(additional_manifest, "archive_member_index")
        )
    if len(set(additional_archive_member_indices)) != len(additional_archive_member_indices):
        raise ValueError("additional conversation member indices must be unique")
    inspection = inspect_zip_archive(
        archive_path,
        archive_member,
        limits=limits,
        budget=budget,
        additional_conversation_member_indices=frozenset(additional_archive_member_indices),
    )
    supplemental_by_index = {
        member.archive_member_index: member for member in inspection.supplemental_members
    }
    additional_paths: list[Path] = []
    additional_archive_members: list[str] = []
    for additional_manifest in additional_manifests:
        archive_member_index = _required_int(
            additional_manifest,
            "archive_member_index",
        )
        supplemental = supplemental_by_index.get(archive_member_index)
        if supplemental is None:
            raise RuntimeError("additional conversation member moved within the archive")
        if _required_digest(additional_manifest, "name_sha256") != supplemental.name_sha256:
            raise RuntimeError("additional conversation member name changed")
        additional_path = _absolute_regular_file(
            additional_manifest,
            "path",
            "additional export member",
        )
        _require_private_file(additional_path, "additional export member")
        additional_paths.append(additional_path)
        additional_archive_members.append(supplemental.member_name)

    conversation_members = _resolve_conversation_members(
        source_system=source_system,
        primary_path=member_path,
        primary_archive_member=archive_member,
        additional_paths=tuple(additional_paths),
        additional_archive_members=tuple(additional_archive_members),
        inspection=inspection,
        budget=budget,
    )
    primary_member = conversation_members[0]
    additional_conversation_member_indices = frozenset(
        member.archive_member_index for member in conversation_members[1:]
    )
    _verify_file_manifest(
        archive_manifest,
        actual_size=inspection.archive_size,
        actual_digest=inspection.archive_sha256,
        label="export archive",
    )
    _verify_file_manifest(
        member_manifest,
        actual_size=primary_member.byte_length,
        actual_digest=primary_member.content_sha256,
        label="export member",
    )
    for additional_manifest, conversation_member in zip(
        additional_manifests,
        conversation_members[1:],
        strict=True,
    ):
        if (
            _required_int(additional_manifest, "archive_member_index")
            != conversation_member.archive_member_index
        ):
            raise RuntimeError("additional conversation member index changed")
        _verify_file_manifest(
            additional_manifest,
            actual_size=conversation_member.byte_length,
            actual_digest=conversation_member.content_sha256,
            label="additional export member",
        )
    budget.add_disk_bytes(
        inspection.archive_size + sum(member.byte_length for member in conversation_members)
    )

    root = path.parent.resolve()
    _require_private_directory(root, "web export plan root")
    conversation_root = Path(_required_string(manifest, "conversation_root"))
    expected_conversation_root = root / "conversations"
    if (
        not conversation_root.is_absolute()
        or conversation_root.resolve() != expected_conversation_root
    ):
        raise RuntimeError("web export conversation root moved after planning")
    _require_private_directory(expected_conversation_root, "conversation split root")
    entries_value = manifest.get("conversations")
    if not isinstance(entries_value, list):
        raise ValueError("web export conversations must be an array")
    entries = cast(list[object], entries_value)

    aggregate_roles: Counter[str] = Counter()
    aggregate_admission: Counter[str] = Counter()
    aggregate_unknown: Counter[str] = Counter()
    malformed_records = 0
    record_count = 0
    source_record_count = 0
    planned_ingest_count = 0
    verified_conversations: list[VerifiedConversation] = []
    expected_files = {"manifest.json"}
    schema_descriptors: set[str] = set()
    parser_versions: dict[str, str] = {}
    attachment_references: list[_AttachmentReference] = []
    attachment_reference_utf8_bytes = 0
    malformed_attachment_references = 0

    entry_index = 0
    for conversation_member in conversation_members:
        descriptor = os.open(
            conversation_member.path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                view = memoryview(mapped)
                try:
                    if (
                        len(view) != conversation_member.byte_length
                        or _hash_view(view, budget) != conversation_member.content_sha256
                    ):
                        raise RuntimeError("export member changed before split verification")
                    validate_json_limits(
                        view,
                        max_depth=limits.max_json_depth,
                        max_string_bytes=limits.max_json_string_bytes,
                        budget=budget,
                    )
                    remaining_records = limits.max_record_count - entry_index
                    span_limit = min(
                        remaining_records + 1,
                        budget.conversation_span_limit(),
                    )
                    spans = _conversation_spans(
                        view,
                        source_system,
                        max_records=span_limit,
                        limit_code=(
                            "memory_bytes" if span_limit < remaining_records + 1 else "record_count"
                        ),
                    )
                    enforce_record_count(entry_index + len(spans), limits)
                    if entry_index + len(spans) > len(entries):
                        raise RuntimeError("web export conversation count changed after planning")
                    for member_conversation_index, span in enumerate(spans):
                        index = entry_index
                        entry_value = entries[index]
                        entry_index += 1
                        if not isinstance(entry_value, dict):
                            raise ValueError("web export conversation entry must be an object")
                        entry = cast(dict[str, Any], entry_value)
                        _require_exact_keys(
                            entry,
                            {
                                "index",
                                "archive_member_index",
                                "member_conversation_index",
                                "relative_path",
                                "source_path",
                                "source_locator",
                                "source_byte_start",
                                "source_byte_end",
                                "sha256",
                                "byte_length",
                                "conversation_id_sha256",
                                "branch_id_sha256",
                                "captured_at_sha256",
                                "parser_name",
                                "parser_version",
                                "schema_fingerprint",
                                "source_record_count",
                                "record_count",
                                "role_counts",
                                "admission_counts",
                                "unknown_record_type_sha256s",
                                "malformed_records",
                                "planned_ingest",
                            },
                            "web export conversation entry",
                        )
                        relative = _validated_plan_relative_path(
                            _required_string(entry, "relative_path")
                        )
                        relative_text = relative.as_posix()
                        if relative_text in expected_files:
                            raise ValueError("web export conversation paths must be unique")
                        expected_files.add(relative_text)
                        split_path = root.joinpath(*relative.parts)
                        split_path = _regular_file(split_path, "conversation split")
                        _require_private_file(split_path, "conversation split")

                        if _required_int(entry, "index") != index:
                            raise RuntimeError("web export conversation index changed")
                        if (
                            _required_int(entry, "archive_member_index")
                            != conversation_member.archive_member_index
                        ):
                            raise RuntimeError("web export conversation member changed")
                        if (
                            _required_int(entry, "member_conversation_index")
                            != member_conversation_index
                        ):
                            raise RuntimeError("web export member-local conversation index changed")
                        if _required_int(entry, "source_byte_start") != span.start:
                            raise RuntimeError("web export conversation start byte changed")
                        if _required_int(entry, "source_byte_end") != span.end:
                            raise RuntimeError("web export conversation end byte changed")
                        span_size = span.end - span.start
                        span_digest = hashlib.sha256(view[span.start : span.end]).hexdigest()
                        if _required_int(entry, "byte_length") != span_size:
                            raise RuntimeError("web export conversation byte length changed")
                        if _required_digest(entry, "sha256") != span_digest:
                            raise RuntimeError("web export conversation digest changed")
                        try:
                            split_size, split_digest = _hash_file(
                                split_path,
                                expected_size=span_size,
                                budget=budget,
                            )
                        except RuntimeError as exc:
                            raise RuntimeError("web export conversation split changed") from exc
                        budget.add_disk_bytes(split_size)
                        budget.checkpoint(
                            logical_memory_bytes=budget.conversation_memory_bytes(
                                split_size,
                                len(entries),
                            )
                        )
                        if (split_size, split_digest) != (span_size, span_digest):
                            raise RuntimeError(
                                "conversation split no longer matches the export member"
                            )
                        parsed = parse_file(
                            split_path,
                            source_system,
                            max_file_bytes=max(DEFAULT_MAX_FILE_BYTES, split_size),
                            resource_checkpoint=budget.checkpoint,
                        )
                        entry_source_record_count = _web_conversation_record_count(
                            view[span.start : span.end],
                            source_system,
                            max_records=(limits.max_record_count - source_record_count + 1),
                        )
                        if _required_int(entry, "source_record_count") != entry_source_record_count:
                            raise RuntimeError("web export source-record count changed")
                        source_record_count += entry_source_record_count
                        enforce_record_count(source_record_count, limits)
                        _verify_parsed_file_binding(entry, parsed)
                        source_path = _conversation_source_path(
                            source_system=source_system,
                            source_account=source_account,
                            archive_sha256=inspection.archive_sha256,
                            conversation_id=parsed.conversation_id,
                            digest=span_digest,
                        )
                        if _required_string(entry, "source_path") != source_path:
                            raise RuntimeError("web export logical source path changed")
                        source_locator = _conversation_source_locator(
                            archive_sha256=inspection.archive_sha256,
                            archive_member=conversation_member.archive_member,
                            index=member_conversation_index,
                            span=span,
                            digest=span_digest,
                        )
                        if _required_string(entry, "source_locator") != source_locator:
                            raise RuntimeError("web export exact source locator changed")
                        if (
                            _required_digest(entry, "schema_fingerprint")
                            != parsed.schema_fingerprint
                        ):
                            raise RuntimeError("web export conversation schema changed")
                        schema_descriptors.update(parsed.schema_descriptors)
                        existing_parser_version = parser_versions.setdefault(
                            parsed.parser_name,
                            parsed.parser_version,
                        )
                        if existing_parser_version != parsed.parser_version:
                            raise RuntimeError("one parser name produced conflicting versions")
                        role_counts, admission_counts, accepted_records = _verify_entry_parse(
                            entry,
                            parsed,
                            max_record_bytes=max_record_bytes,
                        )
                        conversation_references: list[_AttachmentReference] = []
                        for record in accepted_records:
                            references, malformed_references = _record_attachment_references(
                                record,
                                source_system=source_system,
                                conversation_index=index,
                            )
                            conversation_references.extend(references)
                            malformed_attachment_references += malformed_references
                        attachment_references.extend(conversation_references)
                        attachment_reference_utf8_bytes += sum(
                            len(reference.value.encode()) for reference in conversation_references
                        )
                        enforce_record_count(len(attachment_references), limits)
                        budget.checkpoint(
                            logical_memory_bytes=budget.conversation_memory_bytes(
                                span.end - span.start,
                                len(entries),
                            )
                            + budget.attachment_plan_memory_bytes(
                                reference_utf8_bytes=attachment_reference_utf8_bytes,
                                reference_count=len(attachment_references),
                                member_count=0,
                            )
                        )
                        planned_ingest = _required_bool(entry, "planned_ingest")
                        aggregate_roles.update(role_counts)
                        aggregate_admission.update(admission_counts)
                        aggregate_unknown.update(
                            _text_sha256(value) for value in parsed.unknown_record_types
                        )
                        malformed_records += parsed.malformed_records
                        record_count += len(parsed.records)
                        enforce_record_count(record_count, limits)
                        planned_ingest_count += int(planned_ingest)
                        verified_conversations.append(
                            VerifiedConversation(
                                path=split_path,
                                conversation_id=parsed.conversation_id,
                                source_path=source_path,
                                source_locator=source_locator,
                                conversation_index=index,
                                source_byte_start=span.start,
                                source_byte_end=span.end,
                                conversation_sha256=span_digest,
                                byte_length=span_size,
                                planned_ingest=planned_ingest,
                                entry=entry,
                            )
                        )
                finally:
                    view.release()
            after = os.fstat(handle.fileno())
        if _stat_identity(before) != _stat_identity(after):
            raise RuntimeError("export member changed while verifying its plan")
    if entry_index != len(entries):
        raise RuntimeError("web export conversation count changed after planning")

    actual_schema_fingerprint = _aggregate_web_schema_fingerprint(
        source_system,
        schema_descriptors,
    )
    if expected_schema_fingerprint != actual_schema_fingerprint:
        raise RuntimeError("web export aggregate schema fingerprint changed")
    if expected_parser_versions != parser_versions:
        raise RuntimeError("web export parser-version set changed")

    attachment_plan_memory_bytes = budget.conversation_memory_bytes(0, len(entries)) + (
        budget.attachment_plan_memory_bytes(
            reference_utf8_bytes=attachment_reference_utf8_bytes,
            reference_count=len(attachment_references),
            member_count=len(inspection.supplemental_members),
        )
    )
    attachment_plan = _plan_attachments(
        inspection,
        attachment_references,
        archive_path=archive_path,
        archive_identity=archive_identity,
        source_system=source_system,
        conversation_member_indices=additional_conversation_member_indices,
        malformed_references=malformed_attachment_references,
        max_extracted_bytes=max_extracted_attachment_bytes,
        extracted_media_types=extracted_media_types,
        budget=budget,
        logical_memory_bytes=attachment_plan_memory_bytes,
    )
    if manifest.get("attachment_linkage") != attachment_plan.summary:
        raise RuntimeError("web export attachment linkage changed after planning")
    _verify_archive_inspection(
        manifest.get("archive_inspection"),
        inspection,
        supplemental_members=attachment_plan.member_manifests,
    )
    member_by_index = {item.archive_member_index: item for item in inspection.supplemental_members}
    attachment_paths: list[tuple[int, Path]] = []
    for archive_member_index in attachment_plan.extracted_indices:
        member = member_by_index[archive_member_index]
        relative = PurePosixPath(
            "attachments",
            f"{archive_member_index:08d}.bin",
        )
        relative_text = relative.as_posix()
        if relative_text in expected_files:
            raise ValueError("web export plan paths must be unique")
        expected_files.add(relative_text)
        attachment_path = _regular_file(
            root.joinpath(*relative.parts),
            "extracted web export attachment",
        )
        _require_private_file(attachment_path, "extracted web export attachment")
        try:
            attachment_size, attachment_digest = _hash_file(
                attachment_path,
                expected_size=member.byte_length,
                budget=budget,
            )
        except RuntimeError as exc:
            raise RuntimeError("extracted web export attachment changed") from exc
        budget.add_disk_bytes(attachment_size)
        if (attachment_size, attachment_digest) != (
            member.byte_length,
            member.content_sha256,
        ):
            raise RuntimeError("extracted web export attachment changed after planning")
        attachment_paths.append((archive_member_index, attachment_path))

    _verify_plan_tree(root, expected_files)
    aggregate = {
        "conversation_count": len(entries),
        "planned_ingest_count": planned_ingest_count,
        "source_record_count": source_record_count,
        "record_count": record_count,
        "role_counts": dict(sorted(aggregate_roles.items())),
        "admission_counts": dict(sorted(aggregate_admission.items())),
        "unknown_record_type_conversation_counts": dict(sorted(aggregate_unknown.items())),
        "malformed_records": malformed_records,
        "schema_status": (
            "recognized"
            if not aggregate_unknown
            and malformed_records == 0
            and malformed_attachment_references == 0
            else "review_required"
        ),
    }
    for key, actual in aggregate.items():
        if manifest.get(key) != actual:
            raise RuntimeError(f"web export manifest aggregate changed: {key}")

    batch_provenance = WebExportBatchProvenance(
        manifest_sha256=manifest_digest,
        code_revision=code_revision,
        prepared_at=_required_string(manifest, "created_at"),
        archive_sha256=inspection.archive_sha256,
        archive_byte_length=inspection.archive_size,
        selected_member_name_sha256=hashlib.sha256(archive_member.encode()).hexdigest(),
        selected_member_sha256=inspection.selected_member_sha256,
        selected_member_byte_length=inspection.selected_member_size,
        archive_members=tuple(
            WebExportArchiveMemberProvenance(
                archive_member_index=item.archive_member_index,
                locator=item.locator,
                name_sha256=item.name_sha256,
                content_sha256=item.content_sha256,
                compressed_bytes=item.compressed_bytes,
                byte_length=item.byte_length,
                compression_method=item.compression_method,
                media_type_hint=item.media_type,
            )
            for item in inspection.supplemental_members
            if item.archive_member_index not in additional_conversation_member_indices
        ),
        attachment_references=attachment_plan.references,
        extracted_attachment_indices=attachment_plan.extracted_indices,
    )

    return VerifiedWebExportPlan(
        manifest_path=path.resolve(),
        manifest_sha256=manifest_digest,
        archive_path=archive_path,
        member_path=member_path,
        source_system=source_system,
        source_account=source_account,
        scope=scope,
        project_id=project_id,
        expected_ledger_generation=expected_generation,
        code_revision=code_revision,
        max_record_bytes=max_record_bytes,
        source_provenance=source_provenance,
        batch_provenance=batch_provenance,
        limits=limits,
        resource_usage=budget.usage(),
        manifest=manifest,
        conversations=tuple(verified_conversations),
        attachment_paths=tuple(attachment_paths),
    )


def _conversation_spans(
    data: bytes | memoryview,
    source_system: SourceSystem,
    *,
    max_records: int,
    limit_code: str,
) -> tuple[JsonSpan, ...]:
    try:
        if source_system in {SourceSystem.CHATGPT_WEB, SourceSystem.CLAUDE_WEB}:
            return top_level_array_value_spans(data, max_values=max_records)
        if source_system is SourceSystem.GROK_WEB:
            return object_array_value_spans(data, "conversations", max_values=max_records)
    except JsonValueCountLimitError as exc:
        if limit_code == "memory_bytes":
            raise WebExportLimitError(
                "memory_bytes",
                "web export conversation index exceeds the memory budget",
            ) from exc
        raise WebExportLimitError(
            "record_count",
            "web export conversation-count budget exceeded",
        ) from exc
    raise ValueError(f"unsupported web source system: {source_system.value}")


def _web_conversation_record_count(
    data: bytes | memoryview,
    source_system: SourceSystem,
    *,
    max_records: int,
) -> int:
    try:
        if source_system is SourceSystem.CHATGPT_WEB:
            return len(object_item_spans(data, "mapping", max_values=max_records))
        if source_system is SourceSystem.CLAUDE_WEB:
            return len(object_array_value_spans(data, "chat_messages", max_values=max_records))
        if source_system is SourceSystem.GROK_WEB:
            return len(object_array_value_spans(data, "responses", max_values=max_records))
    except JsonValueCountLimitError as exc:
        raise WebExportLimitError(
            "record_count",
            "web export source-record budget exceeded",
        ) from exc
    raise ValueError(f"unsupported web source system: {source_system.value}")


def _conversation_source_path(
    *,
    source_system: SourceSystem,
    source_account: str,
    archive_sha256: str,
    conversation_id: str,
    digest: str,
) -> str:
    account_digest = hashlib.sha256(source_account.encode()).hexdigest()
    conversation_digest = hashlib.sha256(conversation_id.encode()).hexdigest()
    return (
        f"/official-web-export/{source_system.value}/{account_digest}/"
        f"{archive_sha256}/{conversation_digest}/{digest}.json"
    )


def _conversation_source_locator(
    *,
    archive_sha256: str,
    archive_member: str,
    index: int,
    span: JsonSpan,
    digest: str,
) -> str:
    member_name_sha256 = hashlib.sha256(archive_member.encode()).hexdigest()
    return (
        f"zip+sha256:{archive_sha256}/member-name-sha256:{member_name_sha256}"
        f"#conversation={index}&bytes={span.start}-{span.end}&sha256={digest}"
    )


def _aggregate_web_schema_fingerprint(
    source_system: SourceSystem,
    schema_descriptors: set[str],
) -> str:
    payload = {
        "container": "object.conversations" if source_system is SourceSystem.GROK_WEB else "array",
        "schema_descriptors": sorted(schema_descriptors),
    }
    serialized = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


def _verify_entry_parse(
    entry: dict[str, Any],
    parsed: ParseResult,
    *,
    max_record_bytes: int,
) -> tuple[Counter[str], Counter[str], tuple[ParsedRecord, ...]]:
    role_counts = Counter(record.actor_kind for record in parsed.records)
    admission_counts: Counter[str] = Counter()
    accepted_records: list[ParsedRecord] = []
    for record in parsed.records:
        decision = classify_record(
            parsed.source_system,
            record.content_text,
            record.raw_record,
            max_record_bytes=max_record_bytes,
        )
        admission_counts[decision.reason] += 1
        if decision.accepted:
            accepted_records.append(record)
    expected: dict[str, object] = {
        "conversation_id_sha256": _text_sha256(parsed.conversation_id),
        "branch_id_sha256": _optional_text_sha256(parsed.branch_id),
        "captured_at_sha256": _optional_text_sha256(parsed.captured_at),
        "parser_name": parsed.parser_name,
        "parser_version": parsed.parser_version,
        "record_count": len(parsed.records),
        "role_counts": dict(sorted(role_counts.items())),
        "admission_counts": dict(sorted(admission_counts.items())),
        "unknown_record_type_sha256s": sorted(
            _text_sha256(value) for value in parsed.unknown_record_types
        ),
        "malformed_records": parsed.malformed_records,
        "planned_ingest": bool(parsed.records),
    }
    for key, actual in expected.items():
        if entry.get(key) != actual:
            raise RuntimeError(f"web export conversation parse changed: {key}")
    return role_counts, admission_counts, tuple(accepted_records)


def _verify_parsed_file_binding(entry: dict[str, Any], parsed: ParseResult) -> None:
    if parsed.file_size != _required_int(entry, "byte_length"):
        raise RuntimeError("conversation split size changed before parsing")
    if parsed.file_digest != _required_digest(entry, "sha256"):
        raise RuntimeError("conversation split digest changed before parsing")


def _public_plan_summary(verified: VerifiedWebExportPlan) -> dict[str, Any]:
    manifest = verified.manifest
    archive_inspection = _required_object(manifest, "archive_inspection")
    public_archive_inspection = {
        key: value for key, value in archive_inspection.items() if key != "supplemental_members"
    }
    return {
        "manifest_path": str(verified.manifest_path),
        "manifest_sha256": verified.manifest_sha256,
        "source_system": verified.source_system.value,
        "source_account": verified.source_account,
        "source_capture": manifest["source_capture"],
        "scope": verified.scope.value,
        "project_id": verified.project_id,
        "code_revision": verified.code_revision,
        "expected_ledger_generation": verified.expected_ledger_generation,
        "resource_limits": manifest["resource_limits"],
        "attachment_policy": manifest["attachment_policy"],
        "attachment_linkage": manifest["attachment_linkage"],
        "archive_inspection": public_archive_inspection,
        "supplemental_member_count": len(
            cast(
                list[object],
                archive_inspection["supplemental_members"],
            )
        ),
        "resource_usage": verified.resource_usage,
        "conversation_member_count": 1 + len(cast(list[object], manifest["additional_members"])),
        "conversation_count": manifest["conversation_count"],
        "planned_ingest_count": manifest["planned_ingest_count"],
        "source_record_count": manifest["source_record_count"],
        "record_count": manifest["record_count"],
        "role_counts": manifest["role_counts"],
        "admission_counts": manifest["admission_counts"],
        "unknown_record_type_conversation_counts": manifest[
            "unknown_record_type_conversation_counts"
        ],
        "malformed_records": manifest["malformed_records"],
        "schema_status": manifest["schema_status"],
    }


def _manifest_admission_count(manifest: dict[str, Any], reason: str) -> int:
    counts = _required_object(manifest, "admission_counts")
    value = counts.get(reason, 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("web export admission counts must be non-negative integers")
    return value


def _manifest_quarantine_count(manifest: dict[str, Any]) -> int:
    counts = _required_object(manifest, "admission_counts")
    total = 0
    for reason, value in counts.items():
        if not reason:
            raise ValueError("web export admission reason must be a non-empty string")
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("web export admission counts must be non-negative integers")
        if reason != "included":
            total += value
    return total


def _verify_file_manifest(
    value: dict[str, Any],
    *,
    actual_size: int,
    actual_digest: str,
    label: str,
) -> None:
    if _required_int(value, "byte_length") != actual_size:
        raise RuntimeError(f"{label} byte length changed after planning")
    if _required_digest(value, "sha256") != actual_digest:
        raise RuntimeError(f"{label} digest changed after planning")


def _verify_archive_inspection(
    value: object,
    inspection: ArchiveInspection,
    *,
    supplemental_members: tuple[dict[str, object], ...],
) -> None:
    if not isinstance(value, dict):
        raise ValueError("web export archive inspection must be an object")
    loaded = cast(dict[str, object], value)
    expected = inspection.as_dict()
    expected["supplemental_members"] = list(supplemental_members)
    if set(loaded) != set(expected):
        raise ValueError("web export archive inspection keys are invalid")
    if loaded != expected:
        raise RuntimeError("web export archive inspection changed after planning")


def _verify_plan_tree(root: Path, expected_files: set[str]) -> None:
    actual_files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"web export plan contains a symlink: {path}")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            _require_private_directory(path, "web export plan directory")
        elif path.is_file():
            actual_files.add(relative)
        else:
            raise RuntimeError(f"web export plan contains a non-regular entry: {path}")
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        unexpected = sorted(actual_files - expected_files)
        raise RuntimeError(
            f"web export plan file set changed: missing={missing[:3]} unexpected={unexpected[:3]}"
        )


def _validated_plan_relative_path(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.parts[:1] != ("conversations",)
        or len(relative.parts) != 2
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        raise ValueError(f"unsafe web export conversation path: {value}")
    return relative


def _regular_file(path: Path, label: str) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink() or not expanded.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {expanded}")
    return expanded


def _prepare_private_output_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"web export output directory must not be a symlink: {path}")
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
        path.chmod(0o700)
    _require_private_directory(path, "web export output directory")


def _absolute_regular_file(value: dict[str, Any], key: str, label: str) -> Path:
    path = Path(_required_string(value, key)).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    return _regular_file(path, label)


def _require_private_file(path: Path, label: str) -> None:
    metadata = path.stat()
    if metadata.st_uid != os.geteuid():
        raise RuntimeError(f"{label} is not owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RuntimeError(f"{label} is readable or writable by another user: {path}")


def _require_private_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be a regular non-symlink directory: {path}")
    metadata = path.stat()
    if metadata.st_uid != os.geteuid():
        raise RuntimeError(f"{label} is not owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RuntimeError(f"{label} is accessible by another user: {path}")


def _hash_file(
    path: Path,
    *,
    expected_size: int,
    budget: ResourceBudget | None = None,
) -> tuple[int, str]:
    if expected_size < 0:
        raise ValueError("expected file size must be non-negative")
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if before.st_size != expected_size:
            raise RuntimeError(f"file no longer has its approved size: {path}")
        while chunk := handle.read(min(COPY_CHUNK_BYTES, expected_size - size + 1)):
            size += len(chunk)
            if size > expected_size:
                raise RuntimeError(f"file exceeded its approved size while hashing: {path}")
            digest.update(chunk)
            if budget is not None:
                budget.checkpoint(logical_memory_bytes=len(chunk))
        after = os.fstat(handle.fileno())
    if size != expected_size:
        raise RuntimeError(f"file no longer has its approved size: {path}")
    if _stat_identity(before) != _stat_identity(after):
        raise RuntimeError(f"file changed while hashing: {path}")
    return size, digest.hexdigest()


def _hash_view(data: memoryview, budget: ResourceBudget) -> str:
    digest = hashlib.sha256()
    for offset in range(0, len(data), COPY_CHUNK_BYTES):
        chunk = data[offset : offset + COPY_CHUNK_BYTES]
        digest.update(chunk)
        budget.checkpoint(logical_memory_bytes=len(chunk))
    return digest.hexdigest()


def _read_stable_file(path: Path, *, max_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if before.st_size > max_bytes:
            raise ValueError(f"file exceeds the {max_bytes}-byte limit: {path}")
        data = handle.read(max_bytes + 1)
        after = os.fstat(handle.fileno())
    if len(data) > max_bytes:
        raise ValueError(f"file exceeded the {max_bytes}-byte limit while reading: {path}")
    if len(data) != before.st_size or _stat_identity(before) != _stat_identity(after):
        raise RuntimeError(f"file changed while reading: {path}")
    return data


def _write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
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


def _publish_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    _write_private_file(temporary, data)
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as exc:
        temporary.unlink(missing_ok=True)
        raise ValueError(f"private output already exists: {path}") from exc
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    with suppress(OSError):
        temporary.unlink()


def _validate_digest(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _validate_code_revision(value: str) -> None:
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("code revision must be a full lowercase Git object ID")


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _optional_text_sha256(value: str | None) -> str | None:
    return None if value is None else _text_sha256(value)


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    loaded: dict[str, object] = {}
    for key, value in pairs:
        if key in loaded:
            raise ValueError(f"web export manifest contains a duplicate key: {key}")
        loaded[key] = value
    return loaded


def _required_object(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise ValueError(f"{key} must be an object")
    return cast(dict[str, Any], item)


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ValueError(
            f"{label} keys are invalid: missing={missing[:3]} unexpected={unexpected[:3]}"
        )


def _required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a non-empty string")
    return item


def _bounded_manifest_label(value: str, label: str) -> str:
    if value.strip() != value or not value:
        raise ValueError(f"{label} must be a canonical non-empty string")
    if len(value.encode()) > 256:
        raise ValueError(f"{label} exceeds its size limit")
    if any(
        not character.isascii() or not (character.isalnum() or character in ".-_:+/")
        for character in value
    ):
        raise ValueError(f"{label} contains unsupported characters")
    return value


def _required_string_map(value: dict[str, Any], key: str) -> dict[str, str]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise ValueError(f"{key} must be an object")
    result: dict[str, str] = {}
    for item_key, item_value in cast(dict[object, object], item).items():
        if not isinstance(item_key, str) or not isinstance(item_value, str):
            raise ValueError(f"{key} must contain string keys and values")
        result[_bounded_manifest_label(item_key, f"{key} key")] = _bounded_manifest_label(
            item_value, f"{key} value"
        )
    return result


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("optional string value must be non-empty or null")
    return value


def _required_int(value: dict[str, Any], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool) or item < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return item


def _required_positive_int(value: dict[str, Any], key: str) -> int:
    item = _required_int(value, key)
    if item == 0:
        raise ValueError(f"{key} must be positive")
    return item


def _required_bool(value: dict[str, Any], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise ValueError(f"{key} must be a boolean")
    return item


def _required_digest(value: dict[str, Any], key: str) -> str:
    item = _required_string(value, key)
    _validate_digest(item, key)
    return item


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISREG(value.st_mode):
        raise RuntimeError("source changed into a non-regular file")
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
