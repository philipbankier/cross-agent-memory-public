from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import unquote, urlsplit

from cross_assistant_memory.admission import classify_attachment, classify_record
from cross_assistant_memory.grok_bot_capture import (
    GrokBotCaptureScope,
    GrokBotStructuredRequestObservation,
)
from cross_assistant_memory.grok_bot_transcript import project_transcript_page
from cross_assistant_memory.models import SourceSystem
from cross_assistant_memory.safe_files import open_regular_file_no_symlinks

WORKSPACE_ROOT = Path("/workspace")
MAX_SENT_ARTIFACT_BYTES = 4 * 1024 * 1024
_SENSITIVE_PARTS = frozenset({"secrets", "credentials", "keys", "queue", "cam-integration-probe"})
_SENSITIVE_SUFFIXES = frozenset({".key", ".pem", ".token", ".db", ".sqlite", ".sqlite3"})
_MEDIA_HINTS = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".csv": "text/csv",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".pdf": "application/pdf",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".zip": "application/zip",
}


class SentArtifactError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Grok Bot sent artifact: {code}")


def sent_artifact_media_type(url: str) -> str:
    suffix = PurePosixPath(unquote(urlsplit(url).path)).suffix.casefold()
    return _MEDIA_HINTS.get(suffix, "application/octet-stream")


@dataclass(frozen=True)
class SentArtifactSnapshot:
    bot_id: str
    native_tool_call_id: str
    reference_sha256: str
    media_type_hint: str
    data: bytes = field(repr=False)
    content_text: str | None = field(repr=False)
    observed_mtime_ns: int
    observed_ctime_ns: int

    def manifest(self) -> dict[str, object]:
        return {
            "format_version": 1,
            "kind": "sent_artifact_snapshot",
            "source_system": "grok_bot",
            "bot_id": self.bot_id,
            "native_tool_call_id": self.native_tool_call_id,
            "reference_sha256": self.reference_sha256,
            "content_sha256": hashlib.sha256(self.data).hexdigest(),
            "byte_length": len(self.data),
            "media_type_hint": self.media_type_hint,
            "inspection_status": "inspected_text"
            if self.content_text is not None
            else "not_inspected",
            "content_access": "text" if self.content_text is not None else "metadata_only",
            "native_author_id": None,
            "native_version_verified": False,
            "original_sent_bytes_verified": False,
        }


def select_sent_attachment(
    transcript: bytes, *, bot_id: str, scope: GrokBotCaptureScope
) -> tuple[GrokBotStructuredRequestObservation, ...]:
    if type(scope) is not GrokBotCaptureScope or not scope.allows(bot_id):
        raise SentArtifactError("source_not_enrolled")
    try:
        projection = project_transcript_page(transcript, expected_bot_id=bot_id)
    except ValueError:
        raise SentArtifactError("unqualified_source_page") from None
    return tuple(
        GrokBotStructuredRequestObservation(
            bot_id, reply.native_tool_call_id, reply.content_text, kind="attachment_reference"
        )
        for reply in projection.replies
        if reply.kind == "attachment_reference"
    )


def read_sent_artifact(
    reference: GrokBotStructuredRequestObservation, *, scope: GrokBotCaptureScope, max_bytes: int
) -> SentArtifactSnapshot:
    if (
        type(scope) is not GrokBotCaptureScope
        or type(reference) is not GrokBotStructuredRequestObservation
        or not scope.allows(reference.bot_id)
    ):
        raise SentArtifactError("source_not_enrolled")
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_SENT_ARTIFACT_BYTES:
        raise SentArtifactError("invalid_byte_limit")
    if reference.kind != "attachment_reference":
        raise SentArtifactError("unsafe_reference")
    value = cast(dict[str, str], json.loads(reference.content_text))
    relative = PurePosixPath(unquote(urlsplit(value["url"]).path)).relative_to("/workspace")
    if any(part.startswith(".") or part.casefold() in _SENSITIVE_PARTS for part in relative.parts):
        raise SentArtifactError("unsafe_reference")
    if relative.suffix.casefold() in _SENSITIVE_SUFFIXES:
        raise SentArtifactError("unsafe_reference")
    path = WORKSPACE_ROOT.joinpath(*relative.parts)
    try:
        descriptor, _ = open_regular_file_no_symlinks(path, "sent artifact")
    except (OSError, ValueError):
        raise SentArtifactError("unavailable_or_unsafe") from None
    try:
        before = os.fstat(descriptor)
        if before.st_uid != os.getuid() or before.st_nlink != 1:
            raise SentArtifactError("unavailable_or_unsafe")
        if before.st_size > max_bytes:
            raise SentArtifactError("over_limit")
        chunks: list[bytes] = []
        size = 0
        while size <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > max_bytes or size != before.st_size:
            raise SentArtifactError("source_changed")
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            raise SentArtifactError("source_changed")
        # An unchanged descriptor alone does not detect replacement of its directory entry.
        current, _ = open_regular_file_no_symlinks(path, "sent artifact")
        try:
            if _identity(before) != _identity(os.fstat(current)):
                raise SentArtifactError("source_changed")
        finally:
            os.close(current)
    except (OSError, ValueError) as error:
        if isinstance(error, SentArtifactError):
            raise
        raise SentArtifactError("unavailable_or_unsafe") from None
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    decision = classify_record(SourceSystem.GROK_BOT, "", data, max_record_bytes=max_bytes)
    if not decision.accepted:
        raise SentArtifactError("excluded:" + decision.reason)
    media = sent_artifact_media_type(value["url"])
    inspected = classify_attachment(SourceSystem.GROK_BOT, media, data, max_record_bytes=max_bytes)
    if (media.startswith("text/") or media == "application/json") and not inspected.accepted:
        raise SentArtifactError("excluded:" + inspected.reason)
    text = data.decode("utf-8-sig") if inspected.accepted else None
    return SentArtifactSnapshot(
        reference.bot_id,
        reference.native_tool_call_id,
        hashlib.sha256(reference.canonical_bytes()).hexdigest(),
        media,
        data,
        text,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )


def capture_sent_artifact(
    queue: object,
    reference: GrokBotStructuredRequestObservation,
    *,
    scope: GrokBotCaptureScope,
    max_bytes: int,
) -> dict[str, object]:
    from cross_assistant_memory.collector_queue import CollectorQueue, upload_source_key_for
    from cross_assistant_memory.grok_bot_capture import build_grok_bot_capture_upload
    from cross_assistant_memory.native_attachments import (
        MAX_NATIVE_ATTACHMENT_BYTES,
        NativeAttachmentUpload,
        attach_native_artifact,
    )
    from cross_assistant_memory.uploads import parse_upload_batch

    if type(queue) is not CollectorQueue:
        raise SentArtifactError("invalid_queue")
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_NATIVE_ATTACHMENT_BYTES:
        raise SentArtifactError("invalid_byte_limit")
    snapshot = read_sent_artifact(reference, scope=scope, max_bytes=max_bytes)
    body = attach_native_artifact(
        build_grok_bot_capture_upload(reference, source_account_id=scope.source_account_id),
        NativeAttachmentUpload(
            0, snapshot.reference_sha256, snapshot.media_type_hint, snapshot.data
        ),
    )
    cursor = queue.cursor(upload_source_key_for(parse_upload_batch(body)))
    acknowledged = cursor is not None and cursor.next_record_ordinal == 1
    if not acknowledged:
        queue.enqueue_upload(body)
    return {
        "status": "already_acknowledged" if acknowledged else "queued_not_admitted",
        **snapshot.manifest(),
        "content_access": "metadata_only",
    }


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        stat.S_IFMT(value.st_mode),
        value.st_uid,
        value.st_nlink,
    )
