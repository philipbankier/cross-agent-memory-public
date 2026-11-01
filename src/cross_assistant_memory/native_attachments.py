from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import cast

from cross_assistant_memory.admission import (
    TEXT_ATTACHMENT_MEDIA_TYPES,
    classify_attachment,
    classify_record,
)
from cross_assistant_memory.models import ParseResult, SourceSystem

MAX_NATIVE_ATTACHMENT_BYTES = 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FIELDS = {
    "record_ordinal",
    "reference_sha256",
    "media_type_hint",
    "content_sha256",
    "byte_length",
    "data_base64",
}
NATIVE_ATTACHMENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS native_attachment_objects (
  attachment_id TEXT PRIMARY KEY,
  source_record_id TEXT NOT NULL REFERENCES source_records(source_record_id) ON DELETE CASCADE,
  object_id TEXT NOT NULL REFERENCES objects(object_id),
  reference_sha256 TEXT NOT NULL CHECK (length(reference_sha256) = 64),
  media_type_hint TEXT NOT NULL,
  inspection_status TEXT NOT NULL CHECK (inspection_status IN ('inspected_text', 'not_inspected')),
  created_at TEXT NOT NULL,
  UNIQUE(source_record_id, object_id, media_type_hint)
);
CREATE INDEX IF NOT EXISTS native_attachment_object_idx ON native_attachment_objects(object_id);
"""


@dataclass(frozen=True)
class NativeAttachmentUpload:
    record_ordinal: int
    reference_sha256: str
    media_type_hint: str
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.record_ordinal) is not int
            or not 0 <= self.record_ordinal < 2**63
            or type(self.reference_sha256) is not str
            or _DIGEST.fullmatch(self.reference_sha256) is None
            or type(self.media_type_hint) is not str
            or re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", self.media_type_hint) is None
            or len(self.media_type_hint) > 128
            or type(self.data) is not bytes
            or len(self.data) > MAX_NATIVE_ATTACHMENT_BYTES
        ):
            raise ValueError("native attachment fields are invalid")
        decision = classify_record(
            SourceSystem.GROK_BOT,
            "",
            self.data,
            max_record_bytes=MAX_NATIVE_ATTACHMENT_BYTES,
        )
        if not decision.accepted:
            raise ValueError("native attachment failed admission: " + decision.reason)
        if self.media_type_hint in TEXT_ATTACHMENT_MEDIA_TYPES:
            inspected = classify_attachment(
                SourceSystem.GROK_BOT,
                self.media_type_hint,
                self.data,
                max_record_bytes=MAX_NATIVE_ATTACHMENT_BYTES,
            )
            if not inspected.accepted:
                raise ValueError("native attachment failed admission: " + inspected.reason)

    def as_dict(self) -> dict[str, object]:
        return {
            "record_ordinal": self.record_ordinal,
            "reference_sha256": self.reference_sha256,
            "media_type_hint": self.media_type_hint,
            "content_sha256": hashlib.sha256(self.data).hexdigest(),
            "byte_length": len(self.data),
            "data_base64": base64.b64encode(self.data).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, value: object) -> NativeAttachmentUpload:
        if not isinstance(value, dict):
            raise ValueError("native attachment fields are invalid")
        value = cast(dict[str, object], value)
        if set(value) != _FIELDS:
            raise ValueError("native attachment fields are invalid")
        encoded = value["data_base64"]
        if type(encoded) is not str or len(encoded) > 4 * ((MAX_NATIVE_ATTACHMENT_BYTES + 2) // 3):
            raise ValueError("native attachment payload is invalid")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("native attachment payload is invalid") from None
        if (
            base64.b64encode(data).decode("ascii") != encoded
            or type(value["byte_length"]) is not int
            or value["byte_length"] != len(data)
            or type(value["content_sha256"]) is not str
            or value["content_sha256"] != hashlib.sha256(data).hexdigest()
        ):
            raise ValueError("native attachment payload identity is invalid")
        return cls(
            cast(int, value["record_ordinal"]),
            cast(str, value["reference_sha256"]),
            cast(str, value["media_type_hint"]),
            data,
        )


def validate_native_attachments(
    parsed: ParseResult, attachments: tuple[NativeAttachmentUpload, ...]
) -> None:
    from cross_assistant_memory.grok_bot_artifacts import sent_artifact_media_type
    from cross_assistant_memory.grok_bot_capture import GrokBotStructuredRequestObservation

    if not attachments:
        return
    if (
        parsed.source_system is not SourceSystem.GROK_BOT
        or len(attachments) != 1
        or len(parsed.records) != 1
    ):
        raise ValueError("native attachment requires one Grok Bot reference")
    record, attachment = parsed.records[0], attachments[0]
    if type(attachment) is not NativeAttachmentUpload:
        raise ValueError("native attachment fields are invalid")
    if (
        record.record_ordinal != attachment.record_ordinal
        or hashlib.sha256(record.raw_record).hexdigest() != attachment.reference_sha256
    ):
        raise ValueError("native attachment reference identity is invalid")
    try:
        raw = json.loads(record.raw_record)
        reference = GrokBotStructuredRequestObservation(
            raw["bot_id"], raw["native_tool_call_id"], raw["content_text"], raw["kind"]
        )
        if (
            reference.kind != "attachment_reference"
            or reference.canonical_bytes() != record.raw_record
        ):
            raise ValueError("invalid reference")
        url = cast(dict[str, str], json.loads(reference.content_text))["url"]
        if attachment.media_type_hint != sent_artifact_media_type(url):
            raise ValueError("invalid media hint")
    except (KeyError, TypeError, ValueError):
        raise ValueError("native attachment reference is invalid") from None


def attach_native_artifact(body: bytes, attachment: NativeAttachmentUpload) -> bytes:
    from cross_assistant_memory.uploads import parse_upload_batch

    batch = parse_upload_batch(body)
    if batch.native_attachments or batch.exclusion_receipts:
        raise ValueError("native attachment requires an included reference")
    validate_native_attachments(batch.parsed, (attachment,))
    root = json.loads(body)
    root.pop("batch_id")
    root["format_version"] = 3
    root["native_attachments"] = [attachment.as_dict()]

    def canonical(item: object) -> bytes:
        return json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")

    root["batch_id"] = "batch:" + hashlib.sha256(canonical(root)).hexdigest()
    result = canonical(root)
    parse_upload_batch(result)
    return result
