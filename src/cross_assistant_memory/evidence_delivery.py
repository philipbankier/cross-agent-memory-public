from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator
from typing import Annotated, Any

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict, Field, StrictInt

MAX_EVIDENCE_RESPONSE_BYTES = 512 * 1024
MAX_EVIDENCE_PAGE_BYTES = 64 * 1024
EVIDENCE_VERSION_REQUIRED_MESSAGE = (
    "Evidence continuation requires page.expected_evidence_sha256 from "
    "evidence_page.evidence_sha256. Keep event_id and include_context unchanged."
)
EVIDENCE_CHANGED_MESSAGE = (
    "Evidence version does not match this read; restart from the first page. "
    "Keep event_id and include_context unchanged between pages."
)
EVIDENCE_OFFSET_MESSAGE = (
    "Evidence offset is outside the field or not a UTF-8 boundary. Use that field's "
    "next_offset_bytes; null means no remaining page. Do not use raw source byte offsets "
    "for normalized content."
)
Offset = Annotated[StrictInt, Field(ge=0, le=2**31 - 1)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class EvidenceVersionRequiredError(ValueError):
    pass


class EvidenceChangedError(ValueError):
    pass


class EvidenceOffsetError(ValueError):
    pass


class EvidencePageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_offset: Offset = 0
    raw_offset: Offset = 0
    original_content_offset: Offset = 0
    expected_evidence_sha256: Digest | None = None


def _encoded_size(value: dict[str, Any]) -> int:
    # Bound both SDK representations, including JSON string escaping, conservatively.
    return len(
        json.dumps(
            CallToolResult(
                content=[TextContent(type="text", text=json.dumps(value, indent=2))],
                structured_content=value,
            ).model_dump(mode="json", by_alias=True)
        ).encode()
    )


def _page(value: str | None, offset: int, limit: int) -> tuple[str | None, dict[str, Any] | None]:
    if value is None:
        if offset:
            raise ValueError("unavailable evidence field has no continuation")
        return None, None
    raw = value.encode("utf-8")
    if offset > len(raw) or (offset < len(raw) and raw[offset] & 0xC0 == 0x80):
        raise EvidenceOffsetError("evidence offset is outside a UTF-8 boundary")
    end = min(len(raw), offset + limit)
    while end < len(raw) and raw[end] & 0xC0 == 0x80:
        end -= 1
    chunk = raw[offset:end]
    return chunk.decode("utf-8"), {
        "offset_bytes": offset,
        "returned_bytes": len(chunk),
        "total_bytes": len(raw),
        "next_offset_bytes": end if end < len(raw) else None,
        "complete": offset == 0 and end == len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
    }


def _page_limits(content_first: bool) -> Iterator[tuple[int, int]]:
    limit = MAX_EVIDENCE_PAGE_BYTES
    if content_first:
        # Answer reads need normalized text before duplicate envelopes or original text.
        while limit >= 4:
            yield MAX_EVIDENCE_PAGE_BYTES, limit
            limit //= 2
        limit = MAX_EVIDENCE_PAGE_BYTES // 2
    while limit >= 4:
        yield limit, 4 if content_first else limit
        limit //= 2


def _delivery_order(evidence: dict[str, Any]) -> dict[str, Any]:
    # Put access, completeness and attribution before potentially long source text.
    evidence = {key: value for key, value in evidence.items() if key != "next_content_request"}
    page = evidence.get("evidence_page")
    if (
        page is not None
        and (offset := page["fields"]["content_text"]["next_offset_bytes"]) is not None
    ):
        evidence["next_content_request"] = {
            "event_id": evidence["event_id"],
            "include_context": "conversation_context" in evidence,
            "page": {
                "content_offset": offset,
                "expected_evidence_sha256": page["evidence_sha256"],
            },
        }
    leading = (
        "event_id",
        "raw_record_access",
        "evidence_page",
        "actor_kind",
        "authority",
        "source_system",
        "occurred_at",
        "next_content_request",
        "content_text",
    )
    return {**{key: evidence[key] for key in leading if key in evidence}, **evidence}


def _bounded_delivery(
    evidence: dict[str, Any], text_max_bytes: int | None, *, omit_context: bool = False
) -> dict[str, Any] | None:
    result = _delivery_order(evidence)
    if _fits(result, text_max_bytes):
        return result
    context = evidence.get("conversation_context")
    if not omit_context or text_max_bytes is None or not context or not context.get("results"):
        return None
    # Adjacent previews are supplemental. Keep their identities, not misleading partial rows.
    result["conversation_context"] = {
        **context,
        "results": [],
        "omitted_reason": "response_limit_fetch_omitted_event_ids",
        "omitted_event_ids": [row["event_id"] for row in context["results"]],
        "omitted_count": len(context["results"]),
    }
    return result if _fits(result, text_max_bytes) else None


def deliver_evidence(
    evidence: dict[str, Any],
    request: EvidencePageRequest | None = None,
    *,
    text_max_bytes: int | None = None,
) -> dict[str, Any]:
    """Page an already authorized, hash-verified read without altering stored evidence."""
    request = request or EvidencePageRequest()
    binding = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    offsets = (request.content_offset, request.raw_offset, request.original_content_offset)
    if any(offsets) and request.expected_evidence_sha256 is None:
        raise EvidenceVersionRequiredError("evidence continuation requires its version digest")
    if request.expected_evidence_sha256 is not None and request.expected_evidence_sha256 != binding:
        raise EvidenceChangedError("evidence changed; restart from the first page")

    original = evidence["correction"]["original"] if evidence.get("correction") else None
    fields = {
        "content_text": (evidence["content_text"], request.content_offset),
        "raw_record": (evidence["raw_record"], request.raw_offset),
        "original_content_text": (
            original["content_text"] if original is not None else None,
            request.original_content_offset,
        ),
    }
    content_first = request.raw_offset == 0 and request.original_content_offset == 0
    for content_limit, other_limit in _page_limits(content_first):
        pages = {
            key: _page(value, offset, content_limit if key == "content_text" else other_limit)
            for key, (value, offset) in fields.items()
        }
        if (
            not any(offsets)
            and all(page is None or page["complete"] for _, page in pages.values())
            and _fits(evidence, text_max_bytes)
        ):
            return _delivery_order(evidence)
        result = copy.deepcopy(evidence)
        result["content_text"] = pages["content_text"][0]
        result["raw_record"] = pages["raw_record"][0]
        if original is not None:
            result["correction"]["original"]["content_text"] = pages["original_content_text"][0]
        raw_page = pages["raw_record"][1]
        if raw_page is not None and not raw_page["complete"]:
            result["raw_record_access"] = "partial_exact"
        result["evidence_page"] = {
            "version": 1,
            "evidence_sha256": binding,
            "offset_unit": "utf8_bytes",
            "fields": {key: page for key, (_, page) in pages.items()},
        }
        if (
            bounded := _bounded_delivery(
                result,
                text_max_bytes,
                omit_context=other_limit == 4
                or all(page is None or page["complete"] for _, page in pages.values()),
            )
        ) is not None:
            return bounded
    raise ValueError("evidence metadata exceeds the bounded response limit")


def _fits(value: dict[str, Any], text_max_bytes: int | None) -> bool:
    limit = MAX_EVIDENCE_RESPONSE_BYTES
    if text_max_bytes is not None:
        limit = min(limit, text_max_bytes)
    return _encoded_size(value) <= limit


class _FieldPage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    offset_bytes: Offset
    returned_bytes: Offset
    total_bytes: Offset
    next_offset_bytes: Offset | None
    complete: bool
    sha256: Digest
    chunk_sha256: Digest


class _EvidencePage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Annotated[StrictInt, Field(ge=1, le=1)]
    evidence_sha256: Digest
    offset_unit: str
    fields: dict[str, _FieldPage | None]


def limit_evidence_text(evidence: dict[str, Any], text_max_bytes: int) -> dict[str, Any]:
    """Shrink an authorized upstream page, retaining its full-evidence continuation binding."""
    if "evidence_page" not in evidence:
        return deliver_evidence(evidence, text_max_bytes=text_max_bytes)
    page = _EvidencePage.model_validate(evidence["evidence_page"])
    original = evidence["correction"]["original"] if evidence.get("correction") else None
    fields = {
        "content_text": evidence["content_text"],
        "raw_record": evidence["raw_record"],
        "original_content_text": original["content_text"] if original is not None else None,
    }
    if page.offset_unit != "utf8_bytes" or set(page.fields) != set(fields):
        raise ValueError("invalid upstream evidence page")
    for key, value in fields.items():
        info = page.fields[key]
        if value is None and info is None:
            continue
        if not isinstance(value, str) or info is None:
            raise ValueError("invalid upstream evidence field")
        end = info.offset_bytes + info.returned_bytes
        if (
            len(value.encode()) != info.returned_bytes
            or hashlib.sha256(value.encode()).hexdigest() != info.chunk_sha256
            or end > info.total_bytes
            or info.next_offset_bytes != (end if end < info.total_bytes else None)
            or info.complete != (info.offset_bytes == 0 and end == info.total_bytes)
            or (info.complete and info.sha256 != info.chunk_sha256)
            or (end < info.total_bytes and info.returned_bytes == 0)
        ):
            raise ValueError("inconsistent upstream evidence field")
    if (
        bounded := _bounded_delivery(
            evidence,
            text_max_bytes,
            omit_context=all(info is None or info.complete for info in page.fields.values()),
        )
    ) is not None:
        return bounded
    content_first = all(
        (info := page.fields[key]) is None or info.offset_bytes == 0
        for key in ("raw_record", "original_content_text")
    )
    for content_limit, other_limit in _page_limits(content_first):
        result = copy.deepcopy(evidence)
        for key, value in fields.items():
            info = page.fields[key]
            if info is None:
                continue
            chunk, local = _page(value, 0, content_limit if key == "content_text" else other_limit)
            assert local is not None
            end = info.offset_bytes + local["returned_bytes"]
            result["evidence_page"]["fields"][key].update(
                returned_bytes=local["returned_bytes"],
                next_offset_bytes=end if end < info.total_bytes else None,
                complete=info.offset_bytes == 0 and end == info.total_bytes,
                chunk_sha256=local["chunk_sha256"],
            )
            if key == "original_content_text":
                result["correction"]["original"]["content_text"] = chunk
            else:
                result[key] = chunk
        raw = result["evidence_page"]["fields"]["raw_record"]
        if raw is not None and not raw["complete"]:
            result["raw_record_access"] = "partial_exact"
        if (
            bounded := _bounded_delivery(result, text_max_bytes, omit_context=other_limit == 4)
        ) is not None:
            return bounded
    raise ValueError("evidence metadata exceeds the bounded response limit")
