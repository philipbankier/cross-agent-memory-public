from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from cross_assistant_memory.evidence_delivery import (
    MAX_EVIDENCE_PAGE_BYTES,
    MAX_EVIDENCE_RESPONSE_BYTES,
    EvidencePageRequest,
    deliver_evidence,
    limit_evidence_text,
)
from tests.test_evidence_delivery import (
    _evidence,  # pyright: ignore[reportPrivateUsage]
    _sdk_size,  # pyright: ignore[reportPrivateUsage]
)

TEXT_CAP = 16000


def _corrected_evidence(text: str) -> dict[str, Any]:
    evidence = _evidence(text)
    raw = json.dumps({"text": text, "synthetic_metadata": "m" * 626}, ensure_ascii=False)
    evidence.update(
        raw_record=raw,
        source_object_id="sha256:" + hashlib.sha256(raw.encode()).hexdigest(),
        source_locator={"record": 7, "branch": "synthetic"},
        correction={
            "correction_id": "correction:synthetic",
            "reason": "Synthetic correction",
            "original": {"content_text": text, "authority": "user_assertion"},
        },
    )
    return evidence


def _binding(evidence: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _texts(evidence: dict[str, Any]) -> dict[str, str | None]:
    return {
        "content_text": evidence["content_text"],
        "raw_record": evidence["raw_record"],
        "original_content_text": evidence["correction"]["original"]["content_text"],
    }


def _assert_page(result: dict[str, Any], evidence: dict[str, Any]) -> None:
    text = json.dumps(result, indent=2)
    assert len(text.encode()) <= TEXT_CAP
    assert MAX_EVIDENCE_RESPONSE_BYTES == 512 * 1024
    assert MAX_EVIDENCE_PAGE_BYTES == 64 * 1024
    assert _sdk_size(result) <= TEXT_CAP
    page = result["evidence_page"]
    assert page["version"] == 1
    assert page["offset_unit"] == "utf8_bytes"
    assert page["evidence_sha256"] == _binding(evidence)
    originals = _texts(evidence)
    assert set(page["fields"]) == set(originals)
    for field, value in _texts(result).items():
        info = page["fields"][field]
        original = originals[field]
        if original is None:
            assert value is None and info is None
            continue
        assert isinstance(value, str)
        full, chunk = original.encode(), value.encode()
        offset = info["offset_bytes"]
        end = offset + len(chunk)
        assert chunk == full[offset:end]
        assert info["returned_bytes"] == len(chunk) <= MAX_EVIDENCE_PAGE_BYTES
        assert info["total_bytes"] == len(full)
        assert info["sha256"] == hashlib.sha256(full).hexdigest()
        assert info["chunk_sha256"] == hashlib.sha256(chunk).hexdigest()
        assert info["next_offset_bytes"] == (end if end < len(full) else None)
        assert info["complete"] == (offset == 0 and end == len(full))
        if end < len(full):
            assert chunk
    raw = page["fields"]["raw_record"]
    assert result["raw_record_access"] == (
        "partial_exact"
        if raw is not None and not raw["complete"]
        else evidence["raw_record_access"]
    )
    restored = copy.deepcopy(result)
    del restored["evidence_page"]
    next_offset = page["fields"]["content_text"]["next_offset_bytes"]
    if next_offset is not None:
        assert restored.pop("next_content_request") == {
            "event_id": evidence["event_id"],
            "include_context": False,
            "page": {
                "content_offset": next_offset,
                "expected_evidence_sha256": page["evidence_sha256"],
            },
        }
    else:
        assert "next_content_request" not in restored
    restored["content_text"] = evidence["content_text"]
    restored["raw_record"] = evidence["raw_record"]
    restored["raw_record_access"] = evidence["raw_record_access"]
    restored["correction"]["original"]["content_text"] = originals["original_content_text"]
    assert restored == evidence


def test_fitting_whole_evidence_and_upstream_page_are_unchanged() -> None:
    evidence = _corrected_evidence("Small synthetic decision.")
    before = copy.deepcopy(evidence)
    order = list(evidence)
    for result in (
        deliver_evidence(evidence, text_max_bytes=TEXT_CAP),
        limit_evidence_text(evidence, TEXT_CAP),
    ):
        assert result == evidence
        assert list(result)[:3] == ["event_id", "raw_record_access", "authority"]
    upstream = deliver_evidence(
        evidence, EvidencePageRequest(content_offset=1, expected_evidence_sha256=_binding(evidence))
    )
    upstream_before = copy.deepcopy(upstream)
    upstream_order = list(upstream)
    result = limit_evidence_text(upstream, TEXT_CAP)
    assert result == upstream
    assert list(result)[:3] == ["event_id", "raw_record_access", "evidence_page"]
    assert list(upstream) == upstream_order
    assert upstream == upstream_before
    assert evidence == before
    assert list(evidence) == order


def test_initial_read_keeps_all_5593_normalized_bytes_before_duplicate_fields() -> None:
    evidence = _corrected_evidence("n" * 5593)
    before = copy.deepcopy(evidence)
    assert len(evidence["raw_record"].encode()) == 6257
    assert len(json.dumps(evidence, indent=2).encode()) > TEXT_CAP
    for result in (
        deliver_evidence(evidence, text_max_bytes=TEXT_CAP),
        limit_evidence_text(evidence, TEXT_CAP),
    ):
        _assert_page(result, evidence)
        assert result["content_text"] == evidence["content_text"]
        fields = result["evidence_page"]["fields"]
        assert fields["content_text"]["complete"]
        assert fields["content_text"]["next_offset_bytes"] is None
        for field in ("raw_record", "original_content_text"):
            assert 0 < fields[field]["returned_bytes"] < fields[field]["total_bytes"]
            assert fields[field]["next_offset_bytes"] == fields[field]["returned_bytes"]
    assert evidence == before


def test_normalized_only_continuation_keeps_full_tail_and_upstream_binding() -> None:
    evidence = _corrected_evidence("n" * 20000)
    before = copy.deepcopy(evidence)
    offset = 20000 - 5593
    request = EvidencePageRequest(
        content_offset=offset, expected_evidence_sha256=_binding(evidence)
    )
    upstream = deliver_evidence(evidence, request)
    upstream_before = copy.deepcopy(upstream)
    assert len(json.dumps(upstream, indent=2).encode()) > TEXT_CAP
    for result in (
        deliver_evidence(evidence, request, text_max_bytes=TEXT_CAP),
        limit_evidence_text(upstream, TEXT_CAP),
    ):
        _assert_page(result, evidence)
        fields = result["evidence_page"]["fields"]
        content = fields["content_text"]
        assert result["content_text"] == evidence["content_text"][offset:]
        assert content["offset_bytes"] == offset
        assert content["returned_bytes"] == 5593
        assert content["next_offset_bytes"] is None
        assert not content["complete"]
        assert content["sha256"] != content["chunk_sha256"]
        assert fields["raw_record"]["offset_bytes"] == 0
        assert fields["original_content_text"]["offset_bytes"] == 0
    assert upstream == upstream_before
    assert evidence == before


@pytest.mark.parametrize("relay", [False, True], ids=["direct", "relay"])
@pytest.mark.parametrize("withheld", [False, True], ids=["raw-available", "raw-withheld"])
def test_20k_normalized_content_gets_more_bytes_and_reconstructs_until_complete(
    relay: bool,
    withheld: bool,
) -> None:
    sentinel = "Final synthetic instruction."
    evidence = _corrected_evidence("n" * (20000 - len(sentinel)) + sentinel)
    if withheld:
        evidence.update(raw_record=None, raw_record_access="withheld_uninspected_attachment")
    before = copy.deepcopy(evidence)
    assembled = b""
    for _ in range(10):
        request = EvidencePageRequest(
            content_offset=len(assembled), expected_evidence_sha256=_binding(evidence)
        )
        if relay:
            upstream = deliver_evidence(evidence, request)
            upstream_before = copy.deepcopy(upstream)
            result = limit_evidence_text(upstream, TEXT_CAP)
            assert upstream == upstream_before
        else:
            result = deliver_evidence(evidence, request, text_max_bytes=TEXT_CAP)
        _assert_page(result, evidence)
        assert list(result)[:3] == ["event_id", "raw_record_access", "evidence_page"]
        fields = result["evidence_page"]["fields"]
        info = fields["content_text"]
        assert info["offset_bytes"] == len(assembled)
        if withheld:
            assert fields["raw_record"] is None and result["raw_record"] is None
        else:
            assert fields["raw_record"]["offset_bytes"] == 0
        assert fields["original_content_text"]["offset_bytes"] == 0
        if not assembled:
            assert sentinel not in result["content_text"]
            assert info["returned_bytes"] > max(
                field["returned_bytes"]
                for name, field in fields.items()
                if name != "content_text" and field is not None
            )
            assert info["next_offset_bytes"] is not None
        assert not info["complete"]
        assembled += result["content_text"].encode()
        if info["next_offset_bytes"] is None:
            assert result["content_text"].endswith(sentinel)
            break
        assert info["next_offset_bytes"] == len(assembled)
    else:
        pytest.fail("normalized-only continuation did not finish")
    assert assembled == evidence["content_text"].encode()
    assert evidence == before


@pytest.mark.parametrize(
    ("field", "parameter"),
    [("raw_record", "raw_offset"), ("original_content_text", "original_content_offset")],
)
def test_nonzero_duplicate_continuations_stay_balanced_and_reconstruct_utf8(
    field: str, parameter: str
) -> None:
    evidence = _corrected_evidence("n" * 20000 + '\u00e9\u6f22\U0001f642\n\\"' * 17)
    before = copy.deepcopy(evidence)
    first = deliver_evidence(evidence, text_max_bytes=TEXT_CAP)
    _assert_page(first, evidence)
    first_text = _texts(first)[field]
    assert isinstance(first_text, str)
    assembled = first_text.encode()
    assert first["evidence_page"]["fields"][field]["next_offset_bytes"] == len(assembled) > 0
    for index in range(32):
        request = EvidencePageRequest.model_validate(
            {parameter: len(assembled), "expected_evidence_sha256": _binding(evidence)}
        )
        upstream = deliver_evidence(evidence, request)
        upstream_before = copy.deepcopy(upstream)
        direct = deliver_evidence(evidence, request, text_max_bytes=TEXT_CAP)
        result = limit_evidence_text(upstream, TEXT_CAP)
        assert result == direct
        assert upstream == upstream_before
        _assert_page(result, evidence)
        fields = result["evidence_page"]["fields"]
        if index == 0:
            returned = [info["returned_bytes"] for info in fields.values()]
            assert min(returned) > 0 and len(set(returned)) == 1
        info = fields[field]
        assert info["offset_bytes"] == len(assembled)
        assert not info["complete"]
        chunk = _texts(result)[field]
        assert isinstance(chunk, str)
        assembled += chunk.encode()
        if info["next_offset_bytes"] is None:
            break
        assert info["next_offset_bytes"] == len(assembled)
    else:
        pytest.fail("duplicate-field continuation did not finish")
    original = _texts(evidence)[field]
    assert isinstance(original, str)
    assert assembled == original.encode()
    assert evidence == before


def test_priority_keeps_withheld_raw_unavailable_without_losing_metadata() -> None:
    evidence = _corrected_evidence("n" * 5593)
    evidence.update(raw_record=None, raw_record_access="withheld_uninspected_attachment")
    evidence["correction"]["original"]["content_text"] = "o" * 20000
    before = copy.deepcopy(evidence)
    upstream = deliver_evidence(
        evidence, EvidencePageRequest(content_offset=1, expected_evidence_sha256=_binding(evidence))
    )
    upstream_before = copy.deepcopy(upstream)
    for result in (
        deliver_evidence(evidence, text_max_bytes=TEXT_CAP),
        limit_evidence_text(upstream, TEXT_CAP),
    ):
        _assert_page(result, evidence)
        fields = result["evidence_page"]["fields"]
        assert result["raw_record"] is None and fields["raw_record"] is None
        assert result["raw_record_access"] == "withheld_uninspected_attachment"
        assert fields["content_text"]["next_offset_bytes"] is None
        assert fields["original_content_text"]["next_offset_bytes"] is not None
    assert upstream == upstream_before
    assert evidence == before
