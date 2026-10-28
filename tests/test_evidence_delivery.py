from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import sqlite3
from contextlib import nullcontext
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest
from mcp import Client
from mcp.server import MCPServer
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from cross_assistant_memory import mcp_server
from cross_assistant_memory.config import Settings
from cross_assistant_memory.evidence_delivery import (
    EVIDENCE_CHANGED_MESSAGE,
    EVIDENCE_OFFSET_MESSAGE,
    EVIDENCE_VERSION_REQUIRED_MESSAGE,
    MAX_EVIDENCE_PAGE_BYTES,
    MAX_EVIDENCE_RESPONSE_BYTES,
    EvidenceChangedError,
    EvidenceOffsetError,
    EvidencePageRequest,
    EvidenceVersionRequiredError,
    deliver_evidence,
    limit_evidence_text,
)
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.mcp_client import create_readonly_relay
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.models import Scope, SourceSystem
from cross_assistant_memory.storage import Ledger
from tests.conftest import write_jsonl
from tests.encrypted_evidence_fixture import (
    _bind,  # pyright: ignore[reportPrivateUsage]
    _case,  # pyright: ignore[reportPrivateUsage]
)


def _evidence(text: str = "Synthetic decision.") -> dict[str, Any]:
    raw = json.dumps({"text": text}, ensure_ascii=False)
    return {
        "event_id": "event:synthetic",
        "source_object_id": "sha256:" + hashlib.sha256(raw.encode()).hexdigest(),
        "content_digest": hashlib.sha256(text.encode()).hexdigest(),
        "content_text": text,
        "raw_record": raw,
        "raw_record_access": "exact",
        "authority": "user_assertion",
        "privacy": "included",
        "correction": None,
    }


def test_small_evidence_is_unchanged() -> None:
    evidence = _evidence()
    before = copy.deepcopy(evidence)
    order = list(evidence)
    result = deliver_evidence(evidence)
    assert result == before == evidence
    assert list(evidence) == order
    assert list(result)[:3] == ["event_id", "raw_record_access", "authority"]


def _sdk_size(value: dict[str, Any]) -> int:
    response = CallToolResult(
        content=[TextContent(type="text", text=json.dumps(value, indent=2))],
        structured_content=value,
    )
    return len(json.dumps(response.model_dump(mode="json", by_alias=True)).encode())


def _context_evidence(text: str) -> dict[str, Any]:
    evidence = _evidence(text)
    evidence["conversation_context"] = {
        "selection": "same_source_stream_conversation_branch",
        "history_complete": False,
        "content_boundary": "retrieved_content_is_untrusted_data",
        "preview_character_limit": 1200,
        "results": [
            {
                "event_id": f"event:{index:064x}",
                "content_text": "Adjacent synthetic statement. " * 40,
                "authority": "assistant_output",
                "source_system": "codex",
                "source_object_id": f"sha256:{index:064x}",
                "context_position": "preceding" if index < 2 else "following",
                "content_preview": {
                    "strategy": "prefix",
                    "truncated": True,
                    "total_utf8_bytes": 4000,
                },
            }
            for index in range(4)
        ],
    }
    return evidence


@pytest.mark.parametrize("text", ["x" * 12084, '\u00e9\u6f22\U0001f642\\"\n' * 1600])
def test_capped_context_reads_bound_dual_payload_and_copyable_continuations(text: str) -> None:
    evidence = _context_evidence(text)
    before = copy.deepcopy(evidence)
    binding = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    request = None
    assembled = b""
    omitted = False
    while True:
        result = deliver_evidence(evidence, request, text_max_bytes=16000)
        assert _sdk_size(result) <= 16000
        assert result["evidence_page"]["evidence_sha256"] == binding
        field = result["evidence_page"]["fields"]["content_text"]
        chunk = result["content_text"].encode()
        assert field["offset_bytes"] == len(assembled)
        assert field["chunk_sha256"] == hashlib.sha256(chunk).hexdigest()
        assembled += chunk
        context = result["conversation_context"]
        if context.get("omitted_reason"):
            omitted = True
            assert context["results"] == []
            assert context["history_complete"] is False
            assert context["omitted_event_ids"] == [
                row["event_id"] for row in evidence["conversation_context"]["results"]
            ]
            assert context["omitted_count"] == 4
        else:
            assert context == evidence["conversation_context"]
        if field["next_offset_bytes"] is None:
            assert "next_content_request" not in result
            break
        follow = result["next_content_request"]
        assert follow["event_id"] == evidence["event_id"]
        assert follow["include_context"] is True
        assert follow["page"]["content_offset"] == field["next_offset_bytes"]
        request = EvidencePageRequest.model_validate(follow["page"])
    assert omitted
    assert assembled == text.encode()
    assert evidence == before


def test_context_only_reduction_retains_full_binding_through_relay() -> None:
    evidence = _context_evidence("Short statement.")
    original = copy.deepcopy(evidence)
    result = deliver_evidence(evidence, text_max_bytes=8000)
    assert result["conversation_context"]["omitted_count"] == 4
    assert all(
        field is None or field["complete"] for field in result["evidence_page"]["fields"].values()
    )
    assert result["raw_record_access"] == "exact"
    binding = result["evidence_page"]["evidence_sha256"]
    assert limit_evidence_text(result, 8000)["evidence_page"]["evidence_sha256"] == binding
    assert evidence == original
    evidence["conversation_context"]["results"][-1]["content_text"] = "Changed neighbor."
    with pytest.raises(EvidenceChangedError):
        deliver_evidence(
            evidence, EvidencePageRequest(expected_evidence_sha256=binding), text_max_bytes=8000
        )


def test_relay_regenerates_hint_after_shrinking_and_keeps_original_context_choice() -> None:
    evidence = _context_evidence("x" * 60000)
    first = deliver_evidence(evidence, text_max_bytes=16000)
    smaller = limit_evidence_text(first, 8000)
    assert _sdk_size(smaller) <= 8000
    assert smaller["next_content_request"]["include_context"] is True
    assert (
        smaller["next_content_request"]["page"]["content_offset"]
        < (first["next_content_request"]["page"]["content_offset"])
    )
    next_page = deliver_evidence(
        evidence,
        EvidencePageRequest.model_validate(smaller["next_content_request"]["page"]),
        text_max_bytes=8000,
    )
    assert next_page["evidence_page"]["fields"]["content_text"]["offset_bytes"] == len(
        smaller["content_text"].encode()
    )
    assert (
        next_page["evidence_page"]["evidence_sha256"] == first["evidence_page"]["evidence_sha256"]
    )
    without_context = {
        key: value for key, value in evidence.items() if key != "conversation_context"
    }
    with pytest.raises(EvidenceChangedError):
        deliver_evidence(
            without_context,
            EvidencePageRequest.model_validate(smaller["next_content_request"]["page"]),
        )
    assert (
        deliver_evidence(without_context, text_max_bytes=8000)["next_content_request"][
            "include_context"
        ]
        is False
    )


@pytest.mark.parametrize(
    "text", ["x" * 180000, "\u00e9\u6f22\U0001f642" * 18000, '\x00\n\\"' * 40000]
)
def test_pages_reassemble_exact_utf8_and_bound_both_representations(text: str) -> None:
    evidence = _evidence(text)
    evidence["correction"] = {"original": {"content_text": text + "old"}}
    before = copy.deepcopy(evidence)
    for field, parameter, original in (
        ("content_text", "content_offset", text),
        ("raw_record", "raw_offset", evidence["raw_record"]),
        ("original_content_text", "original_content_offset", text + "old"),
    ):
        offset, assembled, binding = 0, b"", None
        while True:
            result = deliver_evidence(
                evidence,
                EvidencePageRequest.model_validate(
                    {parameter: offset, "expected_evidence_sha256": binding}
                ),
            )
            page = result["evidence_page"]
            binding = page["evidence_sha256"]
            info = page["fields"][field]
            chunk = (
                result["correction"]["original"]["content_text"]
                if field == "original_content_text"
                else result[field]
            ).encode()
            assert info["offset_bytes"] == len(assembled) == offset
            assert info["returned_bytes"] == len(chunk) <= MAX_EVIDENCE_PAGE_BYTES
            assert info["total_bytes"] == len(original.encode())
            assert info["chunk_sha256"] == hashlib.sha256(chunk).hexdigest()
            assert info["sha256"] == hashlib.sha256(original.encode()).hexdigest()
            assert not info["complete"]
            encoded = json.dumps(
                {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "structuredContent": result,
                }
            ).encode()
            assert len(encoded) <= MAX_EVIDENCE_RESPONSE_BYTES
            assembled += chunk
            offset = info["next_offset_bytes"]
            if offset is None:
                break
        assert assembled == original.encode()
    assert evidence == before


@pytest.mark.parametrize("value", [True, False, -1, 1.5, "1", 2**31])
@pytest.mark.parametrize("field", ["content_offset", "raw_offset", "original_content_offset"])
def test_offset_schema_rejects_invalid_values(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        EvidencePageRequest.model_validate({field: value})


def test_continuation_requires_binding_and_refuses_invalid_utf8_offset() -> None:
    evidence = _evidence("\u00e9" * 50000)
    binding = deliver_evidence(evidence)["evidence_page"]["evidence_sha256"]
    with pytest.raises(EvidenceVersionRequiredError, match="version digest"):
        deliver_evidence(evidence, EvidencePageRequest(content_offset=2))
    for offset in (1, 100001):
        with pytest.raises(EvidenceOffsetError, match="UTF-8 boundary"):
            deliver_evidence(
                evidence,
                EvidencePageRequest(content_offset=offset, expected_evidence_sha256=binding),
            )


@pytest.mark.parametrize(
    "change", ["text", "authority", "source_object_id", "privacy", "correction", "context"]
)
def test_continuation_refuses_changed_evidence_even_if_it_becomes_small(change: str) -> None:
    evidence = _evidence("x" * 80000)
    binding = deliver_evidence(evidence)["evidence_page"]["evidence_sha256"]
    changed = copy.deepcopy(evidence)
    if change == "text":
        changed = _evidence("short")
    elif change == "correction":
        changed["correction"] = {
            "original": {"content_text": evidence["content_text"]},
            "reason": "changed",
        }
    elif change == "context":
        changed["conversation_context"] = {"results": [{"event_id": "another"}]}
    else:
        changed[change] = "changed"
    with pytest.raises(EvidenceChangedError, match="evidence changed"):
        deliver_evidence(
            changed, EvidencePageRequest(raw_offset=1, expected_evidence_sha256=binding)
        )


@pytest.mark.parametrize("offset", [0, 2, 100000])
def test_valid_utf8_offsets_stay_valid_even_when_not_the_next_cursor(offset: int) -> None:
    evidence = _evidence("\u00e9" * 50000)
    first = deliver_evidence(evidence)
    result = deliver_evidence(
        evidence,
        EvidencePageRequest(
            content_offset=offset,
            expected_evidence_sha256=first["evidence_page"]["evidence_sha256"],
        ),
    )
    field = result["evidence_page"]["fields"]["content_text"]
    assert field["offset_bytes"] == offset
    assert (
        result["content_text"].encode()
        == evidence["content_text"].encode()[offset : offset + field["returned_bytes"]]
    )
    if offset == field["total_bytes"]:
        assert field["returned_bytes"] == 0
        assert field["next_offset_bytes"] is None


@pytest.mark.parametrize(
    ("error_type", "message"),
    [
        (EvidenceVersionRequiredError, EVIDENCE_VERSION_REQUIRED_MESSAGE),
        (EvidenceChangedError, EVIDENCE_CHANGED_MESSAGE),
        (EvidenceOffsetError, EVIDENCE_OFFSET_MESSAGE),
    ],
)
def test_evidence_feedback_never_uses_marker_exception_text(
    error_type: type[ValueError], message: str
) -> None:
    server = MCPServer("Synthetic secret-free evidence errors")

    def operation() -> None:
        raise error_type("synthetic-private-sentinel /synthetic/private/path")

    @server.tool()
    def memory_get_evidence() -> None:
        mcp_server._authorized_tool_call("evidence recovery", operation)  # pyright: ignore[reportPrivateUsage]

    async def exercise() -> None:
        async with Client(server, cache=None) as client:
            result = await client.call_tool("memory_get_evidence", {})
            assert result.is_error
            assert result.content == [
                TextContent(
                    type="text", text=f"Error executing tool memory_get_evidence: {message}"
                )
            ]
            assert "sentinel" not in result.model_dump_json()
            assert "/synthetic/private/path" not in result.model_dump_json()

    asyncio.run(exercise())


@pytest.mark.parametrize("relay_depth", [0, 1, 2])
def test_real_server_evidence_feedback_survives_relays_and_rechecks_access(
    tmp_path: Path, relay_depth: int
) -> None:
    settings = Settings(tmp_path / "node")
    ledger = Ledger(settings)
    prefix = "Synthetic continuation feedback. "
    text = prefix + "\u00e9" * 16000
    source = write_jsonl(
        tmp_path / "continuation.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "continuation", "source": "vscode"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": text}],
                },
            },
        ],
    )
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )
    event_id = ledger.search("Synthetic continuation")[0].event_id
    generation = ledger.generation_digest()
    origin = create_mcp_server(
        settings, transport="stdio", read_only=True, evidence_text_max_bytes=16000
    )

    async def exercise() -> None:
        async with Client(origin, cache=None) as upstream:
            server: Any = origin
            for _ in range(relay_depth):
                inner = server
                server = await create_readonly_relay(lambda inner=inner: Client(inner, cache=None))
            async with Client(server, cache=None) as client:
                arguments = {"event_id": event_id, "include_context": True}
                direct = await upstream.call_tool("memory_get_evidence", arguments)
                first = await client.call_tool("memory_get_evidence", arguments)
                assert first.model_dump() == direct.model_dump()
                assert not first.is_error
                value = cast(dict[str, Any], first.structured_content)
                page = value["evidence_page"]
                binding = page["evidence_sha256"]
                content = page["fields"]["content_text"]
                next_offset = content["next_offset_bytes"]
                assert next_offset is not None
                cases = [
                    (
                        {"content_offset": content["total_bytes"] + 1},
                        True,
                        EVIDENCE_VERSION_REQUIRED_MESSAGE,
                    ),
                    (
                        {"content_offset": content["total_bytes"]},
                        False,
                        EVIDENCE_VERSION_REQUIRED_MESSAGE,
                    ),
                    (
                        {"content_offset": next_offset, "expected_evidence_sha256": binding},
                        False,
                        EVIDENCE_CHANGED_MESSAGE,
                    ),
                    (
                        {"content_offset": next_offset, "expected_evidence_sha256": "0" * 64},
                        True,
                        EVIDENCE_CHANGED_MESSAGE,
                    ),
                    (
                        {
                            "content_offset": content["total_bytes"] + 1,
                            "expected_evidence_sha256": binding,
                        },
                        True,
                        EVIDENCE_OFFSET_MESSAGE,
                    ),
                    (
                        {
                            "content_offset": len(prefix.encode()) + 1,
                            "expected_evidence_sha256": binding,
                        },
                        True,
                        EVIDENCE_OFFSET_MESSAGE,
                    ),
                ]
                for request_page, include_context, message in cases:
                    result = await client.call_tool(
                        "memory_get_evidence",
                        {
                            "event_id": event_id,
                            "include_context": include_context,
                            "page": request_page,
                        },
                    )
                    expected = CallToolResult(
                        is_error=True,
                        content=[
                            TextContent(
                                type="text",
                                text=f"Error executing tool memory_get_evidence: {message}",
                            )
                        ],
                    )
                    assert result.model_dump(exclude={"meta"}) == expected.model_dump(
                        exclude={"meta"}
                    )
                    assert event_id not in result.model_dump_json()
                    assert binding not in result.model_dump_json()
                    assert str(source) not in result.model_dump_json()
                    assert prefix not in result.model_dump_json()
                continuation_args = {
                    **arguments,
                    "page": {"content_offset": next_offset, "expected_evidence_sha256": binding},
                }
                direct_next = await upstream.call_tool("memory_get_evidence", continuation_args)
                next_result = await client.call_tool("memory_get_evidence", continuation_args)
                assert not next_result.is_error
                assert next_result.model_dump() == direct_next.model_dump()
                next_value = cast(dict[str, Any], next_result.structured_content)
                next_field = next_value["evidence_page"]["fields"]["content_text"]
                assert next_value["evidence_page"]["evidence_sha256"] == binding
                assert next_field["sha256"] == hashlib.sha256(text.encode()).hexdigest()
                assert (
                    next_value["content_text"].encode()
                    == text.encode()[next_offset : next_offset + next_field["returned_bytes"]]
                )
                assert ledger.generation_digest() == generation
                with sqlite3.connect(settings.database_path) as connection:
                    connection.execute(
                        "UPDATE events SET privacy='no_memory' WHERE event_id=?", (event_id,)
                    )
                denied = await client.call_tool(
                    "memory_get_evidence", {**arguments, "page": {"content_offset": next_offset}}
                )
                assert denied.is_error and denied.structured_content is None
                assert not any(
                    message in denied.model_dump_json()
                    for message in (
                        EVIDENCE_VERSION_REQUIRED_MESSAGE,
                        EVIDENCE_CHANGED_MESSAGE,
                        EVIDENCE_OFFSET_MESSAGE,
                    )
                )
                assert event_id not in denied.model_dump_json()
                assert str(source) not in denied.model_dump_json()

    asyncio.run(asyncio.wait_for(exercise(), timeout=30))


def test_withheld_raw_stays_unavailable() -> None:
    evidence = _evidence("x" * 80000)
    evidence.update(raw_record=None, raw_record_access="withheld_uninspected_attachment")
    result = deliver_evidence(evidence)
    assert result["raw_record"] is None
    assert result["raw_record_access"] == "withheld_uninspected_attachment"
    assert result["evidence_page"]["fields"]["raw_record"] is None
    with pytest.raises(ValueError, match="unavailable evidence field"):
        deliver_evidence(
            evidence,
            EvidencePageRequest(
                raw_offset=1, expected_evidence_sha256=result["evidence_page"]["evidence_sha256"]
            ),
        )


def test_oversized_metadata_refuses_instead_of_silent_omission() -> None:
    evidence = _evidence()
    evidence["source_locator"] = "synthetic-private-sentinel" * 40000
    with pytest.raises(ValueError, match="metadata exceeds") as caught:
        deliver_evidence(evidence)
    assert "sentinel" not in str(caught.value)


@pytest.mark.parametrize(
    "text",
    ["x" * 12000, "\u00e9\u6f22\U0001f642" * 3000, '\x00\n\\"' * 3000],
    ids=["ascii", "unicode", "escaped"],
)
def test_near_cap_metadata_pages_through_sdk_and_codex_envelopes(text: str) -> None:
    evidence = _evidence(text)
    evidence["source_locator"] = "m" * 252000
    evidence["correction"] = {"original": {"content_text": text}}
    server = MCPServer("Synthetic bounded delivery")

    @server.tool()
    def evidence_page() -> dict[str, Any]:
        return deliver_evidence(evidence)

    async def exercise() -> None:
        async with Client(server) as client:
            response = await client.call_tool("evidence_page", {})
            assert not response.is_error
            result = cast(dict[str, Any], response.structured_content)
            assert isinstance(response.content[0], TextContent)
            assert json.loads(response.content[0].text) == result
            assert list(json.loads(response.content[0].text)) == list(result)
            assert list(result)[:3] == ["event_id", "raw_record_access", "evidence_page"]
            assert result["source_locator"] == evidence["source_locator"]
            content_bytes = result["evidence_page"]["fields"]["content_text"]["returned_bytes"]
            assert 0 < content_bytes < len(text.encode())
            rpc = {
                "jsonrpc": "2.0",
                "id": 1,
                "result": response.model_dump(mode="json", by_alias=True),
            }
            codex = {
                "type": "item.completed",
                "item": {
                    "id": "synthetic-call",
                    "type": "mcp_tool_call",
                    "server": "cross_agent_memory",
                    "tool": "memory_get_evidence",
                    "arguments": {"event_id": "event:synthetic"},
                    "result": response.model_dump(mode="json"),
                    "status": "completed",
                    "error": None,
                },
            }
            assert len(json.dumps(rpc).encode()) < 1024 * 1024
            assert len(json.dumps(codex).encode()) < 1024 * 1024

    asyncio.run(exercise())


@pytest.mark.parametrize("text_limit", [None, 16000])
@pytest.mark.parametrize("metadata_length", [0, 12000, 544174])
def test_actual_mcp_and_relay_preserve_pages_and_recheck_access(
    tmp_path: Path, text_limit: int | None, metadata_length: int
) -> None:
    settings = Settings(tmp_path / "node")
    ledger = Ledger(settings)
    source = write_jsonl(
        tmp_path / "large.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "large-evidence", "source": "vscode"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "synthetic_metadata": "x" * metadata_length,
                    "content": [{"type": "input_text", "text": "Synthetic GLM and Grok decision."}],
                },
            },
        ],
    )
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )
    event = ledger.search("Synthetic GLM")[0].event_id
    original = ledger.get_evidence(event)
    generation = ledger.generation_digest()
    server = create_mcp_server(settings, transport="stdio", read_only=True)

    async def exercise() -> None:
        async with Client(server, cache=None) as upstream:
            relay = await create_readonly_relay(
                lambda: nullcontext(upstream), evidence_text_max_bytes=text_limit
            )
            async with Client(relay, cache=None) as client:
                tools = await client.list_tools()
                tool = next(tool for tool in tools.tools if tool.name == "memory_get_evidence")
                assert "page" in tool.input_schema["properties"]
                args: dict[str, Any] = {"event_id": event}
                assembled = b""
                while True:
                    response = await client.call_tool("memory_get_evidence", args)
                    assert not response.is_error
                    result = cast(dict[str, Any], response.structured_content)
                    assert isinstance(response.content[0], TextContent)
                    assert json.loads(response.content[0].text) == result
                    assert list(json.loads(response.content[0].text)) == list(result)
                    prefix = ["event_id", "raw_record_access"]
                    if "evidence_page" in result:
                        prefix.append("evidence_page")
                    prefix.extend(["actor_kind", "authority", "source_system", "occurred_at"])
                    assert list(result)[: len(prefix)] == prefix
                    if text_limit is not None:
                        assert len(response.content[0].text.encode()) <= text_limit
                    assert len(response.model_dump_json().encode()) < MAX_EVIDENCE_RESPONSE_BYTES
                    assert result["content_text"] == original["content_text"]
                    assert result["source_object_id"] == original["source_object_id"]
                    if "evidence_page" not in result:
                        assert result == original
                        assembled = result["raw_record"].encode()
                        break
                    assert result["raw_record_access"] == "partial_exact"
                    info = result["evidence_page"]["fields"]["raw_record"]
                    assert info["offset_bytes"] == len(assembled)
                    assembled += result["raw_record"].encode()
                    if info["next_offset_bytes"] is None:
                        break
                    args["page"] = {
                        "raw_offset": info["next_offset_bytes"],
                        "expected_evidence_sha256": result["evidence_page"]["evidence_sha256"],
                    }
                assert assembled.decode() == original["raw_record"]
                assert (
                    "sha256:" + hashlib.sha256(assembled).hexdigest()
                    == original["source_object_id"]
                )
                assert ledger.generation_digest() == generation
                # A later page must traverse the normal privacy check, not a cached cursor.
                with sqlite3.connect(settings.database_path) as connection:
                    connection.execute(
                        "UPDATE events SET privacy='no_memory' WHERE event_id=?", (event,)
                    )
                refused = await client.call_tool("memory_get_evidence", args)
                assert refused.is_error and refused.structured_content is None

    asyncio.run(exercise())


@pytest.mark.parametrize("limit", [True, False, -1, 0, 4095, 512 * 1024 + 1, 4096.0, "16000"])
@pytest.mark.parametrize("read_only", [False, True])
def test_origin_rejects_invalid_text_limit_before_opening_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: object, read_only: bool
) -> None:
    settings = Settings(tmp_path / "node")
    open_ledger = Mock(side_effect=AssertionError("invalid limit must not open the ledger"))
    monkeypatch.setattr("cross_assistant_memory.mcp_server.Ledger", open_ledger)

    with pytest.raises(ValueError, match="evidence text limit"):
        create_mcp_server(
            settings,
            transport="stdio",
            read_only=read_only,
            evidence_text_max_bytes=cast(int, limit),
        )

    open_ledger.assert_not_called()
    assert not settings.data_root.exists()


@pytest.mark.parametrize("limit", [4096, 512 * 1024])
def test_origin_accepts_text_limit_endpoints(tmp_path: Path, limit: int) -> None:
    create_mcp_server(Settings(tmp_path / "node"), transport="stdio", evidence_text_max_bytes=limit)


def test_origin_text_cap_pages_through_sdk_and_rechecks_privacy(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "node")
    ledger = Ledger(settings)
    text = "Synthetic origin decision. " + '\u00e9\u6f22\U0001f642\n\\"' * 1200
    source = write_jsonl(
        tmp_path / "origin.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "origin-evidence", "source": "vscode"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": text}],
                },
            },
        ],
    )
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )
    event = ledger.search("Synthetic origin")[0].event_id
    original = ledger.get_evidence(event)
    generation = ledger.generation_digest()
    binding = hashlib.sha256(
        json.dumps(original, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    default_server = create_mcp_server(settings, transport="stdio", read_only=True)
    capped_server = create_mcp_server(
        settings, transport="stdio", read_only=True, evidence_text_max_bytes=16000
    )

    async def exercise() -> None:
        async with Client(default_server, cache=None) as client:
            response = await client.call_tool("memory_get_evidence", {"event_id": event})
            assert not response.is_error
            assert response.structured_content == original
            assert isinstance(response.content[0], TextContent)
            assert len(response.content[0].text.encode()) > 16000
            assert json.loads(response.content[0].text) == original
            assert list(json.loads(response.content[0].text))[:4] == [
                "event_id",
                "raw_record_access",
                "actor_kind",
                "authority",
            ]

        async with Client(capped_server, cache=None) as client:
            args: dict[str, Any] = {"event_id": event}
            assembled = {"content_text": b"", "raw_record": b""}
            for _ in range(100):
                response = await client.call_tool("memory_get_evidence", args)
                assert not response.is_error
                assert len(response.content) == 1
                assert isinstance(response.content[0], TextContent)
                assert len(response.content[0].text.encode()) <= 16000
                # Clipping clients omit structuredContent, so consume paging metadata from text.
                result = json.loads(response.content[0].text)
                assert result == response.structured_content
                assert list(result) == list(cast(dict[str, Any], response.structured_content))
                assert list(result)[:3] == ["event_id", "raw_record_access", "evidence_page"]
                assert len(response.model_dump_json().encode()) < MAX_EVIDENCE_RESPONSE_BYTES
                assert result["source_object_id"] == original["source_object_id"]
                assert result["content_digest"] == original["content_digest"]
                assert result["raw_record_access"] == "partial_exact"
                page = result["evidence_page"]
                assert page["evidence_sha256"] == binding
                assert page["offset_unit"] == "utf8_bytes"
                done = True
                for field in assembled:
                    info = page["fields"][field]
                    chunk = result[field].encode()
                    assert info["offset_bytes"] == len(assembled[field])
                    assert info["returned_bytes"] == len(chunk)
                    assert info["total_bytes"] == len(original[field].encode())
                    assert info["sha256"] == hashlib.sha256(original[field].encode()).hexdigest()
                    assert info["chunk_sha256"] == hashlib.sha256(chunk).hexdigest()
                    assembled[field] += chunk
                    next_offset = info["next_offset_bytes"]
                    assert next_offset is None or next_offset == len(assembled[field])
                    assert next_offset is None or len(chunk) > 0
                    done = done and next_offset is None
                if done:
                    break
                args["page"] = {
                    "content_offset": len(assembled["content_text"]),
                    "raw_offset": len(assembled["raw_record"]),
                    "expected_evidence_sha256": binding,
                }
            else:
                pytest.fail("origin pagination did not finish")
            assert assembled == {field: original[field].encode() for field in assembled}
            assert (
                "sha256:" + hashlib.sha256(assembled["raw_record"]).hexdigest()
                == original["source_object_id"]
            )
            assert ledger.generation_digest() == generation
            with sqlite3.connect(settings.database_path) as connection:
                connection.execute(
                    "UPDATE events SET privacy='no_memory' WHERE event_id=?", (event,)
                )
            refused = await client.call_tool("memory_get_evidence", args)
            assert refused.is_error and refused.structured_content is None

    asyncio.run(exercise())


@pytest.mark.parametrize("length", [2000, 18000])
def test_client_repages_full_or_paged_evidence_without_changing_binding(length: int) -> None:
    evidence = _evidence('\u00e9\u6f22\U0001f642\n\\"' * length)
    evidence["correction"] = {"original": {"content_text": evidence["content_text"] + "old"}}
    before = copy.deepcopy(evidence)
    names = ("content_text", "raw_record", "original_content_text")
    parameters = ("content_offset", "raw_offset", "original_content_offset")
    expected = dict(
        zip(
            names,
            [evidence[n] for n in names[:2]] + [evidence["content_text"] + "old"],
            strict=True,
        )
    )
    assembled = dict.fromkeys(names, b"")
    offsets = dict.fromkeys(parameters, 0)
    binding = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for _ in range(1000):
        upstream = deliver_evidence(
            evidence, EvidencePageRequest(**offsets, expected_evidence_sha256=binding)
        )
        upstream_before = copy.deepcopy(upstream)
        result = limit_evidence_text(upstream, 16000)
        assert upstream == upstream_before
        assert len(json.dumps(result, indent=2).encode()) <= 16000
        assert result["evidence_page"]["evidence_sha256"] == binding
        done = True
        for name, parameter in zip(names, parameters, strict=True):
            info = result["evidence_page"]["fields"][name]
            text = (
                result["correction"]["original"]["content_text"]
                if name == names[-1]
                else result[name]
            )
            raw = text.encode()
            assert info["offset_bytes"] == len(assembled[name])
            assert info["returned_bytes"] == len(raw)
            assert info["chunk_sha256"] == hashlib.sha256(raw).hexdigest()
            assert info["sha256"] == hashlib.sha256(expected[name].encode()).hexdigest()
            assert info["total_bytes"] == len(expected[name].encode())
            assembled[name] += raw
            offsets[parameter] = len(assembled[name])
            done = done and info["next_offset_bytes"] is None
        assert result["raw_record_access"] == "partial_exact"
        if done:
            break
    else:
        pytest.fail("client pagination did not finish")
    assert assembled == {key: value.encode() for key, value in expected.items()}
    assert evidence == before


@pytest.mark.parametrize(
    "field",
    [
        "returned_bytes",
        "total_bytes",
        "next_offset_bytes",
        "offset_bytes",
        "complete",
        "chunk_sha256",
    ],
)
def test_client_refuses_inconsistent_upstream_page(field: str) -> None:
    evidence = deliver_evidence(_evidence("x" * 90000))
    info = evidence["evidence_page"]["fields"]["raw_record"]
    info[field] = {"complete": True, "chunk_sha256": "0" * 64}.get(field, 1)
    with pytest.raises(ValueError, match="upstream evidence"):
        limit_evidence_text(evidence, 16000)


def test_client_budget_preserves_withholding_and_refuses_oversized_metadata() -> None:
    evidence = _evidence("x" * 90000)
    evidence.update(raw_record=None, raw_record_access="withheld_uninspected_attachment")
    result = limit_evidence_text(deliver_evidence(evidence), 16000)
    assert result["raw_record"] is None
    assert result["raw_record_access"] == evidence["raw_record_access"]
    assert result["evidence_page"]["fields"]["raw_record"] is None
    evidence["source_locator"] = "private-sentinel" * 2000
    with pytest.raises(ValueError, match="metadata exceeds") as caught:
        limit_evidence_text(deliver_evidence(evidence), 16000)
    assert "sentinel" not in str(caught.value)


def test_encrypted_pages_reverify_without_plaintext_cache_and_refuse_after_privacy_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, "filesystem", text="Synthetic encrypted decision " + "x" * 90000)
    _bind(case)
    case.local_object.unlink()
    provider_read = Mock(wraps=case.reader.backend.open)
    monkeypatch.setattr(case.reader.backend, "open", provider_read)
    server = create_mcp_server(
        case.settings, transport="stdio", read_only=True, encrypted_evidence_reader=case.reader
    )

    async def exercise() -> None:
        async with Client(server, cache=None) as client:
            first = await client.call_tool("memory_get_evidence", {"event_id": case.event_id})
            assert not first.is_error
            value = cast(dict[str, Any], first.structured_content)
            page = value["evidence_page"]
            args = {
                "event_id": case.event_id,
                "page": {
                    "raw_offset": page["fields"]["raw_record"]["next_offset_bytes"],
                    "expected_evidence_sha256": page["evidence_sha256"],
                },
            }
            first_reads = provider_read.call_count
            assert first_reads > 0
            second = await client.call_tool("memory_get_evidence", args)
            assert not second.is_error and provider_read.call_count > first_reads
            tail = cast(dict[str, Any], second.structured_content)
            assert tail["evidence_page"]["fields"]["raw_record"]["next_offset_bytes"] is None
            assert tail["raw_record_access"] == "partial_exact"
            assert value["raw_record"] + tail["raw_record"] == case.expected_raw
            assert not case.local_object.exists()
            with sqlite3.connect(case.settings.database_path) as connection:
                connection.execute(
                    "UPDATE events SET privacy='no_memory' WHERE event_id=?", (case.event_id,)
                )
            reads = provider_read.call_count
            denied = await client.call_tool("memory_get_evidence", args)
            assert denied.is_error and provider_read.call_count == reads
            assert not case.local_object.exists()

    asyncio.run(exercise())
