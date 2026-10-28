from __future__ import annotations

import asyncio
import copy
import json
import sqlite3
from contextlib import nullcontext
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest
from mcp import Client
from mcp.server.auth.provider import AccessToken
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.mcp_client import create_readonly_relay
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.models import Capability, ClientKind, Scope, SourceSystem
from cross_assistant_memory.search_delivery import (
    MAX_SEARCH_RESPONSE_BYTES,
    SEARCH_CHANGED_MESSAGE,
    SEARCH_TOO_LARGE_MESSAGE,
    SearchPageRequest,
    deliver_search,
)
from cross_assistant_memory.storage import Ledger
from tests.conftest import write_jsonl


def _workset(text: str = "Synthetic preview. " * 60) -> dict[str, Any]:
    return {
        "results": [
            {
                "event_id": f"event:{index:064x}",
                "content_text": text,
                "authority": "user_assertion" if index % 2 else "assistant_output",
                "source_system": "codex" if index % 3 else "claude_code",
                "workset_roles": ["primary"] if index == 0 else ["minority_source"],
                "content_preview": {"strategy": "prefix", "truncated": True},
                "relations": [{"related_evidence_id": f"event:{index + 1:064x}"}],
            }
            for index in range(20)
        ],
        "selection": {"returned_count": 20, "omitted_counts": {"unselected_candidates": 7}},
    }


@pytest.mark.parametrize("limit", [None, 16000])
def test_small_and_empty_worksets_are_unchanged(limit: int | None) -> None:
    worksets: list[dict[str, Any]] = [
        {"results": []},
        {"results": [{"content_text": "Short synthetic result."}]},
    ]
    for workset in worksets:
        assert deliver_search(workset, {"query": "synthetic"}, text_max_bytes=limit) is workset


def test_default_delivery_preserves_large_workset() -> None:
    workset = _workset()
    assert len(json.dumps(workset, indent=2).encode()) > 16000
    assert deliver_search(workset, {}) is workset


def test_optional_context_cannot_make_an_otherwise_deliverable_hit_unreadable() -> None:
    workset = _workset("x" * 700)
    for item in workset["results"]:
        item["conversation_context"] = {
            "results": [{"event_id": "event:" + "f" * 64, "content_text": "adjacent" * 500}]
        }
    before = copy.deepcopy(workset)
    result = deliver_search(workset, {}, text_max_bytes=4096)
    assert len(result["results"]) == 1
    hit = result["results"][0]
    assert hit["conversation_context"]["results"] == []
    assert hit["conversation_context"]["omitted_reason"].startswith("response_limit")
    assert hit["conversation_context"]["omitted_event_ids"] == ["event:" + "f" * 64]
    assert hit["conversation_context"]["omitted_count"] == 1
    assert {k: v for k, v in hit.items() if k != "conversation_context"} == {
        k: v for k, v in workset["results"][0].items() if k != "conversation_context"
    }
    assert workset == before
    assert len(json.dumps(result, indent=2).encode()) <= 4096
    workset["results"][0]["conversation_context"]["results"][0]["content_text"] = "changed"
    with pytest.raises(ValueError, match="search changed"):
        deliver_search(
            workset,
            {},
            SearchPageRequest(
                result_offset=1, expected_search_sha256=result["search_page"]["search_sha256"]
            ),
            text_max_bytes=4096,
        )


def test_single_hit_context_omission_needs_no_paging_overhead() -> None:
    workset: dict[str, Any] = {"results": [{"content_text": "x" * 1400}]}
    assert len(json.dumps(workset, indent=2).encode()) < 4096
    workset["results"][0]["conversation_context"] = {
        "results": [{"event_id": "event:" + "f" * 64, "content_text": "y" * 1000}]
    }
    result = deliver_search(workset, {}, text_max_bytes=4096)
    assert "search_page" not in result
    assert result["results"][0]["conversation_context"]["omitted_reason"].startswith(
        "response_limit"
    )
    assert len(json.dumps(result, indent=2).encode()) <= 4096
    assert result["results"][0]["conversation_context"]["omitted_event_ids"] == [
        "event:" + "f" * 64
    ]


def test_supplied_binding_is_checked_at_offset_zero_even_without_cap() -> None:
    with pytest.raises(ValueError, match="search changed"):
        deliver_search({"results": []}, {}, SearchPageRequest(expected_search_sha256="0" * 64))


@pytest.mark.parametrize(
    "text",
    ["x" * 1200, "\u00e9\u6f22\U0001f642" * 200, '\x00\n\\"' * 300],
    ids=["ascii", "unicode", "escaped"],
)
def test_pages_preserve_every_result_in_order_without_changing_selection(text: str) -> None:
    workset = _workset(text)
    before = copy.deepcopy(workset)
    arguments: dict[str, Any] = {"query": "synthetic", "limit": 20, "contexts": []}
    request = None
    assembled: list[dict[str, Any]] = []
    binding = None
    for _ in range(20):
        result = deliver_search(workset, arguments, request, text_max_bytes=16000)
        text_response = json.dumps(result, indent=2)
        assert len(text_response.encode()) <= 16000
        envelope = {
            "content": [{"type": "text", "text": text_response}],
            "structuredContent": result,
        }
        assert len(json.dumps(envelope).encode()) <= MAX_SEARCH_RESPONSE_BYTES
        sdk_result = CallToolResult(
            content=[TextContent(type="text", text=text_response)], structured_content=result
        ).model_dump(mode="json", by_alias=True)
        assert len(json.dumps(sdk_result).encode()) <= 16000
        page = result["search_page"]
        assert page["result_offset"] == len(assembled)
        assert page["returned_count"] == len(result["results"]) > 0
        assert page["total_results"] == 20
        assert page["selection_scope"] == "whole_workset"
        assert page["complete"] is False
        assert result["selection"] == workset["selection"]
        assert binding is None or page["search_sha256"] == binding
        binding = page["search_sha256"]
        assembled.extend(result["results"])
        if page["next_result_offset"] is None:
            break
        assert page["next_result_offset"] == len(assembled)
        request = SearchPageRequest(
            result_offset=page["next_result_offset"], expected_search_sha256=binding
        )
    assert assembled == workset["results"]
    assert workset == before


@pytest.mark.parametrize("value", [True, False, -1, 1.5, "1", 21])
def test_invalid_offsets_refuse(value: object) -> None:
    with pytest.raises(ValidationError):
        SearchPageRequest.model_validate({"result_offset": value})


@pytest.mark.parametrize("value", [True, 42, "secret-sentinel", "A" * 64, "a" * 63])
def test_invalid_binding_refuses(value: object) -> None:
    with pytest.raises(ValidationError):
        SearchPageRequest.model_validate({"expected_search_sha256": value})


def test_unknown_page_fields_refuse() -> None:
    with pytest.raises(ValidationError):
        SearchPageRequest.model_validate({"offset": 1})


def test_missing_binding_and_out_of_range_offsets_refuse() -> None:
    workset = _workset("Small synthetic preview.")
    binding = deliver_search(workset, {}, text_max_bytes=4096)["search_page"]["search_sha256"]
    with pytest.raises(ValueError, match="version digest"):
        deliver_search(workset, {}, SearchPageRequest(result_offset=1), text_max_bytes=4096)
    with pytest.raises(ValueError, match="outside"):
        deliver_search(
            workset,
            {},
            SearchPageRequest(result_offset=20, expected_search_sha256=binding),
            text_max_bytes=4096,
        )


def test_text_that_fits_alone_but_not_as_a_dual_result_refuses() -> None:
    workset = {"results": [{"content_text": "\u00e9\u6f22\U0001f642" * 400}]}
    assert len(json.dumps(workset, indent=2).encode()) < 16000
    with pytest.raises(ValueError, match="exceeds the bounded response"):
        deliver_search(workset, {}, text_max_bytes=16000)


@pytest.mark.parametrize(
    "change", ["query", "limit", "contexts", "result", "order", "counts", "empty"]
)
def test_continuation_binds_query_and_complete_workset_even_if_changed_workset_fits(
    change: str,
) -> None:
    workset = _workset()
    arguments: dict[str, Any] = {"query": "synthetic", "limit": 20, "contexts": []}
    first = deliver_search(workset, arguments, text_max_bytes=16000)
    page = SearchPageRequest(
        result_offset=first["search_page"]["next_result_offset"],
        expected_search_sha256=first["search_page"]["search_sha256"],
    )
    if change in arguments:
        arguments[change] = "changed"
    elif change == "result":
        workset["results"][-1]["authority"] = "changed"
    elif change == "order":
        workset["results"].reverse()
    elif change == "counts":
        workset["selection"]["omitted_counts"]["unselected_candidates"] += 1
    else:
        workset["results"] = []
    with pytest.raises(ValueError, match="search changed"):
        deliver_search(workset, arguments, page, text_max_bytes=16000)


@pytest.mark.parametrize("large_field", ["metadata", "result"])
def test_unpageable_data_refuses_without_omitting_fields_or_exposing_values(
    large_field: str,
) -> None:
    workset = _workset()
    if large_field == "metadata":
        workset["selection"]["label"] = "private-sentinel" * 2000
    else:
        workset["results"][0]["content_text"] = "private-sentinel" * 2000
    with pytest.raises(ValueError, match="bounded response limit") as caught:
        deliver_search(workset, {}, text_max_bytes=16000)
    assert "private-sentinel" not in str(caught.value)


@pytest.mark.parametrize("limit", [True, False, -1, 0, 4095, 524289, 4096.0, "16000"])
def test_origin_rejects_invalid_limit_before_opening_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: object
) -> None:
    open_ledger = Mock(side_effect=AssertionError("invalid limit must not open ledger"))
    monkeypatch.setattr("cross_assistant_memory.mcp_server.Ledger", open_ledger)
    with pytest.raises(ValueError, match="search text limit"):
        create_mcp_server(
            Settings(tmp_path / "node"), transport="stdio", search_text_max_bytes=cast(int, limit)
        )
    open_ledger.assert_not_called()


def test_actual_mcp_relay_preserves_all_results_and_rechecks_privacy_and_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(tmp_path / "node")
    ledger = Ledger(settings)
    source = write_jsonl(
        tmp_path / "search.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "hosted-search", "source": "vscode"}},
            *[
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": f"Synthetic search {index}. " + "x" * 1200,
                            }
                        ],
                    },
                }
                for index in range(20)
            ],
        ],
    )
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )
    original = ledger.retrieve_workset("Synthetic search", limit=20)
    generation = ledger.generation_digest()
    server = create_mcp_server(
        settings, transport="stdio", read_only=True, search_text_max_bytes=16000
    )

    async def exercise() -> None:
        async with Client(server, cache=None) as upstream:
            relay = await create_readonly_relay(lambda: nullcontext(upstream))
            async with Client(relay, cache=None) as client:
                tools = (await client.list_tools()).tools
                search = next(tool for tool in tools if tool.name == "memory_search")
                assert "page" in search.input_schema["properties"]
                args: dict[str, Any] = {"query": "Synthetic search", "limit": 20}
                assembled: list[dict[str, Any]] = []
                for _ in range(20):
                    response = await client.call_tool("memory_search", args)
                    assert not response.is_error
                    assert len(response.content) == 1
                    assert isinstance(response.content[0], TextContent)
                    assert len(response.content[0].text.encode()) <= 16000
                    result = json.loads(response.content[0].text)
                    assert result == response.structured_content
                    assert result["selection"] == original["selection"]
                    page = result["search_page"]
                    assert page["result_offset"] == len(assembled)
                    assembled.extend(result["results"])
                    if page["next_result_offset"] is None:
                        break
                    args = result["next_search_request"]
                assert assembled == original["results"]
                assert ledger.generation_digest() == generation
                identity_before = ledger.identity_state_digest()
                ledger.register_client(
                    label="unrelated synthetic status client",
                    kind=ClientKind.ASSISTANT,
                    capabilities=[Capability.MEMORY_STATUS],
                )
                assert ledger.identity_state_digest() != identity_before
                assert ledger.generation_digest() == generation
                unchanged = await client.call_tool("memory_search", args)
                assert not unchanged.is_error

                for invalid in (
                    {**args, "query": "Synthetic"},
                    {**args, "page": {"result_offset": 1}},
                    {**args, "page": {"expected_search_sha256": "private-sentinel"}},
                ):
                    refused = await client.call_tool("memory_search", invalid)
                    assert refused.is_error and refused.structured_content is None
                    assert "private-sentinel" not in refused.model_dump_json()

                monkeypatch.setattr(
                    "cross_assistant_memory.mcp_server.get_access_token",
                    lambda: AccessToken(
                        token="synthetic",
                        client_id="synthetic",
                        scopes=["memory:status"],
                        claims={"client_kind": "assistant"},
                    ),
                )
                refused = await client.call_tool("memory_search", args)
                assert refused.is_error and refused.structured_content is None
                monkeypatch.setattr(
                    "cross_assistant_memory.mcp_server.get_access_token",
                    lambda: AccessToken(
                        token="synthetic",
                        client_id="another",
                        scopes=["memory:search"],
                        claims={"client_kind": "assistant", "device_id": "another-device"},
                    ),
                )
                refused = await client.call_tool("memory_search", args)
                assert refused.is_error and SEARCH_CHANGED_MESSAGE in refused.model_dump_json()
                fresh = await client.call_tool(
                    "memory_search", {"query": "Synthetic search", "limit": 20}
                )
                assert not fresh.is_error
                fresh_workset = cast(dict[str, Any], fresh.structured_content)
                assert (
                    fresh_workset["results"] == original["results"][: len(fresh_workset["results"])]
                )
                monkeypatch.setattr(
                    "cross_assistant_memory.mcp_server.get_access_token", lambda: None
                )
                with sqlite3.connect(settings.database_path) as connection:
                    connection.execute(
                        "UPDATE events SET privacy='no_memory' WHERE event_id=?",
                        (original["results"][-1]["event_id"],),
                    )
                refused = await client.call_tool("memory_search", args)
                assert refused.is_error and refused.structured_content is None
                assert SEARCH_CHANGED_MESSAGE in refused.model_dump_json()
                fresh = await client.call_tool("memory_search", {"query": "Synthetic search"})
                assert not fresh.is_error

    asyncio.run(exercise())


def test_oversized_result_error_survives_actual_server_and_relay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(tmp_path / "node")
    Ledger(settings)
    workset = _workset("private-sentinel" * 2000)
    monkeypatch.setattr(
        "cross_assistant_memory.mcp_server.MemoryApplication.search",
        Mock(return_value=workset),
    )
    server = create_mcp_server(
        settings, transport="stdio", read_only=True, search_text_max_bytes=16000
    )

    async def exercise() -> None:
        async with Client(server, cache=None) as upstream:
            relay = await create_readonly_relay(lambda: nullcontext(upstream))
            async with Client(relay, cache=None) as client:
                result = await client.call_tool("memory_search", {"query": "synthetic"})
                assert result.is_error and result.structured_content is None
                assert result.content == [
                    TextContent(
                        type="text",
                        text=f"Error executing tool memory_search: {SEARCH_TOO_LARGE_MESSAGE}",
                    )
                ]
                assert "private-sentinel" not in result.model_dump_json()

    asyncio.run(exercise())
