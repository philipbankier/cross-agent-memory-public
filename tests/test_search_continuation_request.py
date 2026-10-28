from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from mcp import Client
from mcp.types import TextContent

from cross_assistant_memory.config import Settings
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.search_delivery import SearchPageRequest, deliver_search
from cross_assistant_memory.storage import Ledger


def _workset() -> dict[str, Any]:
    return {
        "results": [
            {"event_id": f"event:{index:064x}", "content_text": "Synthetic preview. " * 60}
            for index in range(20)
        ],
        "selection": {"returned_count": 20},
    }


def test_search_page_precedes_previews() -> None:
    result = deliver_search(_workset(), {}, text_max_bytes=16000)
    assert next(iter(result)) == "search_page"


def test_oversized_helper_does_not_make_existing_cursor_unusable() -> None:
    workset = _workset()
    arguments = {"query": "private-sentinel" * 2000}
    before = copy.deepcopy((workset, arguments))
    result = deliver_search(workset, {}, text_max_bytes=16000, continuation_arguments=arguments)
    assert "next_search_request" not in result
    assert result["search_page"]["next_result_offset"] == 1
    assert (workset, arguments) == before


def test_complete_worksets_need_no_continuation_arguments() -> None:
    workset = {"results": [{"content_text": "Small synthetic match."}]}
    assert (
        deliver_search(
            workset, {}, text_max_bytes=16000, continuation_arguments={"query": "synthetic"}
        )
        is workset
    )


@pytest.mark.parametrize("context", [False, True])
def test_helper_is_optional_at_smallest_response_cap(context: bool) -> None:
    workset = _workset()
    workset["results"] = workset["results"][:2]
    for item in workset["results"]:
        item["content_text"] = "x" * 1000
        if context:
            item["conversation_context"] = {
                "results": [{"event_id": "event:" + "f" * 64, "content_text": "y" * 3000}]
            }
    before = copy.deepcopy(workset)
    arguments = {"query": "synthetic " * 150}
    baseline = deliver_search(workset, arguments, text_max_bytes=4096)
    result = deliver_search(
        workset, arguments, text_max_bytes=4096, continuation_arguments=arguments
    )
    assert result == baseline
    assert "next_search_request" not in result
    assert workset == before


def test_final_suffix_does_not_claim_earlier_results_were_read() -> None:
    workset = _workset()
    arguments = {"query": "synthetic"}
    first = deliver_search(workset, arguments, text_max_bytes=16000)
    result = deliver_search(
        workset,
        arguments,
        SearchPageRequest(
            result_offset=19, expected_search_sha256=first["search_page"]["search_sha256"]
        ),
        text_max_bytes=16000,
        continuation_arguments=arguments,
    )
    assert result["search_page"]["complete"] is False
    assert result["search_page"]["next_result_offset"] is None
    assert "next_search_request" not in result


def test_helper_fallback_preserves_context_and_usable_cursor() -> None:
    workset = _workset()
    for item in workset["results"]:
        item["content_text"] = "x" * 100
        item["conversation_context"] = {
            "results": [{"event_id": "event:" + "f" * 64, "content_text": "y" * 300}]
        }
    arguments = {"query": "synthetic " * 150}
    first = deliver_search(
        workset, arguments, text_max_bytes=4096, continuation_arguments=arguments
    )
    assert "next_search_request" not in first
    assert first["results"] == workset["results"][:1]
    second = deliver_search(
        workset,
        arguments,
        SearchPageRequest(
            result_offset=first["search_page"]["next_result_offset"],
            expected_search_sha256=first["search_page"]["search_sha256"],
        ),
        text_max_bytes=4096,
        continuation_arguments=arguments,
    )
    assert second["results"] == workset["results"][1:2]
    assert second["search_page"]["result_offset"] == 1


@pytest.mark.parametrize("contexts", [None, [{"kind": "topic", "key": "synthetic"}]])
@pytest.mark.parametrize("query", ["synthetic", '\u00e9\u6f22\\"synthetic'])
def test_actual_mcp_can_copy_search_continuation_without_private_binding_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contexts: list[dict[str, str]] | None,
    query: str,
) -> None:
    settings = Settings(tmp_path / "node")
    Ledger(settings)
    workset = _workset()
    original = copy.deepcopy(workset)
    search = Mock(return_value=workset)
    monkeypatch.setattr("cross_assistant_memory.mcp_server.MemoryApplication.search", search)
    server = create_mcp_server(
        settings, transport="stdio", read_only=True, search_text_max_bytes=16000
    )
    initial: dict[str, Any] = {
        "query": query,
        "mode": "how_did_it_change",
        "project_id": "synthetic-project",
        "limit": 20,
        "authorities": ["assistant_output"],
        "contexts": contexts,
        "retrieval_control": "force",
    }

    async def exercise() -> None:
        async with Client(server, cache=None) as client:
            args = copy.deepcopy(initial)
            assembled: list[dict[str, Any]] = []
            for _ in range(20):
                response = await client.call_tool("memory_search", args)
                assert not response.is_error
                serialized = json.dumps(response.model_dump(mode="json", by_alias=True))
                assert len(serialized.encode()) <= 16000
                result = response.structured_content
                assert result is not None
                assert isinstance(response.content[0], TextContent)
                assert json.loads(response.content[0].text) == result
                assert next(iter(result)) == "search_page"
                assembled.extend(result["results"])
                page = result["search_page"]
                if page["next_result_offset"] is None:
                    assert "next_search_request" not in result
                    break
                args = result["next_search_request"]
                assert list(result)[1] == "next_search_request"
                assert {key: value for key, value in args.items() if key != "page"} == initial
                assert set(args) == set(initial) | {"page"}
                assert args["page"] == {
                    "result_offset": len(assembled),
                    "expected_search_sha256": page["search_sha256"],
                }
            assert assembled == original["results"]
            assert workset == original
            assert search.call_count > 1

    asyncio.run(exercise())
