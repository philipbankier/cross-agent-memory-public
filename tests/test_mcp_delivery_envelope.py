from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import SERVER_INFO_META_KEY, CallToolResult, TextContent

from cross_assistant_memory.config import Settings
from cross_assistant_memory.evidence_delivery import deliver_evidence
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.models import Capability, ClientKind
from cross_assistant_memory.search_delivery import deliver_search
from cross_assistant_memory.storage import Ledger
from tests.test_evidence_delivery import (
    _context_evidence,  # pyright: ignore[reportPrivateUsage]
    _evidence,  # pyright: ignore[reportPrivateUsage]
    _sdk_size,  # pyright: ignore[reportPrivateUsage]
)
from tests.test_search_delivery import _workset  # pyright: ignore[reportPrivateUsage]


@asynccontextmanager
async def _client(settings: Settings, http: bool, limit: int) -> AsyncGenerator[Client]:
    options: dict[str, Any] = {
        "read_only": True,
        "evidence_text_max_bytes": limit,
        "search_text_max_bytes": limit,
        "memory_app": True,
    }
    if not http:
        server = create_mcp_server(settings, transport="stdio", **options)
        async with Client(server, cache=None) as client:
            yield client
        return

    ledger = Ledger(settings)
    registered = ledger.register_client(
        label="synthetic delivery reader",
        kind=ClientKind.ASSISTANT,
        capabilities=[Capability.MEMORY_SEARCH, Capability.MEMORY_EVIDENCE_READ],
    )
    credential = ledger.issue_client_credential(
        registered["client_id"], expires_at=datetime.now(UTC) + timedelta(hours=1)
    )
    app = create_mcp_server(
        settings,
        transport="streamable-http",
        http_auth_url="http://127.0.0.1:8765/mcp",
        **options,
    ).streamable_http_app(stateless_http=True, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app),
            headers={"Authorization": f"Bearer {credential['token']}"},
            trust_env=False,
        ) as transport,
        Client(
            streamable_http_client("http://127.0.0.1:8765/mcp", http_client=transport), cache=None
        ) as client,
    ):
        yield client


def _value(result: CallToolResult, limit: int) -> dict[str, Any]:
    assert not result.is_error
    wire = result.model_dump(mode="json", by_alias=True)
    assert wire["_meta"][SERVER_INFO_META_KEY]["name"] == "Cross Assistant Memory"
    assert len(json.dumps(wire).encode()) <= limit
    assert len(result.content) == 1 and isinstance(result.content[0], TextContent)
    value = json.loads(result.content[0].text)
    assert value == result.structured_content
    return value


@pytest.mark.parametrize("http", [False, True], ids=["memory-transport", "http"])
@pytest.mark.parametrize("case", ["whole", "paged", "escaped-context"])
def test_origin_evidence_reserves_transport_metadata_and_reconstructs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, http: bool, case: str
) -> None:
    settings = Settings(tmp_path / "node")
    Ledger(settings)
    evidence = (
        _context_evidence('\u00e9\u6f22\U0001f642\\"\n' * 800)
        if case == "escaped-context"
        else _evidence("x" * (1200 if case == "whole" else 12084))
    )
    evidence["event_id"] = "event:" + "a" * 64
    before = copy.deepcopy(evidence)
    binding = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    # The old handler fits exactly, but the later SDK identity stamp does not.
    limit = _sdk_size(deliver_evidence(evidence, text_max_bytes=16000))
    assert 4096 <= limit <= 16000
    monkeypatch.setattr(
        "cross_assistant_memory.mcp_server.MemoryApplication.get_evidence",
        Mock(return_value=evidence),
    )

    async def exercise() -> None:
        args = {
            "event_id": evidence["event_id"],
            "include_context": "conversation_context" in evidence,
        }
        assembled = b""
        async with _client(settings, http, limit) as client:
            for _ in range(64):
                value = _value(await client.call_tool("memory_get_evidence", args), limit)
                chunk = value["content_text"].encode()
                if "evidence_page" in value:
                    page = value["evidence_page"]
                    assert page["evidence_sha256"] == binding
                    field = page["fields"]["content_text"]
                    assert field["offset_bytes"] == len(assembled)
                    assert field["returned_bytes"] == len(chunk)
                    assert field["chunk_sha256"] == hashlib.sha256(chunk).hexdigest()
                    assert (
                        field["sha256"]
                        == hashlib.sha256(evidence["content_text"].encode()).hexdigest()
                    )
                assembled += chunk
                if "next_content_request" not in value:
                    break
                args = value["next_content_request"]
                assert args["event_id"] == evidence["event_id"]
                assert args["include_context"] == ("conversation_context" in evidence)
            assert assembled == evidence["content_text"].encode()
        assert evidence == before

    asyncio.run(asyncio.wait_for(exercise(), timeout=15))


@pytest.mark.parametrize("http", [False, True], ids=["memory-transport", "http"])
@pytest.mark.parametrize("text", ["x" * 1200, '\u00e9\\"\n' * 100], ids=["ascii", "escaped"])
def test_origin_search_reserves_transport_metadata_and_preserves_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, http: bool, text: str
) -> None:
    settings = Settings(tmp_path / "node")
    Ledger(settings)
    workset = _workset(text)
    before = copy.deepcopy(workset)
    limit = _sdk_size(deliver_search(workset, {}, text_max_bytes=16000))
    assert 4096 <= limit <= 16000
    monkeypatch.setattr(
        "cross_assistant_memory.mcp_server.MemoryApplication.search", Mock(return_value=workset)
    )

    async def exercise() -> None:
        args: dict[str, Any] = {"query": "synthetic", "limit": 20}
        assembled: list[dict[str, Any]] = []
        binding = None
        async with _client(settings, http, limit) as client:
            for _ in range(20):
                value = _value(await client.call_tool("memory_search", args), limit)
                assert value["selection"] == workset["selection"]
                page = value["search_page"]
                assert page["result_offset"] == len(assembled)
                assert binding is None or page["search_sha256"] == binding
                binding = page["search_sha256"]
                assembled.extend(value["results"])
                if page["next_result_offset"] is None:
                    break
                args["page"] = {
                    "result_offset": page["next_result_offset"],
                    "expected_search_sha256": binding,
                }
            assert assembled == workset["results"]
        assert workset == before

    asyncio.run(asyncio.wait_for(exercise(), timeout=15))
