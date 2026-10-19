from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from cross_assistant_memory.application import MemoryApplication
from cross_assistant_memory.config import Settings
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.storage import Ledger


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("memory_search", {"query": "canary", "query_mode": "decision"}),
        ("memory_status", {"private-key-sentinel": "private-argument-sentinel"}),
        (
            "memory_get_evidence",
            {"event_id": "event:" + "a" * 64, "unexpected": "private-argument-sentinel"},
        ),
    ],
)
def test_mcp_rejects_unknown_arguments_before_application_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tool_name: str,
    arguments: dict[str, Any],
) -> None:
    settings = Settings(tmp_path / "data")
    Ledger(settings)

    def unexpected(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("unknown arguments reached the application")

    for method in ("search", "status", "get_evidence"):
        monkeypatch.setattr(MemoryApplication, method, unexpected)
    server = create_mcp_server(settings, transport="stdio", principal="test:mcp", read_only=True)

    async def exercise() -> None:
        async with Client(server) as client:
            response = await client.call_tool(tool_name, arguments)
        assert response.is_error
        assert response.structured_content is None
        assert response.content[0].model_dump()["text"] == (
            f"Error executing tool {tool_name}: invalid arguments; consult its input schema"
        )
        assert "private-argument-sentinel" not in response.model_dump_json()
        assert "private-argument-sentinel" not in caplog.text
        assert "private-key-sentinel" not in response.model_dump_json()
        assert "private-key-sentinel" not in caplog.text

    asyncio.run(exercise())


def test_mcp_tool_schemas_close_top_level_arguments(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "data")
    Ledger(settings)
    server = create_mcp_server(settings, transport="stdio", principal="test:mcp")

    async def exercise() -> None:
        async with Client(server) as client:
            tools = (await client.list_tools()).tools
        assert {tool.name for tool in tools} >= {
            "memory_search",
            "memory_status",
            "memory_get_evidence",
            "memory_propose",
        }
        assert all(tool.input_schema.get("additionalProperties") is False for tool in tools)

    asyncio.run(exercise())
