from __future__ import annotations

import asyncio
import runpy
from pathlib import Path

from mcp import Client


def test_native_context_probe_has_no_history_or_granted_authority() -> None:
    module = runpy.run_path(str(Path(__file__).parents[1] / "script/grok-bot-context-probe.py"))
    server = module["create_server"]()

    async def exercise() -> None:
        async with Client(server) as client:
            tools = (await client.list_tools()).tools
            assert [tool.name for tool in tools] == ["cam_context_probe"]
            assert tools[0].annotations is not None
            assert tools[0].annotations.read_only_hint
            response = await client.call_tool("cam_context_probe", {})
        assert not response.is_error
        result = response.structured_content
        assert result is not None
        assert result["real_history_access"] is False
        assert result["identity_authority"] == "not_established"
        assert result["caller_identity_verified"] is False
        assert result["request_method"] == "tools/call"
        assert "token" not in result and "request_params" not in result

    asyncio.run(exercise())
