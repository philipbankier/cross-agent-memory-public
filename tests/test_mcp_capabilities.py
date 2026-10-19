from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp.types import (
    GetPromptRequest,
    GetPromptRequestParams,
    GetPromptResult,
    ListPromptsRequest,
    ListPromptsResult,
    SubscriptionFilter,
    SubscriptionsListenRequest,
    SubscriptionsListenRequestParams,
    SubscriptionsListenResult,
)

from cross_assistant_memory.config import Settings
from cross_assistant_memory.mcp_app import MEMORY_APP_URI
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.storage import Ledger


@pytest.mark.parametrize("memory_app", [False, True])
@pytest.mark.parametrize("method", ["prompts/list", "prompts/get", "subscriptions/listen"])
def test_unadvertised_features_refuse_without_disabling_memory(
    tmp_path: Path, memory_app: bool, method: str
) -> None:
    settings = Settings(tmp_path / "node")
    Ledger(settings)
    server = create_mcp_server(settings, transport="stdio", read_only=True, memory_app=memory_app)

    async def exercise() -> None:
        async with Client(server) as client:
            assert client.server_capabilities.prompts is None
            assert client.server_capabilities.tools is not None
            assert client.server_capabilities.tools.list_changed is False
            with pytest.raises(MCPError) as error:
                if method == "prompts/list":
                    await client.session.send_request(ListPromptsRequest(), ListPromptsResult)
                elif method == "prompts/get":
                    await client.session.send_request(
                        GetPromptRequest(
                            params=GetPromptRequestParams(name="synthetic-unadvertised")
                        ),
                        GetPromptResult,
                    )
                else:
                    await client.session.send_request(
                        SubscriptionsListenRequest(
                            params=SubscriptionsListenRequestParams(
                                notifications=SubscriptionFilter(tools_list_changed=True)
                            )
                        ),
                        SubscriptionsListenResult,
                        request_read_timeout_seconds=0.5,
                    )
            assert error.value.code == -32601
            assert "synthetic-unadvertised" not in str(error.value)
            status = await client.call_tool("memory_status", {})
            assert not status.is_error

    asyncio.run(exercise())


def test_app_keeps_its_advertised_resource_after_feature_refusal(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "node")
    Ledger(settings)
    server = create_mcp_server(settings, transport="stdio", read_only=True, memory_app=True)

    async def exercise() -> None:
        async with Client(server) as client:
            result = await client.read_resource(MEMORY_APP_URI)
            assert len(result.contents) == 1
            resources = (await client.list_resources()).resources
            assert [str(resource.uri) for resource in resources] == [MEMORY_APP_URI]

    asyncio.run(exercise())
