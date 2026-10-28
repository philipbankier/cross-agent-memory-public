from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

from cross_assistant_memory.collector_runtime import load_transport_credential
from cross_assistant_memory.evidence_delivery import (
    EVIDENCE_CHANGED_MESSAGE,
    EVIDENCE_OFFSET_MESSAGE,
    EVIDENCE_VERSION_REQUIRED_MESSAGE,
    limit_evidence_text,
)
from cross_assistant_memory.search_delivery import SEARCH_CHANGED_MESSAGE, SEARCH_TOO_LARGE_MESSAGE

READ_ONLY_TOOLS = frozenset({"memory_status", "memory_search", "memory_get_evidence"})


def validate_loopback_endpoint(endpoint: str) -> str:
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        raise ValueError("memory endpoint must be http://127.0.0.1:PORT/mcp") from None
    if port is None or not 1 <= port <= 65535 or endpoint != f"http://127.0.0.1:{port}/mcp":
        raise ValueError("memory endpoint must be http://127.0.0.1:PORT/mcp")
    return endpoint


def _failure() -> CallToolResult:
    return CallToolResult(
        is_error=True,
        content=[TextContent(type="text", text="Memory request refused or unavailable.")],
    )


def _readonly_tools(listing: ListToolsResult) -> list[Tool]:
    tools = [tool for tool in listing.tools if tool.name in READ_ONLY_TOOLS]
    if (
        listing.next_cursor is not None
        or len(tools) != len(READ_ONLY_TOOLS)
        or frozenset(tool.name for tool in tools) != READ_ONLY_TOOLS
    ):
        raise ValueError("memory server does not expose the expected read-only tool contract")
    return tools


async def create_readonly_relay(
    connect: Callable[[], AbstractAsyncContextManager[Client]],
    *,
    evidence_text_max_bytes: int | None = None,
) -> Server[Any]:
    if evidence_text_max_bytes is not None and (
        type(evidence_text_max_bytes) is not int
        or not 4096 <= evidence_text_max_bytes <= 512 * 1024
    ):
        raise ValueError("evidence text limit must be between 4096 and 524288 bytes")
    async with connect() as upstream:
        tools = _readonly_tools(await upstream.list_tools())
    contract = {tool.name: tool for tool in tools}

    async def list_tools(
        _context: ServerRequestContext[Any], _params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        return ListToolsResult(tools=tools)

    async def call_tool(
        _context: ServerRequestContext[Any], params: CallToolRequestParams
    ) -> CallToolResult:
        if params.name not in READ_ONLY_TOOLS:
            return _failure()
        try:
            # Keep transport task-group failures inside this request, not the stdio lifetime.
            async with connect() as upstream:
                current = _readonly_tools(await upstream.list_tools())
                if {tool.name: tool for tool in current} != contract:
                    return _failure()
                result = await upstream.call_tool(params.name, params.arguments)
            if result.is_error:
                # Recreate exact fixed feedback only, never upstream metadata or diagnostics.
                messages = ["invalid arguments; consult its input schema"]
                if params.name == "memory_search":
                    messages += [SEARCH_CHANGED_MESSAGE, SEARCH_TOO_LARGE_MESSAGE]
                elif params.name == "memory_get_evidence":
                    messages += [
                        EVIDENCE_VERSION_REQUIRED_MESSAGE,
                        EVIDENCE_CHANGED_MESSAGE,
                        EVIDENCE_OFFSET_MESSAGE,
                    ]
                for message in messages:
                    safe = TextContent(
                        type="text", text=f"Error executing tool {params.name}: {message}"
                    )
                    if result.structured_content is None and result.content == [safe]:
                        return CallToolResult(is_error=True, content=[safe])
                return _failure()
            if params.name == "memory_get_evidence" and evidence_text_max_bytes is not None:
                value = result.structured_content
                if (
                    value is None
                    or len(result.content) != 1
                    or not isinstance(result.content[0], TextContent)
                    or json.loads(result.content[0].text) != value
                ):
                    return _failure()
                # Paging budgets a bare result; reserve the metadata retained from upstream.
                envelope = result.model_copy(update={"content": [], "structured_content": {}})
                bare = CallToolResult(content=[], structured_content={})
                overhead = max(
                    0,
                    len(json.dumps(envelope.model_dump(mode="json", by_alias=True)).encode())
                    - len(json.dumps(bare.model_dump(mode="json", by_alias=True)).encode()),
                )
                bounded = limit_evidence_text(value, evidence_text_max_bytes - overhead)
                result = result.model_copy(
                    update={
                        "structured_content": bounded,
                        "content": [TextContent(type="text", text=json.dumps(bounded, indent=2))],
                    }
                )
                if len(json.dumps(result.model_dump(mode="json", by_alias=True)).encode()) > (
                    evidence_text_max_bytes
                ):
                    return _failure()
        except Exception:
            return _failure()
        return result

    return Server(
        "Cross-Agent Memory Read-Only Connection",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


@asynccontextmanager
async def _upstream_connection(endpoint: str, credential: str) -> AsyncGenerator[Client, None]:
    # Keep bearer credentials on loopback even when ambient proxy variables are configured.
    async with (
        httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {credential}"},
            timeout=httpx2.Timeout(60, connect=10),
            follow_redirects=False,
            trust_env=False,
        ) as http,
        Client(
            streamable_http_client(endpoint, http_client=http),
            read_timeout_seconds=60,
            cache=None,
        ) as upstream,
    ):
        yield upstream


async def _connect(
    endpoint: str, credential: str, evidence_text_max_bytes: int | None = None
) -> None:
    relay = await create_readonly_relay(
        lambda: _upstream_connection(endpoint, credential),
        evidence_text_max_bytes=evidence_text_max_bytes,
    )
    async with stdio_server() as (reader, writer):
        await relay.run(reader, writer, relay.create_initialization_options())


def run_readonly_client(
    endpoint: str, credential_file: Path, *, evidence_text_max_bytes: int | None = None
) -> None:
    endpoint = validate_loopback_endpoint(endpoint)
    credential = load_transport_credential(credential_file)
    try:
        asyncio.run(_connect(endpoint, credential, evidence_text_max_bytes))
    except Exception as error:
        raise RuntimeError(
            f"Memory connection failed ({type(error).__name__}); "
            "check the node and client credential."
        ) from None
