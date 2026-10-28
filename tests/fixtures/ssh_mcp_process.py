"""Synthetic subprocess peer and actual CLI adapter; never opens a real SSH connection."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

from mcp.client.stdio import StdioServerParameters
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

from cross_assistant_memory import mcp_ssh_client

NAMES = ("memory_status", "memory_search", "memory_get_evidence")
SECRET = "SYNTHETIC-REMOTE-SECRET-NOT-FOR-LOGS"
ROOT = Path(sys.argv[2])


def record(event: str) -> None:
    with (ROOT / "events.jsonl").open("a") as output:
        fcntl.flock(output, fcntl.LOCK_EX)
        output.write(
            json.dumps({"event": event, "pid": os.getpid(), "at": time.monotonic()}) + "\n"
        )
        output.flush()


def mode() -> str:
    return (ROOT / "mode").read_text()


async def upstream() -> None:
    async def listing(
        _context: ServerRequestContext[Any],
        _params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        if mode() == "discovery-hang":
            record("waiting")
            await asyncio.Event().wait()
        return ListToolsResult(
            tools=[
                Tool(
                    name=name,
                    description="changed" if mode() == "drift" else "synthetic",
                    input_schema={"type": "object", "additionalProperties": True},
                )
                for name in (*NAMES, "memory_propose")
            ]
        )

    async def call(
        _context: ServerRequestContext[Any],
        params: CallToolRequestParams,
    ) -> CallToolResult:
        record("call")
        if mode() == "hang":
            record("waiting")
            await asyncio.Event().wait()
        if mode() == "error":
            print(SECRET, file=sys.stderr, flush=True)
            return CallToolResult(is_error=True, content=[TextContent(type="text", text=SECRET)])
        if mode() == "slow":
            await asyncio.sleep(0.1)
        value = {"tool": params.name, "text": "synthetic evidence", "arguments": params.arguments}
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(value))], structured_content=value
        )

    server = Server("Synthetic SSH peer", on_list_tools=listing, on_call_tool=call)
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


if sys.argv[1] == "upstream":
    record("start")
    try:
        if mode() == "unavailable":
            print(SECRET, file=sys.stderr, flush=True)
            raise SystemExit(1)
        if mode() == "malformed":
            print(SECRET, flush=True)
            for _ in sys.stdin:
                pass
        else:
            asyncio.run(upstream())
    finally:
        record("stop")
else:
    from cross_assistant_memory.cli import main

    parameters = StdioServerParameters(
        command=sys.executable,
        args=[__file__, "upstream", str(ROOT)],
        env={"PYTHONPATH": str(Path(mcp_ssh_client.__file__).resolve().parents[1])},
    )
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else mcp_ssh_client.REQUEST_TIMEOUT
    with (
        patch.object(mcp_ssh_client, "_slot_directory", return_value=ROOT / "slots"),
        patch.object(mcp_ssh_client.SSHConnection, "parameters", return_value=parameters),
        patch.object(mcp_ssh_client, "REQUEST_TIMEOUT", timeout),
        patch.object(mcp_ssh_client, "DISCOVERY_TIMEOUT", min(20.0, timeout)),
    ):
        main(
            [
                "connect-ssh",
                "--host",
                "synthetic.invalid",
                "--remote-python",
                "/python",
                "--remote-runtime",
                "/runtime",
                "--remote-credential-file",
                "/remote-only/token",
                "--url",
                "http://127.0.0.1:28765/mcp",
            ]
        )
