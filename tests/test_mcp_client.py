from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
    ToolAnnotations,
)

from cross_assistant_memory import mcp_client
from cross_assistant_memory.config import Settings
from cross_assistant_memory.evidence_delivery import (
    EVIDENCE_CHANGED_MESSAGE,
    EVIDENCE_OFFSET_MESSAGE,
    EVIDENCE_VERSION_REQUIRED_MESSAGE,
)
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.models import Capability, ClientKind, Scope, SourceSystem
from cross_assistant_memory.search_delivery import SEARCH_CHANGED_MESSAGE, SEARCH_TOO_LARGE_MESSAGE
from cross_assistant_memory.storage import Ledger
from tests.conftest import write_jsonl

NAMES = ("memory_status", "memory_search", "memory_get_evidence")
TOKEN = "cam1.synthetic.connector-test"
EVIDENCE = CallToolResult(
    content=[TextContent(type="text", text="Synthetic exact evidence.\nSecond line.")],
    structured_content={
        "event_id": "synthetic-event",
        "content_text": "Synthetic exact evidence.\nSecond line.",
        "speaker": "user",
        "authority": "source_evidence",
        "citation": {"source_locator": "synthetic.jsonl:2", "evidence_id": "synthetic-event"},
        "corrections": [],
        "nullable": None,
    },
)


def _server(
    calls: list[CallToolRequestParams],
    names: tuple[str, ...] = (*NAMES, "memory_propose"),
    *,
    cursor: str | None = None,
    failure: str | None = None,
    reply: CallToolResult | None = None,
    call_events: tuple[asyncio.Event, asyncio.Event] | None = None,
) -> Server[Any]:
    async def listing(
        _context: ServerRequestContext[Any], _params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        return ListToolsResult(
            tools=[
                Tool(
                    name=name,
                    description=f"Synthetic {name}",
                    input_schema={"type": "object", "additionalProperties": True},
                    annotations=ToolAnnotations(read_only_hint=name in NAMES),
                )
                for name in names
            ],
            next_cursor=cursor,
        )

    async def call(
        _context: ServerRequestContext[Any], params: CallToolRequestParams
    ) -> CallToolResult:
        calls.append(params)
        if call_events is not None:
            started, release = call_events
            started.set()
            await release.wait()
        if failure == "exception":
            raise ValueError(TOKEN)
        if failure == "result":
            return CallToolResult(
                is_error=True,
                content=[TextContent(type="text", text=TOKEN)],
                structured_content={"secret": TOKEN},
            )
        return reply if reply is not None else EVIDENCE

    return Server("Synthetic connector upstream", on_list_tools=listing, on_call_tool=call)


@pytest.mark.parametrize("oversized", [False, True])
def test_capped_relay_checks_the_final_envelope_including_upstream_metadata(
    oversized: bool,
) -> None:
    value = {
        "event_id": "event:" + "0" * 64,
        "content_text": "Synthetic evidence.",
        "raw_record": "Synthetic raw record.",
        "raw_record_access": "exact",
        "correction": None,
    }
    metadata = {"synthetic_marker": "not-a-secret" * (1000 if oversized else 1)}
    reply = CallToolResult.model_validate(
        {
            "content": [{"type": "text", "text": json.dumps(value, indent=2)}],
            "structuredContent": value,
            "_meta": metadata,
        }
    )
    calls: list[CallToolRequestParams] = []
    upstream = _server(calls, reply=reply)

    async def exercise() -> None:
        relay = await mcp_client.create_readonly_relay(
            lambda: Client(upstream, cache=None), evidence_text_max_bytes=4096
        )
        async with Client(relay, cache=None) as client:
            result = await client.call_tool("memory_get_evidence", {"event_id": value["event_id"]})
        encoded = result.model_dump(mode="json", by_alias=True)
        assert len(json.dumps(encoded).encode()) <= 4096
        assert result.is_error is oversized
        if oversized:
            assert "not-a-secret" not in json.dumps(encoded)
            assert result.structured_content is None
        else:
            assert encoded["_meta"]["synthetic_marker"] == metadata["synthetic_marker"]
            assert result.structured_content == value
        assert len(calls) == 1

    asyncio.run(exercise())


def test_capped_relay_reserves_metadata_before_paging() -> None:
    content = "Synthetic evidence. " * 400
    value = {
        "event_id": "event:" + "0" * 64,
        "content_text": content,
        "raw_record": "Synthetic raw record.",
        "raw_record_access": "exact",
        "correction": None,
    }
    marker = "synthetic metadata " * 140
    reply = CallToolResult.model_validate(
        {
            "content": [{"type": "text", "text": json.dumps(value, indent=2)}],
            "structuredContent": value,
            "_meta": {"synthetic_marker": marker},
        }
    )
    calls: list[CallToolRequestParams] = []
    upstream = _server(calls, reply=reply)

    async def exercise() -> None:
        relay = await mcp_client.create_readonly_relay(
            lambda: Client(upstream, cache=None), evidence_text_max_bytes=8192
        )
        async with Client(relay, cache=None) as client:
            result = await client.call_tool("memory_get_evidence", {"event_id": value["event_id"]})
        assert not result.is_error and result.structured_content is not None
        encoded = result.model_dump(mode="json", by_alias=True)
        assert len(json.dumps(encoded).encode()) <= 8192
        assert encoded["_meta"]["synthetic_marker"] == marker
        delivered = result.structured_content
        assert 0 < len(delivered["content_text"]) < len(content)
        assert content.startswith(delivered["content_text"])
        assert delivered["next_content_request"]["include_context"] is False
        assert len(result.content) == 1 and isinstance(result.content[0], TextContent)
        assert json.loads(result.content[0].text) == delivered
        assert len(calls) == 1

    asyncio.run(exercise())


@pytest.mark.parametrize("port", [1, 8765, 65535])
def test_canonical_loopback_endpoint(port: int) -> None:
    endpoint = f"http://127.0.0.1:{port}/mcp"
    assert mcp_client.validate_loopback_endpoint(endpoint) == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:8765/mcp",
        "http://localhost:8765/mcp",
        "http://[::1]:8765/mcp",
        "http://127.1:8765/mcp",
        "http://2130706433:8765/mcp",
        "http://0.0.0.0:8765/mcp",
        "http://192.0.2.1:8765/mcp",
        "http://user:password@127.0.0.1:8765/mcp",
        "http://127.0.0.1/mcp",
        "http://127.0.0.1:0/mcp",
        "http://127.0.0.1:65536/mcp",
        "http://127.0.0.1:bad/mcp",
        "http://127.0.0.1:08765/mcp",
        "HTTP://127.0.0.1:8765/mcp",
        "http://127.0.0.1:8765/mcp/",
        "http://127.0.0.1:8765/mcp?",
        "http://127.0.0.1:8765/mcp#",
        "http://127.0.0.1:8765/%6dcp",
        "http://127.0.0.1:8765/a/../mcp",
        " http://127.0.0.1:8765/mcp",
        "http://127.0.0.1:8765/mcp\n",
        "http://[127.0.0.1:8765/mcp",
    ],
)
def test_rejects_noncanonical_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError, match="memory endpoint must be"):
        mcp_client.validate_loopback_endpoint(endpoint)


@pytest.mark.parametrize(
    "kind", ["missing", "public", "empty", "control", "nonascii", "large", "symlink", "parent"]
)
def test_invalid_credential_never_connects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    credential = tmp_path / "token"
    credential.write_bytes(
        {"empty": b"", "control": b"abc\x00def", "nonascii": b"\xff", "large": b"a" * 65537}.get(
            kind, TOKEN.encode("ascii")
        )
    )
    credential.chmod(0o644 if kind == "public" else 0o600)
    if kind == "missing":
        credential.unlink()
    elif kind == "symlink":
        link = tmp_path / "linked-token"
        link.symlink_to(credential)
        credential = link
    elif kind == "parent":
        link = tmp_path / "linked-parent"
        link.symlink_to(tmp_path, target_is_directory=True)
        credential = link / "token"

    async def unexpected(_endpoint: str, _credential: str, _limit: int | None) -> None:
        pytest.fail("invalid credential reached the network connector")

    monkeypatch.setattr(mcp_client, "_connect", unexpected)
    with pytest.raises((ValueError, OSError)):
        mcp_client.run_readonly_client("http://127.0.0.1:8765/mcp", credential)


def test_endpoint_validation_precedes_credential_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(_path: Path) -> str:
        pytest.fail("invalid endpoint caused credential access")

    monkeypatch.setattr(mcp_client, "load_transport_credential", unexpected)
    with pytest.raises(ValueError, match="memory endpoint"):
        mcp_client.run_readonly_client("http://localhost:8765/mcp", Path("unused"))


def test_connection_failure_is_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    credential = tmp_path / "token with spaces"
    credential.write_text(TOKEN + "\n", encoding="ascii")
    credential.chmod(0o600)

    async def failure(endpoint: str, token: str, limit: int | None) -> None:
        assert limit is None
        assert endpoint == "http://127.0.0.1:8765/mcp"
        assert token == TOKEN
        raise ValueError(f"secret={token}; path={credential}")

    monkeypatch.setattr(mcp_client, "_connect", failure)
    with pytest.raises(RuntimeError, match="Memory connection failed") as caught:
        mcp_client.run_readonly_client("http://127.0.0.1:8765/mcp", credential)
    assert TOKEN not in str(caught.value)
    assert str(credential) not in str(caught.value)
    assert caught.value.__suppress_context__


def test_relay_preserves_tools_arguments_and_evidence_and_blocks_writes() -> None:
    calls: list[CallToolRequestParams] = []

    async def exercise() -> None:
        async with Client(_server(calls), cache=None) as upstream:
            original = await upstream.list_tools()
            direct = await upstream.call_tool("memory_get_evidence", {})
            assert direct.structured_content == EVIDENCE.structured_content
            calls.clear()
            relay = await mcp_client.create_readonly_relay(lambda: nullcontext(upstream))
            async with Client(relay, cache=None) as client:
                listing = await client.list_tools()
                assert [tool.model_dump() for tool in listing.tools] == [
                    tool.model_dump() for tool in original.tools if tool.name in NAMES
                ]
                assert len(listing.tools) == 3
                for name in NAMES:
                    arguments = {"event_id": "synthetic-event", "nested": {"values": [None, 1]}}
                    result = await client.call_tool(name, arguments)
                    assert result.model_dump() == direct.model_dump()
                    assert calls[-1].name == name
                    assert calls[-1].arguments == arguments
                for name in ("memory_propose", "memory_search_shadow", "unknown"):
                    assert (await client.call_tool(name, {})).is_error
                assert len(calls) == 3

    asyncio.run(asyncio.wait_for(exercise(), timeout=10))


@pytest.mark.parametrize(
    "names,cursor", [(NAMES[:2], None), ((*NAMES, NAMES[0]), None), (NAMES, "next")]
)
def test_relay_refuses_incomplete_duplicate_or_paginated_contract(
    names: tuple[str, ...], cursor: str | None
) -> None:
    async def exercise() -> None:
        async with Client(_server([], names, cursor=cursor), cache=None) as upstream:
            with pytest.raises(ValueError, match="read-only tool contract"):
                await mcp_client.create_readonly_relay(lambda: nullcontext(upstream))

    asyncio.run(asyncio.wait_for(exercise(), timeout=10))


@pytest.mark.parametrize("failure", ["exception", "result"])
def test_relay_redacts_upstream_errors(failure: str) -> None:
    async def exercise() -> None:
        async with (
            Client(_server([], failure=failure), cache=None) as upstream,
            Client(await mcp_client.create_readonly_relay(lambda: nullcontext(upstream))) as client,
        ):
            result = await client.call_tool("memory_status", {})
            assert result.is_error
            assert result.structured_content is None
            assert TOKEN not in result.model_dump_json()
            assert result.content == [
                TextContent(type="text", text="Memory request refused or unavailable.")
            ]

    asyncio.run(asyncio.wait_for(exercise(), timeout=10))


@pytest.mark.parametrize("nested", [False, True])
def test_relay_preserves_canonical_evidence_and_safe_validation_feedback(
    tmp_path: Path, nested: bool
) -> None:
    settings = Settings(tmp_path / "synthetic node")
    ledger = Ledger(settings)
    source = write_jsonl(
        tmp_path / "synthetic.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "relay-test", "source": "vscode"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Synthetic relay evidence."}],
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
    server = create_mcp_server(settings, transport="stdio", read_only=True)

    async def exercise() -> None:
        async with Client(server, cache=None) as upstream:
            search = await upstream.call_tool("memory_search", {"query": "Synthetic relay"})
            assert search.structured_content is not None
            event_id = search.structured_content["results"][0]["event_id"]
            arguments = {"event_id": event_id, "include_context": True}
            direct = await upstream.call_tool("memory_get_evidence", arguments)
            assert not direct.is_error
            assert direct.structured_content is not None
            assert direct.structured_content["content_text"] == "Synthetic relay evidence."
            relay = await mcp_client.create_readonly_relay(lambda: nullcontext(upstream))
            if nested:
                inner_relay = relay
                relay = await mcp_client.create_readonly_relay(
                    lambda: Client(inner_relay, cache=None)
                )
            async with Client(relay, cache=None) as client:
                tools = {tool.name: tool for tool in (await client.list_tools()).tools}
                identifier = tools["memory_get_evidence"].input_schema["properties"]["event_id"]
                assert identifier["pattern"] == r"^event:[0-9a-f]{64}$"
                assert "Copy the complete value" in identifier["description"]
                for invalid_id in (
                    "a" * 64,
                    "event:" + "a" * 63,
                    "event:" + "a" * 65,
                    "event:" + "A" * 64,
                    "sha256:" + "a" * 64,
                    " event:" + "a" * 64,
                    "event:" + "a" * 64 + "\n",
                    f"event:{TOKEN}:{source}",
                    "",
                    None,
                    123,
                    {"input_value": TOKEN, "path": str(source)},
                ):
                    refused = await client.call_tool(
                        "memory_get_evidence", {"event_id": invalid_id}
                    )
                    assert refused.model_dump(exclude={"meta"}) == CallToolResult(
                        is_error=True,
                        content=[
                            TextContent(
                                type="text",
                                text="Error executing tool memory_get_evidence: "
                                "invalid arguments; consult its input schema",
                            )
                        ],
                    ).model_dump(exclude={"meta"})
                    assert TOKEN not in refused.model_dump_json()
                    assert str(source) not in refused.model_dump_json()
                result = await client.call_tool("memory_get_evidence", arguments)
                assert result.model_dump() == direct.model_dump()

    asyncio.run(asyncio.wait_for(exercise(), timeout=15))


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize(
    "message",
    [
        "invalid arguments; consult its input schema",
        SEARCH_CHANGED_MESSAGE,
        SEARCH_TOO_LARGE_MESSAGE,
        EVIDENCE_VERSION_REQUIRED_MESSAGE,
        EVIDENCE_CHANGED_MESSAGE,
        EVIDENCE_OFFSET_MESSAGE,
    ],
)
@pytest.mark.parametrize(
    "variant",
    ["exact", "metadata", "prefix", "suffix", "wrong_tool", "extra_content", "structured"],
)
def test_relay_only_recreates_exact_safe_validation_errors(
    name: str, variant: str, message: str
) -> None:
    safe = TextContent(
        type="text",
        text=f"Error executing tool {name}: {message}",
    )
    reply = CallToolResult(is_error=True, content=[safe])
    if variant == "metadata":
        reply = CallToolResult.model_validate({**reply.model_dump(), "_meta": {"secret": TOKEN}})
        assert TOKEN in reply.model_dump_json()
    elif variant in {"prefix", "suffix"}:
        reply.content = [
            TextContent(
                type="text", text=TOKEN + safe.text if variant == "prefix" else safe.text + TOKEN
            )
        ]
    elif variant == "wrong_tool":
        reply.content = [
            TextContent(
                type="text",
                text="Error executing tool memory_propose: "
                "invalid arguments; consult its input schema",
            )
        ]
    elif variant == "extra_content":
        reply.content = [safe, TextContent(type="text", text=TOKEN)]
    elif variant == "structured":
        reply.structured_content = {"input_value": TOKEN, "diagnostic": "/synthetic/private/path"}

    async def exercise() -> None:
        async with (
            Client(_server([], reply=reply), cache=None) as upstream,
            Client(await mcp_client.create_readonly_relay(lambda: nullcontext(upstream))) as client,
        ):
            result = await client.call_tool(name, {})
            expected = CallToolResult(
                is_error=True,
                content=[safe]
                if variant in {"exact", "metadata"}
                and (
                    message == "invalid arguments; consult its input schema"
                    or (
                        name == "memory_search"
                        and message
                        in {
                            SEARCH_CHANGED_MESSAGE,
                            SEARCH_TOO_LARGE_MESSAGE,
                        }
                    )
                    or (
                        name == "memory_get_evidence"
                        and message
                        in {
                            EVIDENCE_VERSION_REQUIRED_MESSAGE,
                            EVIDENCE_CHANGED_MESSAGE,
                            EVIDENCE_OFFSET_MESSAGE,
                        }
                    )
                )
                else [TextContent(type="text", text="Memory request refused or unavailable.")],
            )
            assert result.model_dump(exclude={"meta"}) == expected.model_dump(exclude={"meta"})
            assert TOKEN not in result.model_dump_json()

    asyncio.run(asyncio.wait_for(exercise(), timeout=10))


@pytest.mark.parametrize(
    "message",
    [
        "invalid arguments; consult its input schema",
        EVIDENCE_VERSION_REQUIRED_MESSAGE,
        EVIDENCE_CHANGED_MESSAGE,
        EVIDENCE_OFFSET_MESSAGE,
    ],
)
def test_nested_relays_preserve_safe_feedback_and_redact_hostile_errors(message: str) -> None:
    safe = TextContent(
        type="text",
        text=f"Error executing tool memory_get_evidence: {message}",
    )
    opaque = TextContent(type="text", text="Memory request refused or unavailable.")

    async def exercise() -> None:
        for content, structured, expected in (
            ([safe], None, safe),
            ([TextContent(type="text", text=safe.text + TOKEN)], {"secret": TOKEN}, opaque),
            ([safe, TextContent(type="text", text=TOKEN)], None, opaque),
        ):
            reply = CallToolResult.model_validate(
                {
                    "isError": True,
                    "content": [item.model_dump() for item in content],
                    "structuredContent": structured,
                    "_meta": {"secret": TOKEN, "diagnostic": "/synthetic/private/path"},
                }
            )
            calls: list[CallToolRequestParams] = []
            upstream = _server(calls, reply=reply)
            inner = await mcp_client.create_readonly_relay(
                lambda upstream=upstream: Client(upstream, cache=None)
            )
            outer = await mcp_client.create_readonly_relay(
                lambda inner=inner: Client(inner, cache=None)
            )
            async with Client(outer, cache=None) as client:
                result = await client.call_tool("memory_get_evidence", {"event_id": TOKEN})
                assert result.is_error and result.structured_content is None
                assert result.content == [expected]
                assert TOKEN not in result.model_dump_json()
                assert "/synthetic/private/path" not in result.model_dump_json()
                assert len(calls) == 1
                assert calls[0].arguments == {"event_id": TOKEN}

    asyncio.run(asyncio.wait_for(exercise(), timeout=10))


@pytest.mark.parametrize("limit", [True, 0, 4095, 524289, 4096.5])
def test_relay_rejects_invalid_evidence_budget_before_connecting(limit: Any) -> None:
    def unexpected() -> Any:
        pytest.fail("invalid budget reached the upstream connection")

    with pytest.raises(ValueError, match="evidence text limit"):
        asyncio.run(mcp_client.create_readonly_relay(unexpected, evidence_text_max_bytes=limit))


def test_bounded_relay_refuses_divergent_representations_without_affecting_other_tools() -> None:
    async def exercise() -> None:
        async with Client(_server([]), cache=None) as upstream:
            direct = await upstream.call_tool("memory_status", {})
            relay = await mcp_client.create_readonly_relay(
                lambda: nullcontext(upstream), evidence_text_max_bytes=16000
            )
            async with Client(relay, cache=None) as client:
                evidence = await client.call_tool("memory_get_evidence", {})
                assert evidence.is_error and evidence.structured_content is None
                assert "Synthetic exact evidence" not in evidence.model_dump_json()
                for name in ("memory_status", "memory_search"):
                    result = await client.call_tool(name, {})
                    assert result.model_dump() == direct.model_dump()

    asyncio.run(asyncio.wait_for(exercise(), timeout=10))


@pytest.mark.parametrize("drift", ["missing", "duplicate", "paginated", "schema", "description"])
def test_reconnection_refuses_changed_contract_before_calling_tools(drift: str) -> None:
    calls: list[CallToolRequestParams] = []
    healthy = _server(calls)

    async def exercise() -> None:
        current = healthy
        async with Client(healthy, cache=None) as direct:
            changed = await direct.list_tools()
            expected = await direct.call_tool("memory_get_evidence", {})
        calls.clear()
        if drift == "missing":
            changed.tools.pop(0)
        elif drift == "duplicate":
            changed.tools.append(changed.tools[0])
        elif drift == "paginated":
            changed.next_cursor = "next"
        elif drift == "description":
            changed.tools[0].description = "Changed description with identical schemas."
        else:
            changed.tools[0].input_schema = {"type": "object", "required": ["new_argument"]}

        async def listing(
            _context: ServerRequestContext[Any], _params: PaginatedRequestParams | None
        ) -> ListToolsResult:
            return changed

        async def unexpected(
            _context: ServerRequestContext[Any], _params: CallToolRequestParams
        ) -> CallToolResult:
            pytest.fail("changed upstream contract reached a tool")

        relay = await mcp_client.create_readonly_relay(lambda: Client(current, cache=None))
        async with Client(relay, cache=None) as client:
            current = Server("Changed contract", on_list_tools=listing, on_call_tool=unexpected)
            result = await client.call_tool("memory_status", {})
            assert result.is_error
            assert result.structured_content is None
            assert result.content == [
                TextContent(type="text", text="Memory request refused or unavailable.")
            ]
            assert not calls
            current = healthy
            assert (await client.call_tool("memory_get_evidence", {})).model_dump() == (
                expected.model_dump()
            )
            assert len(calls) == 1

    asyncio.run(asyncio.wait_for(exercise(), timeout=10))


def test_http_capability_and_revocation_through_relay(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "synthetic node")
    ledger = Ledger(settings)
    record = ledger.register_client(
        label="synthetic status-only connector",
        kind=ClientKind.COLLECTOR,
        capabilities=[Capability.MEMORY_STATUS],
    )
    credential = ledger.issue_client_credential(
        record["client_id"], expires_at=datetime.now(UTC) + timedelta(hours=1)
    )
    app = create_mcp_server(
        settings,
        transport="streamable-http",
        read_only=True,
        http_auth_url="http://127.0.0.1:8765/mcp",
    ).streamable_http_app(stateless_http=True, json_response=True)

    async def exercise() -> None:
        async with (
            app.router.lifespan_context(app),
            httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app),
                headers={"Authorization": f"Bearer {credential['token']}"},
                trust_env=False,
            ) as http,
            Client(
                streamable_http_client("http://127.0.0.1:8765/mcp", http_client=http), cache=None
            ) as upstream,
            Client(await mcp_client.create_readonly_relay(lambda: nullcontext(upstream))) as client,
        ):
            assert not (await client.call_tool("memory_status", {})).is_error
            for name, arguments in (
                ("memory_search", {"query": "synthetic"}),
                ("memory_get_evidence", {"event_id": "event:" + "a" * 64}),
            ):
                refused = await client.call_tool(name, arguments)
                assert refused.is_error and refused.structured_content is None
                assert refused.content == [
                    TextContent(type="text", text="Memory request refused or unavailable.")
                ]
            ledger.revoke_client_credential(credential["credential_id"])
            refused = await client.call_tool("memory_status", {})
            assert refused.is_error and refused.structured_content is None
            assert refused.content == [
                TextContent(type="text", text="Memory request refused or unavailable.")
            ]
            assert credential["token"] not in refused.model_dump_json()

    asyncio.run(asyncio.wait_for(exercise(), timeout=15))


@pytest.mark.parametrize("status", [401, 403, 307])
def test_http_refusal_and_redirect_do_not_forward_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    requests: list[httpx2.Request] = []
    real_client = httpx2.AsyncClient

    def respond(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(status, headers={"Location": "http://127.0.0.1:9876/stolen"})

    def client_factory(**kwargs: Any) -> httpx2.AsyncClient:
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return real_client(**kwargs, transport=httpx2.MockTransport(respond))

    monkeypatch.setattr(httpx2, "AsyncClient", client_factory)
    credential = tmp_path / "token"
    credential.write_text(TOKEN, encoding="ascii")
    credential.chmod(0o600)
    with pytest.raises(RuntimeError, match="Memory connection failed") as caught:
        mcp_client.run_readonly_client("http://127.0.0.1:8765/mcp", credential)
    assert requests
    assert all(str(request.url) == "http://127.0.0.1:8765/mcp" for request in requests)
    assert all(request.headers["authorization"] == f"Bearer {TOKEN}" for request in requests)
    assert TOKEN not in str(caught.value)


def test_actual_cli_stdio_lifecycle_survives_restart_and_ignores_local_env(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "synthetic node")
    ledger = Ledger(settings)
    record = ledger.register_client(
        label="synthetic CLI connector",
        kind=ClientKind.COLLECTOR,
        capabilities=[Capability.MEMORY_STATUS],
    )
    credential = ledger.issue_client_credential(
        record["client_id"], expires_at=datetime.now(UTC) + timedelta(hours=1)
    )
    token_path = tmp_path / "synthetic token with spaces"
    token_path.write_text(credential["token"] + "\n", encoding="ascii")
    token_path.chmod(0o600)
    client_home = tmp_path / "must not create a local ledger"
    invalid_config = tmp_path / "invalid evidence configuration"
    invalid_config.write_text("not JSON", encoding="ascii")
    environment = {
        **{key: value for key, value in os.environ.items() if not key.startswith("CAM_")},
        "CAM_HOME": str(client_home),
        "CAM_EVIDENCE_CONFIG": str(invalid_config),
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "ALL_PROXY": "http://127.0.0.1:1",
        "NO_PROXY": "",
        "http_proxy": "http://127.0.0.1:1",
        "https_proxy": "http://127.0.0.1:1",
        "all_proxy": "http://127.0.0.1:1",
        "no_proxy": "",
    }

    async def exercise() -> None:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            address = listener.getsockname()
            endpoint = f"http://127.0.0.1:{address[1]}/mcp"
            app = create_mcp_server(
                settings, transport="streamable-http", read_only=True, http_auth_url=endpoint
            ).streamable_http_app(stateless_http=True, json_response=True)
            server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
            task = asyncio.create_task(server.serve(sockets=[listener]))
            try:
                async with asyncio.timeout(5):
                    while not server.started:
                        if task.done():
                            await task
                            pytest.fail("synthetic server stopped before startup")
                        await asyncio.sleep(0.01)
                parameters = StdioServerParameters(
                    command=sys.executable,
                    args=[
                        "-m",
                        "cross_assistant_memory",
                        "connect",
                        "--url",
                        endpoint,
                        "--credential-file",
                        str(token_path),
                    ],
                    env=environment,
                )
                async with Client(parameters, read_timeout_seconds=5, cache=None) as client:
                    assert {tool.name for tool in (await client.list_tools()).tools} == set(NAMES)
                    assert not (await client.call_tool("memory_status", {})).is_error
                    assert (await client.call_tool("memory_propose", {})).is_error
                    server.should_exit = True
                    await asyncio.wait_for(task, timeout=5)
                    refused = await client.call_tool("memory_status", {})
                    assert refused.is_error and refused.structured_content is None
                    assert refused.content == [
                        TextContent(type="text", text="Memory request refused or unavailable.")
                    ]
                    assert {tool.name for tool in (await client.list_tools()).tools} == set(NAMES)
                    with socket.socket() as restarted_listener:
                        restarted_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        restarted_listener.bind(address)
                        app = create_mcp_server(
                            settings,
                            transport="streamable-http",
                            read_only=True,
                            http_auth_url=endpoint,
                        ).streamable_http_app(stateless_http=True, json_response=True)
                        server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
                        task = asyncio.create_task(server.serve(sockets=[restarted_listener]))
                        try:
                            async with asyncio.timeout(5):
                                while not server.started:
                                    if task.done():
                                        await task
                                        pytest.fail("synthetic server stopped before restart")
                                    await asyncio.sleep(0.01)
                            assert not (await client.call_tool("memory_status", {})).is_error
                            ledger.revoke_client_credential(credential["credential_id"])
                            assert (await client.call_tool("memory_status", {})).is_error
                        finally:
                            server.should_exit = True
                            await asyncio.wait_for(task, timeout=5)
            finally:
                server.should_exit = True
                await asyncio.wait_for(task, timeout=5)

    asyncio.run(asyncio.wait_for(exercise(), timeout=25))
    assert not client_home.exists()
    assert invalid_config.read_text(encoding="ascii") == "not JSON"
    assert token_path.read_text(encoding="ascii") == credential["token"] + "\n"


@pytest.mark.parametrize("in_flight", [False, True])
def test_actual_cli_exits_when_parent_closes_stdin(tmp_path: Path, in_flight: bool) -> None:
    token_path = tmp_path / "synthetic token"
    token_path.write_text(TOKEN, encoding="ascii")
    token_path.chmod(0o600)

    async def exercise() -> None:
        started, release = asyncio.Event(), asyncio.Event()
        calls: list[CallToolRequestParams] = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            endpoint = f"http://127.0.0.1:{listener.getsockname()[1]}/mcp"
            app = _server(calls, call_events=(started, release)).streamable_http_app(
                stateless_http=True, json_response=True
            )
            server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
            server_task = asyncio.create_task(server.serve(sockets=[listener]))
            process = None
            try:
                async with asyncio.timeout(5):
                    while not server.started:
                        if server_task.done():
                            await server_task
                            pytest.fail("synthetic server stopped before startup")
                        await asyncio.sleep(0.01)
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-m",
                    "cross_assistant_memory",
                    "connect",
                    "--url",
                    endpoint,
                    "--credential-file",
                    str(token_path),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                assert process.stdin is not None and process.stdout is not None
                assert process.stderr is not None
                meta = {
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "synthetic-parent-exit-test",
                        "version": "1.0.0",
                    },
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                }
                request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {"_meta": meta},
                }
                process.stdin.write((json.dumps(request) + "\n").encode())
                await process.stdin.drain()
                response = json.loads(await asyncio.wait_for(process.stdout.readline(), timeout=5))
                assert response["id"] == 1
                assert {tool["name"] for tool in response["result"]["tools"]} == set(NAMES)
                if in_flight:
                    request = {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"_meta": meta, "name": "memory_status", "arguments": {}},
                    }
                    process.stdin.write((json.dumps(request) + "\n").encode())
                    await process.stdin.drain()
                    await asyncio.wait_for(started.wait(), timeout=5)
                process.stdin.close()
                await process.stdin.wait_closed()
                assert await asyncio.wait_for(process.wait(), timeout=5) == 0
                assert TOKEN.encode() not in await process.stderr.read()
                assert len(calls) == int(in_flight)
            finally:
                if process is not None and process.returncode is None:
                    process.kill()
                    await process.wait()
                release.set()
                server.should_exit = True
                await asyncio.wait_for(server_task, timeout=5)

    asyncio.run(asyncio.wait_for(exercise(), timeout=20))
