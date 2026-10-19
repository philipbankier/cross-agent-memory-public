from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.config import Settings
from cross_assistant_memory.evaluation import (
    file_entries,
    set_read_only_tree,
    sha256_file,
    write_json,
    write_jsonl,
)
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import QueryMode, Scope, SourceSystem
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    publish_directory_no_replace,
)
from cross_assistant_memory.storage import Ledger

EXACT_CLIENT_FORMAT_VERSION = 2
EXACT_CLIENT_CONTRACT_VERSION = 2
EXACT_CLIENT_FINAL_MARKER = "CAM_EXACT_CLIENT_PASS"
EXACT_CLIENT_TOOLS = ("memory_status", "memory_search", "memory_get_evidence")
EXACT_CLIENT_IDS = (
    "codex-bundled",
    "codex-path",
    "claude-code",
    "grok-cli",
)
EXACT_CLIENT_HARNESS_PATHS = (
    "evaluation/exact-clients-v2/contract.json",
    "script/cross-memory",
    "script/test-exact-clients",
    "src/cross_assistant_memory/cli.py",
    "src/cross_assistant_memory/client_evaluation.py",
    "src/cross_assistant_memory/mcp_server.py",
    "src/cross_assistant_memory/storage.py",
)
EXACT_CLIENT_CONTRACT_PATH = Path("evaluation/exact-clients-v2/contract.json")
EXACT_CLIENT_INSTALL_KINDS = (
    "chatgpt_app_bundle",
    "openai_npm",
    "anthropic_native",
    "xai_native",
)
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_PROCESS_OUTPUT_BYTES = 4 * 1024 * 1024
PROCESS_TIMEOUT_SECONDS = 120
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
EVENT_ID_PATTERN = re.compile(r"event:[0-9a-f]{64}")
GIT_OBJECT_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


@dataclass(frozen=True)
class ExactClientSpec:
    client_id: str
    family: str
    protocol: str
    install_kind: str
    code_identifier: str
    team_id: str
    package_name: str | None


@dataclass(frozen=True)
class ExactClientContract:
    path: Path
    sha256: str
    clients: tuple[ExactClientSpec, ...]
    expected_final: str
    expected_tools: tuple[str, ...]
    fixture: dict[str, Any]


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: float


@dataclass
class ClientTrace:
    client_id: str
    family: str
    protocol: str
    model_requests: int = 0
    title_requests: int = 0
    model_ids: set[str] = field(default_factory=set[str])
    endpoint_counts: Counter[str] = field(default_factory=Counter[str])
    issued_tools: list[str] = field(default_factory=list[str])
    completed_tools: list[str] = field(default_factory=list[str])
    search_tool_calls: int = 0
    final_issued: bool = False
    failure: str | None = None
    protocol_events: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])

    def public_summary(self) -> dict[str, Any]:
        return {
            "model_requests": self.model_requests,
            "title_requests": self.title_requests,
            "model_ids": sorted(self.model_ids),
            "endpoint_counts": dict(sorted(self.endpoint_counts.items())),
            "issued_tools": self.issued_tools,
            "completed_tools": self.completed_tools,
            "search_tool_calls": self.search_tool_calls,
            "final_issued": self.final_issued,
            "protocol_events": self.protocol_events,
        }


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode())


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _require_exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{label} fields do not match: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    supplied = path.expanduser()
    if supplied.is_symlink():
        raise ValueError(f"{label} must not be a symlink: {supplied}")
    resolved = supplied.resolve()
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file: {resolved}")
    raw: object = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    return cast(dict[str, Any], raw)


def load_exact_client_contract(path: Path) -> ExactClientContract:
    supplied = path.expanduser()
    raw = _load_json_object(supplied, "exact-client contract")
    _require_exact_fields(
        raw,
        {"format_version", "clients", "expected_final", "expected_tools", "fixture"},
        "exact-client contract",
    )
    if raw.get("format_version") != EXACT_CLIENT_CONTRACT_VERSION:
        raise ValueError("unsupported exact-client contract format")
    raw_clients = raw.get("clients")
    if not isinstance(raw_clients, list):
        raise ValueError("exact-client contract clients must be a list")
    clients: list[ExactClientSpec] = []
    for index, item in enumerate(cast(list[object], raw_clients)):
        if not isinstance(item, dict):
            raise ValueError(f"exact-client contract client {index} must be an object")
        client = cast(dict[str, Any], item)
        _require_exact_fields(
            client,
            {
                "client_id",
                "family",
                "protocol",
                "install_kind",
                "code_identifier",
                "team_id",
                "package_name",
            },
            "client contract",
        )
        install_kind = _require_string(client.get("install_kind"), "client install kind")
        if install_kind not in EXACT_CLIENT_INSTALL_KINDS:
            raise ValueError("exact-client contract install kind is invalid")
        raw_package_name = client.get("package_name")
        if raw_package_name is not None and not isinstance(raw_package_name, str):
            raise ValueError("client package name must be a string or null")
        clients.append(
            ExactClientSpec(
                client_id=_require_string(client.get("client_id"), "client id"),
                family=_require_string(client.get("family"), "client family"),
                protocol=_require_string(client.get("protocol"), "client protocol"),
                install_kind=install_kind,
                code_identifier=_require_string(
                    client.get("code_identifier"), "client code identifier"
                ),
                team_id=_require_string(client.get("team_id"), "client team identifier"),
                package_name=raw_package_name,
            )
        )
    if tuple(item.client_id for item in clients) != EXACT_CLIENT_IDS:
        raise ValueError("exact-client contract client order is invalid")
    if tuple(item.install_kind for item in clients) != EXACT_CLIENT_INSTALL_KINDS:
        raise ValueError("exact-client contract install-kind order is invalid")
    expected_final = _require_string(raw.get("expected_final"), "expected final marker")
    if expected_final != EXACT_CLIENT_FINAL_MARKER:
        raise ValueError("exact-client contract final marker is invalid")
    raw_tools = raw.get("expected_tools")
    if not isinstance(raw_tools, list) or any(
        not isinstance(item, str) for item in cast(list[object], raw_tools)
    ):
        raise ValueError("exact-client contract tools must be strings")
    expected_tools = tuple(cast(list[str], raw_tools))
    if expected_tools != EXACT_CLIENT_TOOLS:
        raise ValueError("exact-client contract tool order is invalid")
    raw_fixture = raw.get("fixture")
    if not isinstance(raw_fixture, dict):
        raise ValueError("exact-client contract fixture must be an object")
    fixture = cast(dict[str, Any], raw_fixture)
    _require_exact_fields(
        fixture,
        {
            "canary",
            "project_id",
            "query",
            "records",
            "scope",
            "source_account",
            "source_path",
            "source_system",
        },
        "exact-client fixture",
    )
    if fixture.get("source_system") != SourceSystem.CODEX.value:
        raise ValueError("exact-client fixture source system is invalid")
    if fixture.get("scope") != Scope.PROJECT.value:
        raise ValueError("exact-client fixture scope is invalid")
    for key in ("canary", "project_id", "query", "source_account", "source_path"):
        _require_string(fixture.get(key), f"fixture {key}")
    records = fixture.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("exact-client fixture records must be a non-empty list")
    for index, record in enumerate(cast(list[object], records)):
        if not isinstance(record, dict):
            raise ValueError(f"exact-client fixture record {index} must be an object")
    serialized = json.dumps(raw, indent=2, sort_keys=True) + "\n"
    if fixture["canary"] not in serialized:
        raise ValueError("exact-client fixture canary is absent from the fixture")
    resolved = supplied.resolve()
    return ExactClientContract(
        path=resolved,
        sha256=sha256_file(resolved),
        clients=tuple(clients),
        expected_final=expected_final,
        expected_tools=expected_tools,
        fixture=fixture,
    )


def _anthropic_sse(events: list[tuple[str, dict[str, Any]]]) -> bytes:
    return "".join(
        f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"
        for event, data in events
    ).encode()


def _anthropic_tool(name: str, arguments: dict[str, Any], stage: int) -> bytes:
    return _anthropic_sse(
        [
            (
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": f"msg_exact_{stage}",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-sonnet-4-5",
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                    },
                },
            ),
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {
                        "type": "tool_use",
                        "id": f"toolu_exact_{stage}",
                        "name": name,
                        "input": {},
                    },
                },
            ),
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": json.dumps(arguments, separators=(",", ":")),
                    },
                },
            ),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                    "usage": {"output_tokens": 1},
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        ]
    )


def _anthropic_text(text: str) -> bytes:
    return _anthropic_sse(
        [
            (
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_exact_final",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-sonnet-4-5",
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                    },
                },
            ),
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            ),
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": text},
                },
            ),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 1},
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        ]
    )


def _responses_sse(events: list[dict[str, Any]]) -> bytes:
    return "".join(
        f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
        for event in events
    ).encode()


def _responses_usage() -> dict[str, Any]:
    return {
        "input_tokens": 1,
        "input_tokens_details": None,
        "output_tokens": 1,
        "output_tokens_details": None,
        "total_tokens": 2,
    }


def _responses_tool(name: str, arguments: dict[str, Any], stage: int) -> bytes:
    response_id = f"resp_exact_{stage}"
    return _responses_sse(
        [
            {"type": "response.created", "response": {"id": response_id}},
            {
                "type": "response.output_item.done",
                "output_index": 0,
                "item": {
                    "type": "function_call",
                    "id": f"fc_exact_{stage}",
                    "call_id": f"call_exact_{stage}",
                    "namespace": "mcp__cam",
                    "name": name,
                    "arguments": json.dumps(arguments, separators=(",", ":")),
                    "status": "completed",
                },
            },
            {
                "type": "response.completed",
                "response": {"id": response_id, "usage": _responses_usage()},
            },
        ]
    )


def _responses_text(text: str) -> bytes:
    response_id = "resp_exact_final"
    return _responses_sse(
        [
            {"type": "response.created", "response": {"id": response_id}},
            {
                "type": "response.output_item.done",
                "output_index": 0,
                "item": {
                    "type": "message",
                    "role": "assistant",
                    "id": "msg_exact_final",
                    "content": [{"type": "output_text", "text": text}],
                },
            },
            {
                "type": "response.completed",
                "response": {"id": response_id, "usage": _responses_usage()},
            },
        ]
    )


def _chat_sse(
    *,
    model: str,
    text: str | None = None,
    tool_name: str | None = None,
    arguments: dict[str, Any] | None = None,
    stage: int,
) -> bytes:
    completion_id = f"chatcmpl_exact_{stage}"
    if tool_name is not None:
        delta: dict[str, Any] = {
            "role": "assistant",
            "tool_calls": [
                {
                    "index": 0,
                    "id": f"call_exact_{stage}",
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(arguments or {}, separators=(",", ":")),
                    },
                }
            ],
        }
        finish_reason = "tool_calls"
    else:
        delta = {"role": "assistant", "content": text or ""}
        finish_reason = "stop"
    chunks: list[dict[str, Any]] = [
        {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": 0,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
        },
        {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": 0,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
            "usage": {
                "prompt_tokens": 1,
                "completion_tokens": 1,
                "total_tokens": 2,
            },
        },
    ]
    return (
        "".join(f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks)
        + "data: [DONE]\n\n"
    ).encode()


def _dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        cast(dict[str, Any], item) for item in cast(list[object], value) if isinstance(item, dict)
    ]


def _tool_result_text(value: dict[str, Any]) -> str:
    content = value.get("content")
    if isinstance(content, str):
        return content
    return json.dumps(content, sort_keys=True)


def _anthropic_tool_results(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for message in messages:
        for block in _dict_list(message.get("content")):
            if block.get("type") == "tool_result":
                results.append(block)
    return results


def _chat_tool_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in messages if item.get("role") == "tool"]


def _discover_qualified_tool(search_result: str, suffix: str) -> str:
    match = re.search(rf"\b[A-Za-z0-9_-]+__{re.escape(suffix)}\b", search_result)
    if match is None:
        raise ValueError(f"Grok search result omitted qualified {suffix} tool")
    return match.group(0)


class LoopbackContext:
    def __init__(self, contract: ExactClientContract, event_id: str) -> None:
        self.contract = contract
        self.event_id = event_id
        self._lock = threading.Lock()
        self._trace: ClientTrace | None = None

    def begin(self, client: ExactClientSpec) -> None:
        with self._lock:
            if self._trace is not None:
                raise RuntimeError("an exact-client trace is already active")
            self._trace = ClientTrace(client.client_id, client.family, client.protocol)

    def fail(self, reason: str) -> None:
        with self._lock:
            if self._trace is not None and self._trace.failure is None:
                self._trace.failure = reason

    def finish(self) -> ClientTrace:
        with self._lock:
            if self._trace is None:
                raise RuntimeError("no exact-client trace is active")
            trace = self._trace
            self._trace = None
        if trace.failure is not None:
            raise RuntimeError(f"{trace.client_id} loopback protocol failed: {trace.failure}")
        if tuple(trace.issued_tools) != self.contract.expected_tools:
            raise RuntimeError(f"{trace.client_id} did not receive the required tool sequence")
        if tuple(trace.completed_tools) != self.contract.expected_tools:
            raise RuntimeError(f"{trace.client_id} did not complete the required tool sequence")
        if not trace.final_issued:
            raise RuntimeError(f"{trace.client_id} did not reach the final response")
        if trace.family == "grok_cli" and trace.search_tool_calls != 3:
            raise RuntimeError("Grok did not discover each CAM tool independently")
        return trace

    def health(self) -> bytes:
        return b"ok"

    def models(self) -> bytes:
        return _json_bytes(
            {
                "object": "list",
                "data": [
                    {
                        "id": "grok-code-fast-1",
                        "object": "model",
                        "created": 0,
                        "owned_by": "xai",
                    }
                ],
            }
        )

    def post(self, path: str, body: dict[str, Any]) -> tuple[str, bytes]:
        with self._lock:
            if self._trace is None:
                raise RuntimeError("model request arrived without an active client")
            trace = self._trace
            endpoint = path.split("?", 1)[0]
            issued_before = len(trace.issued_tools)
            completed_before = len(trace.completed_tools)
            searches_before = trace.search_tool_calls
            titles_before = trace.title_requests
            trace.model_requests += 1
            trace.endpoint_counts[endpoint] += 1
            model = body.get("model")
            if isinstance(model, str):
                trace.model_ids.add(model)
            if path.startswith("/v1/responses"):
                response = self._codex_response(trace, body)
            elif path.startswith("/v1/messages"):
                response = self._claude_response(trace, body)
            elif path.endswith("/chat/completions"):
                response = self._grok_response(trace, body)
            else:
                raise ValueError(f"unsupported loopback endpoint: {endpoint}")
            issued_delta = trace.issued_tools[issued_before:]
            completed_delta = trace.completed_tools[completed_before:]
            if len(issued_delta) > 1 or len(completed_delta) > 1:
                raise RuntimeError("one protocol request changed multiple tool stages")
            trace.protocol_events.append(
                {
                    "sequence": len(trace.protocol_events) + 1,
                    "endpoint": endpoint,
                    "model_id": model if isinstance(model, str) else None,
                    "request_sha256": _sha256_bytes(_json_bytes(body)),
                    "response_sha256": _sha256_bytes(response),
                    "issued_tool": issued_delta[0] if issued_delta else None,
                    "completed_tool": completed_delta[0] if completed_delta else None,
                    "search_tool_delta": trace.search_tool_calls - searches_before,
                    "title_request_delta": trace.title_requests - titles_before,
                    "final_issued": trace.final_issued,
                }
            )
            return "text/event-stream", response

    def _complete(self, trace: ClientTrace, tool: str) -> None:
        expected_index = len(trace.completed_tools)
        if expected_index >= len(EXACT_CLIENT_TOOLS) or EXACT_CLIENT_TOOLS[expected_index] != tool:
            raise ValueError("client completed CAM tools out of order")
        trace.completed_tools.append(tool)

    def _issue(self, trace: ClientTrace, tool: str) -> None:
        expected_index = len(trace.issued_tools)
        if expected_index >= len(EXACT_CLIENT_TOOLS) or EXACT_CLIENT_TOOLS[expected_index] != tool:
            raise ValueError("loopback attempted to issue CAM tools out of order")
        trace.issued_tools.append(tool)

    def _validate_status(self, text: str) -> None:
        if "read_only" not in text:
            raise ValueError("memory_status result omitted the read-only state")

    def _validate_search(self, text: str) -> None:
        if self.event_id not in text:
            raise ValueError("memory_search result omitted the expected event")

    def _validate_evidence(self, text: str) -> None:
        canary = cast(str, self.contract.fixture["canary"])
        if canary not in text:
            raise ValueError("memory_get_evidence result omitted the expected canary")

    def _codex_response(self, trace: ClientTrace, body: dict[str, Any]) -> bytes:
        if trace.family != "codex":
            raise ValueError("non-Codex client used the Responses endpoint")
        namespace = next(
            (
                item
                for item in _dict_list(body.get("tools"))
                if item.get("type") == "namespace" and item.get("name") == "mcp__cam"
            ),
            None,
        )
        if namespace is None:
            shapes = [
                {"type": item.get("type"), "name": item.get("name")}
                for item in _dict_list(body.get("tools"))
            ]
            raise ValueError(f"Codex omitted the CAM namespace: {shapes}")
        namespace_tools = {
            item.get("name") for item in _dict_list(namespace.get("tools")) if item.get("name")
        }
        if not set(EXACT_CLIENT_TOOLS).issubset(namespace_tools):
            raise ValueError("Codex CAM namespace omitted required tools")
        outputs = [
            item
            for item in _dict_list(body.get("input"))
            if item.get("type") == "function_call_output"
        ]
        stage = len(outputs)
        if stage == 0:
            self._issue(trace, "memory_status")
            return _responses_tool("memory_status", {}, stage)
        if stage == 1:
            self._validate_status(json.dumps(outputs[-1], sort_keys=True))
            self._complete(trace, "memory_status")
            self._issue(trace, "memory_search")
            return _responses_tool(
                "memory_search",
                {"query": self.contract.fixture["query"], "limit": 5},
                stage,
            )
        if stage == 2:
            self._validate_search(json.dumps(outputs[-1], sort_keys=True))
            self._complete(trace, "memory_search")
            self._issue(trace, "memory_get_evidence")
            return _responses_tool("memory_get_evidence", {"event_id": self.event_id}, stage)
        if stage == 3:
            self._validate_evidence(json.dumps(outputs[-1], sort_keys=True))
            self._complete(trace, "memory_get_evidence")
            trace.final_issued = True
            return _responses_text(self.contract.expected_final)
        raise ValueError("Codex submitted unexpected extra tool results")

    def _claude_response(self, trace: ClientTrace, body: dict[str, Any]) -> bytes:
        if trace.family != "claude_code":
            raise ValueError("non-Claude client used the Messages endpoint")
        tools = [item.get("name") for item in _dict_list(body.get("tools"))]
        if not tools:
            return _anthropic_text("CAM_PREFLIGHT_OK")
        by_suffix = {name.rsplit("__", 1)[-1]: name for name in tools if isinstance(name, str)}
        if not set(EXACT_CLIENT_TOOLS).issubset(by_suffix):
            raise ValueError("Claude omitted required CAM tools")
        results = _anthropic_tool_results(_dict_list(body.get("messages")))
        stage = len(results)
        if stage == 0:
            self._issue(trace, "memory_status")
            return _anthropic_tool(by_suffix["memory_status"], {}, stage)
        if stage == 1:
            self._validate_status(_tool_result_text(results[-1]))
            self._complete(trace, "memory_status")
            self._issue(trace, "memory_search")
            return _anthropic_tool(
                by_suffix["memory_search"],
                {"query": self.contract.fixture["query"], "limit": 5},
                stage,
            )
        if stage == 2:
            self._validate_search(_tool_result_text(results[-1]))
            self._complete(trace, "memory_search")
            self._issue(trace, "memory_get_evidence")
            return _anthropic_tool(
                by_suffix["memory_get_evidence"], {"event_id": self.event_id}, stage
            )
        if stage == 3:
            self._validate_evidence(_tool_result_text(results[-1]))
            self._complete(trace, "memory_get_evidence")
            trace.final_issued = True
            return _anthropic_text(self.contract.expected_final)
        raise ValueError("Claude submitted unexpected extra tool results")

    def _grok_response(self, trace: ClientTrace, body: dict[str, Any]) -> bytes:
        if trace.family != "grok_cli":
            raise ValueError("non-Grok client used the Chat Completions endpoint")
        raw_tools = _dict_list(body.get("tools"))
        offered = {
            item.get("function", {}).get("name")
            for item in raw_tools
            if isinstance(item.get("function"), dict)
        }
        model = _require_string(body.get("model"), "Grok request model")
        if "session_title" in offered:
            trace.title_requests += 1
            return _chat_sse(
                model=model,
                tool_name="session_title",
                arguments={"session_title": "CAM exact client evaluation"},
                stage=-1,
            )
        if not {"search_tool", "use_tool"}.issubset(offered):
            raise ValueError("Grok omitted deferred search or use tools")
        messages = _dict_list(body.get("messages"))
        results = _chat_tool_messages(messages)
        stage = len(results)
        if stage == 0:
            trace.search_tool_calls += 1
            return _chat_sse(
                model=model,
                tool_name="search_tool",
                arguments={"query": "memory_status", "limit": 5},
                stage=stage,
            )
        if stage == 1:
            target = _discover_qualified_tool(_tool_result_text(results[-1]), "memory_status")
            self._issue(trace, "memory_status")
            return _chat_sse(
                model=model,
                tool_name="use_tool",
                arguments={"tool_name": target, "tool_input": {}},
                stage=stage,
            )
        if stage == 2:
            self._validate_status(_tool_result_text(results[-1]))
            self._complete(trace, "memory_status")
            trace.search_tool_calls += 1
            return _chat_sse(
                model=model,
                tool_name="search_tool",
                arguments={"query": "memory_search", "limit": 5},
                stage=stage,
            )
        if stage == 3:
            target = _discover_qualified_tool(_tool_result_text(results[-1]), "memory_search")
            self._issue(trace, "memory_search")
            return _chat_sse(
                model=model,
                tool_name="use_tool",
                arguments={
                    "tool_name": target,
                    "tool_input": {"query": self.contract.fixture["query"], "limit": 5},
                },
                stage=stage,
            )
        if stage == 4:
            search_text = _tool_result_text(results[-1])
            self._validate_search(search_text)
            self._complete(trace, "memory_search")
            trace.search_tool_calls += 1
            return _chat_sse(
                model=model,
                tool_name="search_tool",
                arguments={"query": "memory_get_evidence", "limit": 5},
                stage=stage,
            )
        if stage == 5:
            target = _discover_qualified_tool(_tool_result_text(results[-1]), "memory_get_evidence")
            prior_search = _tool_result_text(results[-2])
            match = EVENT_ID_PATTERN.search(prior_search)
            if match is None or match.group(0) != self.event_id:
                raise ValueError("Grok did not carry forward the searched event identifier")
            self._issue(trace, "memory_get_evidence")
            return _chat_sse(
                model=model,
                tool_name="use_tool",
                arguments={"tool_name": target, "tool_input": {"event_id": self.event_id}},
                stage=stage,
            )
        if stage == 6:
            self._validate_evidence(_tool_result_text(results[-1]))
            self._complete(trace, "memory_get_evidence")
            trace.final_issued = True
            return _chat_sse(model=model, text=self.contract.expected_final, stage=stage)
        raise ValueError("Grok submitted unexpected extra tool results")


class _EvaluationHTTPServer(ThreadingHTTPServer):
    def __init__(self, context: LoopbackContext) -> None:
        self.context = context
        super().__init__(("127.0.0.1", 0), _EvaluationHandler)


class _EvaluationHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = cast(_EvaluationHTTPServer, self.server)
        if self.path == "/health-probe":
            self._send(200, "text/plain", server.context.health())
            return
        if self.path == "/models":
            self._send(200, "application/json", server.context.models())
            return
        self._send(404, "application/json", _json_bytes({"error": "not_found"}))

    def do_POST(self) -> None:
        server = cast(_EvaluationHTTPServer, self.server)
        try:
            raw_length = self.headers.get("content-length")
            if raw_length is None:
                raise ValueError("loopback request omitted content length")
            length = int(raw_length)
            if length < 0 or length > MAX_REQUEST_BYTES:
                raise ValueError("loopback request exceeded the body limit")
            raw_body = self.rfile.read(length)
            parsed: object = json.loads(raw_body)
            if not isinstance(parsed, dict):
                raise ValueError("loopback request body must be an object")
            content_type, response = server.context.post(self.path, cast(dict[str, Any], parsed))
        except (AssertionError, KeyError, TypeError, ValueError) as error:
            server.context.fail(str(error))
            self._send(
                400,
                "application/json",
                _json_bytes({"error": {"message": "evaluation protocol rejected"}}),
            )
            return
        self._send(200, content_type, response)

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args
        return


class LoopbackServer:
    def __init__(self, context: LoopbackContext) -> None:
        self._server = _EvaluationHTTPServer(context)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="cam-exact-client-loopback",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return self._server.server_port

    def __enter__(self) -> LoopbackServer:
        self._thread.start()
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("exact-client loopback server did not stop")


def _run_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int = PROCESS_TIMEOUT_SECONDS,
) -> ProcessResult:
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    process_group = process.pid
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        _terminate_process_group(process, process_group)
        raise RuntimeError("exact-client process exceeded its bounded timeout") from error
    except BaseException:
        _terminate_process_group(process, process_group)
        raise
    else:
        _terminate_orphaned_process_group(process_group)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if len(stdout) > MAX_PROCESS_OUTPUT_BYTES or len(stderr) > MAX_PROCESS_OUTPUT_BYTES:
        raise RuntimeError("exact-client process exceeded its output limit")
    return ProcessResult(process.returncode, stdout, stderr, elapsed_ms)


def _terminate_orphaned_process_group(process_group: int) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGTERM)
    time.sleep(0.05)
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGKILL)


def _terminate_process_group(process: subprocess.Popen[bytes], process_group: int) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGTERM)
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process_group, signal.SIGKILL)
        process.communicate()


def _run_checked(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    label: str,
) -> ProcessResult:
    result = _run_process(command, cwd=cwd, env=env)
    if result.returncode != 0:
        raise RuntimeError(
            f"{label} failed with exit {result.returncode}; "
            f"stdout_sha256={_sha256_bytes(result.stdout)}; "
            f"stderr_sha256={_sha256_bytes(result.stderr)}"
        )
    return result


def _base_environment(home: Path, temporary: Path, executable: Path) -> dict[str, str]:
    path_parts = [str(executable.parent), "/opt/homebrew/bin", "/usr/bin", "/bin"]
    return {
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "PATH": ":".join(dict.fromkeys(path_parts)),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_PROXY": "127.0.0.1,localhost",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _scheme_string(value: str) -> str:
    return json.dumps(value)


def build_sandbox_profile(
    *,
    real_home: Path,
    repository: Path,
    working_root: Path,
    ledger_root: Path,
    loopback_port: int,
    executables: tuple[Path, ...],
) -> str:
    if not 1 <= loopback_port <= 65535:
        raise ValueError("exact-client loopback port is invalid")
    allowed_read_roots = {repository.resolve(), working_root.resolve(), ledger_root.resolve()}
    for executable in executables:
        supplied = executable.expanduser().absolute()
        allowed_read_roots.add(supplied.parent)
        allowed_read_roots.add(supplied.resolve().parent)
    clauses = [
        "(version 1)",
        "(allow default)",
        f"(deny file-read* (subpath {_scheme_string(str(real_home.resolve()))}))",
        f"(allow file-read-metadata (subpath {_scheme_string(str(real_home.resolve()))}))",
        "(deny file-write*)",
        "(deny network-inbound)",
        "(deny network-outbound)",
    ]
    clauses.extend(
        f"(allow file-read* (subpath {_scheme_string(str(path))}))"
        for path in sorted(allowed_read_roots, key=str)
    )
    clauses.extend(
        [
            f"(allow file-write* (subpath {_scheme_string(str(working_root.resolve()))}))",
            '(allow file-write* (literal "/dev/null"))',
            f'(allow network-outbound (remote ip "localhost:{loopback_port}"))',
        ]
    )
    return "".join(clauses)


def _sandbox_command(sandbox_exec: Path, profile: str, command: list[str]) -> list[str]:
    return [str(sandbox_exec), "-p", profile, *command]


def _preflight_script(kind: str) -> str:
    scripts = {
        "home": (
            "import errno,sys\n"
            "try:\n open(sys.argv[1], 'rb').read(1)\n"
            "except OSError as exc:\n"
            " sys.exit(0 if exc.errno in (errno.EPERM, errno.EACCES) else 3)\n"
            "sys.exit(2)\n"
        ),
        "loopback": (
            "import sys,urllib.request\n"
            "with urllib.request.urlopen(sys.argv[1], timeout=3) as response:\n"
            " data=response.read(3)\n"
            "sys.exit(0 if data == b'ok' else 2)\n"
        ),
        "nonloopback": (
            "import errno,socket,sys\n"
            "sock=socket.socket(); sock.settimeout(2)\n"
            "try:\n sock.connect(('1.1.1.1', 80))\n"
            "except OSError as exc:\n"
            " sys.exit(0 if exc.errno in (errno.EPERM, errno.EACCES) else 3)\n"
            "finally:\n sock.close()\n"
            "sys.exit(2)\n"
        ),
        "url-denied": (
            "import errno,sys,urllib.error,urllib.request\n"
            "try:\n urllib.request.urlopen(sys.argv[1], timeout=3).read(1)\n"
            "except urllib.error.URLError as exc:\n"
            " reason=exc.reason\n"
            " code=getattr(reason, 'errno', None)\n"
            " sys.exit(0 if code in (errno.EPERM, errno.EACCES) else 3)\n"
            "except OSError as exc:\n"
            " sys.exit(0 if exc.errno in (errno.EPERM, errno.EACCES) else 3)\n"
            "sys.exit(2)\n"
        ),
        "write": (
            "import errno,sys\n"
            "try:\n open(sys.argv[1], 'xb').close()\n"
            "except OSError as exc:\n"
            " sys.exit(0 if exc.errno in (errno.EPERM, errno.EACCES) else 3)\n"
            "sys.exit(2)\n"
        ),
        "write-existing": (
            "import errno,sys\n"
            "try:\n"
            " with open(sys.argv[1], 'ab') as handle:\n  handle.write(b'x')\n"
            "except OSError as exc:\n"
            " sys.exit(0 if exc.errno in (errno.EPERM, errno.EACCES) else 3)\n"
            "sys.exit(2)\n"
        ),
        "working-write": ("import sys\nwith open(sys.argv[1], 'xb'):\n pass\nsys.exit(0)\n"),
    }
    return scripts[kind]


def run_sandbox_preflight(
    *,
    sandbox_exec: Path,
    profile: str,
    working_root: Path,
    port: int,
    denied_loopback_port: int,
    ledger_probe: Path,
    real_home: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    marker = real_home / "AGENTS.md"
    if not marker.is_file():
        raise RuntimeError("sandbox preflight requires the existing home AGENTS.md marker")
    outside = Path("/private/tmp") / f"cam-exact-client-denied-{uuid.uuid4().hex}"
    inside = working_root / f"sandbox-write-{uuid.uuid4().hex}"
    checks = {
        "real_home_read_denied": [str(marker)],
        "loopback_allowed": [f"http://127.0.0.1:{port}/health-probe"],
        "other_loopback_port_denied": [f"http://127.0.0.1:{denied_loopback_port}/health-probe"],
        "non_loopback_denied": [],
        "outside_write_denied": [str(outside)],
        "ledger_write_denied": [str(ledger_probe)],
        "working_write_allowed": [str(inside)],
    }
    kinds = {
        "real_home_read_denied": "home",
        "loopback_allowed": "loopback",
        "other_loopback_port_denied": "url-denied",
        "non_loopback_denied": "nonloopback",
        "outside_write_denied": "write",
        "ledger_write_denied": "write-existing",
        "working_write_allowed": "working-write",
    }
    results: dict[str, bool] = {}
    try:
        execution_probe = _run_process(
            _sandbox_command(
                sandbox_exec,
                profile,
                ["/usr/bin/python3", "-c", "import sys; sys.exit(23)"],
            ),
            cwd=working_root,
            env=env,
            timeout_seconds=15,
        )
        results["command_executed"] = execution_probe.returncode == 23
        for label, arguments in checks.items():
            command = _sandbox_command(
                sandbox_exec,
                profile,
                ["/usr/bin/python3", "-c", _preflight_script(kinds[label]), *arguments],
            )
            result = _run_process(command, cwd=working_root, env=env, timeout_seconds=15)
            results[label] = result.returncode == 0
        if not all(results.values()):
            failed = sorted(label for label, passed in results.items() if not passed)
            raise RuntimeError(f"macOS sandbox preflight failed: {failed}")
    finally:
        if inside.exists():
            inside.unlink()
        if outside.exists():
            outside.unlink()
    return {
        "sandbox_enforced": True,
        "profile_sha256": _sha256_text(profile),
        **results,
    }


def _checkpoint_database(database_path: Path) -> None:
    with sqlite3.connect(database_path, isolation_level=None) as connection:
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None or checkpoint[0] != 0:
            raise RuntimeError("exact-client ledger WAL checkpoint did not complete")
    for suffix in ("-wal", "-shm"):
        database_path.with_name(f"{database_path.name}{suffix}").unlink(missing_ok=True)


def _fixture_source_bytes(contract: ExactClientContract) -> bytes:
    records = cast(list[dict[str, Any]], contract.fixture["records"])
    return b"".join(_json_bytes(record) + b"\n" for record in records)


def _build_fixture_ledger(
    contract: ExactClientContract, working_root: Path
) -> tuple[Path, Path, str, dict[str, Any]]:
    source = working_root / "fixture.jsonl"
    source.write_bytes(_fixture_source_bytes(contract))
    source.chmod(0o600)
    ledger_root = working_root / "ledger"
    settings = Settings(ledger_root)
    ledger = Ledger(settings)
    parsed = parse_file(source, SourceSystem.CODEX)
    report = ledger.ingest(
        parsed,
        source_account=cast(str, contract.fixture["source_account"]),
        scope=Scope.PROJECT,
        project_id=cast(str, contract.fixture["project_id"]),
        source_path=cast(str, contract.fixture["source_path"]),
    )
    if report.inserted_events != 1 or report.quarantined_records != 0:
        raise RuntimeError("exact-client fixture did not ingest exactly one evidence event")
    results = ledger.search(
        cast(str, contract.fixture["query"]),
        mode=QueryMode.FIND_EVIDENCE,
        scopes=(Scope.PROJECT,),
        project_id=cast(str, contract.fixture["project_id"]),
        authorities=None,
        limit=5,
        principal="evaluation:exact-client-fixture",
    )
    canary = cast(str, contract.fixture["canary"])
    matching = [
        item
        for item in results
        if canary in cast(str, ledger.get_evidence(item.event_id).get("raw_record", ""))
    ]
    if len(matching) != 1:
        raise RuntimeError("exact-client fixture canary did not resolve to one evidence event")
    event_id = matching[0].event_id
    _checkpoint_database(settings.database_path)
    set_read_only_tree(ledger_root)
    return (
        ledger_root,
        settings.database_path,
        event_id,
        {
            "source_sha256": _sha256_bytes(_fixture_source_bytes(contract)),
            "event_id_sha256": _sha256_text(event_id),
            "query_sha256": _sha256_text(cast(str, contract.fixture["query"])),
            "canary_sha256": _sha256_text(canary),
        },
    )


def ledger_tree_snapshot(root: Path) -> list[dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("exact-client ledger root must be a regular directory")
    entries: list[dict[str, Any]] = []
    paths = [root, *sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root)))]
    for path in paths:
        if path.is_symlink():
            raise ValueError("exact-client ledger tree must not contain symlinks")
        metadata = path.stat()
        relative = "." if path == root else str(path.relative_to(root))
        if path.is_dir():
            kind = "directory"
            digest: str | None = None
        elif path.is_file():
            kind = "file"
            digest = sha256_file(path)
        else:
            raise ValueError(f"unsupported exact-client ledger entry: {relative}")
        entries.append(
            {
                "path": relative,
                "kind": kind,
                "mode": stat.S_IMODE(metadata.st_mode),
                "bytes": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "sha256": digest,
            }
        )
    return entries


def _regular_executable(path: Path, label: str) -> Path:
    supplied = path.expanduser().absolute()
    if not supplied.exists():
        raise ValueError(f"{label} does not exist: {supplied}")
    resolved = supplied.resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"{label} is not an executable regular file: {resolved}")
    return supplied


def _system_home() -> Path:
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    if not home.is_dir():
        raise RuntimeError("the operating-system account home is unavailable")
    return home


def _codesign_identity(path: Path) -> tuple[str, str]:
    verification = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(path)],
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise RuntimeError("exact-client native payload failed strict code-signature validation")
    details = subprocess.run(
        ["/usr/bin/codesign", "-dv", "--verbose=4", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if details.returncode != 0:
        raise RuntimeError("exact-client native payload omitted code-signature details")
    values: dict[str, str] = {}
    for line in details.stderr.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"Identifier", "TeamIdentifier"}:
            values[key] = value
    identifier = values.get("Identifier")
    team_id = values.get("TeamIdentifier")
    if not identifier or not team_id:
        raise RuntimeError("exact-client native payload has no vendor signing identity")
    return identifier, team_id


def _identity_entry(path: Path, role: str) -> dict[str, Any]:
    resolved = path.resolve()
    code_identifier: str | None = None
    team_id: str | None = None
    if role == "native_payload":
        code_identifier, team_id = _codesign_identity(resolved)
    return {
        "role": role,
        "bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
        "code_identifier": code_identifier,
        "team_id": team_id,
    }


def _codex_native_payload(launcher: Path) -> Path | None:
    resolved = launcher.resolve()
    if resolved.suffix != ".js":
        return None
    package_root = resolved.parent.parent
    candidates = sorted(
        item
        for item in (package_root / "node_modules").glob("@openai/codex-*/vendor/*/bin/codex")
        if item.is_file()
        and not item.is_symlink()
        and item == item.resolve()
        and os.access(item, os.X_OK)
    )
    if len(candidates) != 1:
        raise RuntimeError("Codex launcher did not resolve to exactly one native payload")
    return candidates[0]


def executable_identity(path: Path, client: ExactClientSpec) -> dict[str, Any]:
    supplied = path.expanduser().absolute()
    resolved = path.resolve()
    package_name: str | None = None
    package_version: str | None = None
    if client.install_kind == "chatgpt_app_bundle":
        expected = Path("/Applications/ChatGPT.app/Contents/Resources/codex")
        if supplied != expected or resolved != expected.resolve():
            raise RuntimeError("bundled Codex is not the ChatGPT application payload")
    elif client.install_kind == "openai_npm":
        if resolved.name != "codex.js" or resolved.parent.name != "bin":
            raise RuntimeError("PATH Codex is not an OpenAI npm launcher")
        package_root = resolved.parent.parent
        package = _load_json_object(package_root / "package.json", "OpenAI Codex package")
        package_name = _require_string(package.get("name"), "OpenAI Codex package name")
        package_version = _require_string(package.get("version"), "OpenAI Codex package version")
        if package_name != client.package_name:
            raise RuntimeError("PATH Codex npm package identity is invalid")
        discovered = shutil.which("codex")
        if discovered is None or not os.path.samefile(discovered, supplied):
            raise RuntimeError("PATH Codex does not match the active shell command")
    elif client.install_kind not in {"anthropic_native", "xai_native"}:
        raise RuntimeError("unsupported exact-client installation kind")
    entries = [
        _identity_entry(resolved, "launcher" if resolved.suffix == ".js" else "native_payload")
    ]
    if client.family == "codex":
        payload = _codex_native_payload(path)
        if payload is not None:
            entries.append(_identity_entry(payload, "native_payload"))
    roles = [cast(str, item["role"]) for item in entries]
    if roles.count("native_payload") != 1:
        raise RuntimeError("client identity must bind exactly one native payload")
    native = next(item for item in entries if item["role"] == "native_payload")
    if native["code_identifier"] != client.code_identifier or native["team_id"] != client.team_id:
        raise RuntimeError(f"{client.client_id} vendor signing identity is invalid")
    if client.package_name is None and package_name is not None:
        raise RuntimeError(f"{client.client_id} unexpectedly resolved through a package")
    return {
        "install_kind": client.install_kind,
        "supplied_path_sha256": _sha256_text(str(supplied)),
        "resolved_path_sha256": _sha256_text(str(resolved)),
        "execution_path_sha256": _sha256_text(str(_client_execution_path(path, client))),
        "package_name": package_name,
        "package_version": package_version,
        "entries": entries,
    }


def _client_execution_path(path: Path, client: ExactClientSpec) -> Path:
    del client
    return path.expanduser().absolute()


def _native_payload_path(path: Path, client: ExactClientSpec) -> Path:
    payload = _codex_native_payload(path) if client.family == "codex" else None
    return payload.resolve() if payload is not None else path.resolve()


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _mcp_command(repository: Path, ledger_root: Path, principal: str) -> tuple[str, list[str]]:
    command = repository / "script" / "cross-memory"
    if not command.is_file() or not os.access(command, os.X_OK):
        raise RuntimeError("exact-client MCP launcher is unavailable")
    return (
        str(command),
        [
            "--home",
            str(ledger_root),
            "serve",
            "--transport",
            "stdio",
            "--read-only",
            "--principal",
            principal,
        ],
    )


def _write_codex_config(
    path: Path,
    *,
    port: int,
    repository: Path,
    ledger_root: Path,
    principal: str,
) -> None:
    command, arguments = _mcp_command(repository, ledger_root, principal)
    argument_list = ", ".join(_toml_string(item) for item in arguments)
    path.write_text(
        'model = "cam-eval"\n'
        'model_provider = "loopback"\n\n'
        "[model_providers.loopback]\n"
        'name = "CAM exact-client evaluation"\n'
        f'base_url = "http://127.0.0.1:{port}/v1"\n'
        'env_key = "CAM_EVAL_API_KEY"\n'
        'wire_api = "responses"\n'
        "request_max_retries = 0\n"
        "stream_max_retries = 0\n\n"
        "[mcp_servers.cam]\n"
        f"command = {_toml_string(command)}\n"
        f"args = [{argument_list}]\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _write_claude_config(
    path: Path,
    *,
    repository: Path,
    ledger_root: Path,
    principal: str,
) -> None:
    command, arguments = _mcp_command(repository, ledger_root, principal)
    path.write_text(
        json.dumps(
            {"mcpServers": {"cam": {"command": command, "args": arguments}}},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _version(
    executable: Path,
    *,
    sandbox_exec: Path,
    profile: str,
    cwd: Path,
    env: dict[str, str],
) -> str:
    result = _run_checked(
        _sandbox_command(sandbox_exec, profile, [str(executable), "--version"]),
        cwd=cwd,
        env=env,
        label="client version probe",
    )
    value = result.stdout.decode("utf-8", errors="strict").strip()
    if not value or len(value) > 500 or "\x00" in value:
        raise RuntimeError("client version output is invalid")
    return value


def _contains_exact_string(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value.strip() == expected
    if isinstance(value, list):
        return any(_contains_exact_string(item, expected) for item in cast(list[object], value))
    if isinstance(value, dict):
        return any(
            _contains_exact_string(item, expected)
            for item in cast(dict[object, object], value).values()
        )
    return False


def _validate_json_marker(raw: bytes, expected: str, label: str) -> None:
    try:
        parsed: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} did not return one JSON object") from error
    if not _contains_exact_string(parsed, expected):
        raise RuntimeError(f"{label} omitted the exact final marker")


def _client_result(
    *,
    client: ExactClientSpec,
    identity: dict[str, Any],
    version: str,
    process: ProcessResult,
    trace: ClientTrace,
    sandbox: dict[str, Any],
) -> dict[str, Any]:
    return {
        "client_id": client.client_id,
        "family": client.family,
        "protocol": client.protocol,
        "status": "passed",
        "version": version,
        "version_sha256": _sha256_text(version),
        "executable_identity": identity,
        "exit_code": process.returncode,
        "elapsed_ms": round(process.elapsed_ms, 3),
        "stdout_bytes": len(process.stdout),
        "stdout_sha256": _sha256_bytes(process.stdout),
        "stderr_bytes": len(process.stderr),
        "stderr_sha256": _sha256_bytes(process.stderr),
        "exact_output_persisted": False,
        "final_marker_seen": True,
        "trace": trace.public_summary(),
        "sandbox": sandbox,
    }


def _run_codex_client(
    *,
    client: ExactClientSpec,
    executable: Path,
    sandbox_exec: Path,
    profile: str,
    client_root: Path,
    repository: Path,
    ledger_root: Path,
    port: int,
    context: LoopbackContext,
    sandbox: dict[str, Any],
) -> dict[str, Any]:
    execution_path = _client_execution_path(executable, client)
    home = client_root / "home"
    work = client_root / "work"
    temporary = client_root / "tmp"
    for directory in (home, work, temporary):
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    _write_codex_config(
        home / "config.toml",
        port=port,
        repository=repository,
        ledger_root=ledger_root,
        principal=f"exact-client:{client.client_id}",
    )
    env = _base_environment(home, temporary, execution_path)
    env.update({"CODEX_HOME": str(home), "CAM_EVAL_API_KEY": "public-synthetic-key"})
    identity = executable_identity(executable, client)
    version = _version(
        execution_path,
        sandbox_exec=sandbox_exec,
        profile=profile,
        cwd=work,
        env=env,
    )
    output_message = client_root / "last-message.txt"
    prompt = (
        "Use CAM tools to check status, search for Atlas rollback code, retrieve exact evidence, "
        "and print exactly CAM_EXACT_CLIENT_PASS only after all three calls succeed."
    )
    command = [
        str(execution_path),
        "exec",
        "--strict-config",
        "--sandbox",
        "read-only",
        "--ephemeral",
        "--ignore-rules",
        "--skip-git-repo-check",
        "--color",
        "never",
        "--output-last-message",
        str(output_message),
        prompt,
    ]
    context.begin(client)
    try:
        process = _run_checked(
            _sandbox_command(sandbox_exec, profile, command),
            cwd=work,
            env=env,
            label=client.client_id,
        )
        trace = context.finish()
    except BaseException:
        with suppress(Exception):
            context.finish()
        raise
    if not output_message.is_file():
        raise RuntimeError(f"{client.client_id} did not write its final message")
    final = output_message.read_text(encoding="utf-8").strip()
    if final != EXACT_CLIENT_FINAL_MARKER:
        raise RuntimeError(f"{client.client_id} omitted the exact final marker")
    if executable_identity(executable, client) != identity:
        raise RuntimeError(f"{client.client_id} executable identity changed during evaluation")
    return _client_result(
        client=client,
        identity=identity,
        version=version,
        process=process,
        trace=trace,
        sandbox=sandbox,
    )


def _run_claude_client(
    *,
    client: ExactClientSpec,
    executable: Path,
    sandbox_exec: Path,
    profile: str,
    client_root: Path,
    repository: Path,
    ledger_root: Path,
    port: int,
    context: LoopbackContext,
    sandbox: dict[str, Any],
) -> dict[str, Any]:
    execution_path = _client_execution_path(executable, client)
    home = client_root / "home"
    work = client_root / "work"
    temporary = client_root / "tmp"
    for directory in (home, work, temporary):
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    mcp_config = client_root / "mcp.json"
    _write_claude_config(
        mcp_config,
        repository=repository,
        ledger_root=ledger_root,
        principal=f"exact-client:{client.client_id}",
    )
    env = _base_environment(home, temporary, execution_path)
    env.update(
        {
            "ANTHROPIC_API_KEY": "public-synthetic-key",
            "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
        }
    )
    identity = executable_identity(executable, client)
    version = _version(
        execution_path,
        sandbox_exec=sandbox_exec,
        profile=profile,
        cwd=work,
        env=env,
    )
    prompt = (
        "Use CAM tools to check status, search for Atlas rollback code, retrieve exact evidence, "
        "and print exactly CAM_EXACT_CLIENT_PASS only after all three calls succeed."
    )
    command = [
        str(execution_path),
        "--bare",
        "--print",
        "--output-format",
        "json",
        "--no-session-persistence",
        "--tools",
        "",
        "--mcp-config",
        str(mcp_config),
        "--strict-mcp-config",
        "--permission-mode",
        "dontAsk",
        "--allowedTools",
        "mcp__cam__memory_status,mcp__cam__memory_search,mcp__cam__memory_get_evidence",
        "--max-turns",
        "4",
        "--model",
        "claude-sonnet-4-5",
        prompt,
    ]
    context.begin(client)
    try:
        process = _run_checked(
            _sandbox_command(sandbox_exec, profile, command),
            cwd=work,
            env=env,
            label=client.client_id,
        )
        trace = context.finish()
    except BaseException:
        with suppress(Exception):
            context.finish()
        raise
    _validate_json_marker(process.stdout, EXACT_CLIENT_FINAL_MARKER, client.client_id)
    if executable_identity(executable, client) != identity:
        raise RuntimeError(f"{client.client_id} executable identity changed during evaluation")
    return _client_result(
        client=client,
        identity=identity,
        version=version,
        process=process,
        trace=trace,
        sandbox=sandbox,
    )


def _run_grok_client(
    *,
    client: ExactClientSpec,
    executable: Path,
    sandbox_exec: Path,
    profile: str,
    client_root: Path,
    repository: Path,
    ledger_root: Path,
    port: int,
    context: LoopbackContext,
    sandbox: dict[str, Any],
) -> dict[str, Any]:
    execution_path = _client_execution_path(executable, client)
    home = client_root / "home"
    grok_home = home / ".grok"
    work = client_root / "work"
    temporary = client_root / "tmp"
    for directory in (home, grok_home, work, temporary):
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    leader_socket = client_root / "leader.sock"
    env = _base_environment(home, temporary, execution_path)
    env.update(
        {
            "GROK_HOME": str(grok_home),
            "XAI_API_KEY": "public-synthetic-key",
            "GROK_CODE_XAI_API_KEY": "public-synthetic-key",
            "GROK_CLI_CHAT_PROXY_BASE_URL": f"http://127.0.0.1:{port}",
            "GROK_MODELS_BASE_URL": f"http://127.0.0.1:{port}",
        }
    )
    identity = executable_identity(executable, client)
    version = _version(
        execution_path,
        sandbox_exec=sandbox_exec,
        profile=profile,
        cwd=work,
        env=env,
    )
    command, arguments = _mcp_command(repository, ledger_root, f"exact-client:{client.client_id}")
    registration = [
        str(execution_path),
        "mcp",
        "add",
        "--leader-socket",
        str(leader_socket),
        "--command",
        command,
        *[f"--args={argument}" for argument in arguments],
        "cam",
    ]
    _run_checked(
        _sandbox_command(sandbox_exec, profile, registration),
        cwd=work,
        env=env,
        label="Grok isolated MCP registration",
    )
    prompt = (
        "Use CAM tools to check status, search for Atlas rollback code, retrieve exact evidence, "
        "and print exactly CAM_EXACT_CLIENT_PASS only after all three calls succeed."
    )
    run_command = [
        str(execution_path),
        "--leader-socket",
        str(leader_socket),
        "--single",
        prompt,
        "--model",
        "grok-code-fast-1",
        "--verbatim",
        "--output-format",
        "json",
        "--no-memory",
        "--no-subagents",
        "--disable-web-search",
        "--tools",
        "search_tool,use_tool",
        "--always-approve",
        "--no-plan",
        "--max-turns",
        "10",
    ]
    context.begin(client)
    try:
        process = _run_checked(
            _sandbox_command(sandbox_exec, profile, run_command),
            cwd=work,
            env=env,
            label=client.client_id,
        )
        trace = context.finish()
    except BaseException:
        with suppress(Exception):
            context.finish()
        raise
    _validate_json_marker(process.stdout, EXACT_CLIENT_FINAL_MARKER, client.client_id)
    if executable_identity(executable, client) != identity:
        raise RuntimeError(f"{client.client_id} executable identity changed during evaluation")
    return _client_result(
        client=client,
        identity=identity,
        version=version,
        process=process,
        trace=trace,
        sandbox=sandbox,
    )


def _resolve_revision(repository: Path, revision: str) -> str:
    if not revision or "\x00" in revision:
        raise ValueError("exact-client revision is invalid")
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    resolved = result.stdout.strip()
    if result.returncode != 0 or GIT_OBJECT_PATTERN.fullmatch(resolved) is None:
        raise RuntimeError(f"exact-client revision is unavailable: {revision}")
    return resolved


def _revision_file_hashes(repository: Path, revision: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in EXACT_CLIENT_HARNESS_PATHS:
        result = subprocess.run(
            ["git", "show", f"{revision}:{relative}"],
            cwd=repository,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"exact-client harness path is absent at {revision}: {relative}")
        hashes[relative] = _sha256_bytes(result.stdout)
    return hashes


def _revision_tree(repository: Path, revision: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{revision}^{{tree}}"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    tree = result.stdout.strip()
    if result.returncode != 0 or GIT_OBJECT_PATTERN.fullmatch(tree) is None:
        raise RuntimeError("exact-client revision tree is unavailable")
    return tree


def _git_blob_digest(data: bytes, object_length: int) -> str:
    payload = f"blob {len(data)}\0".encode() + data
    if object_length == 40:
        return hashlib.sha1(payload, usedforsecurity=False).hexdigest()
    if object_length == 64:
        return hashlib.sha256(payload).hexdigest()
    raise RuntimeError("unsupported Git object format")


def _verify_checkout_tree(repository: Path, revision: str) -> None:
    result = subprocess.run(
        ["git", "ls-tree", "-rz", "--full-tree", revision],
        cwd=repository,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("exact-client revision contents are unavailable")
    for raw_entry in result.stdout.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise RuntimeError("exact-client revision tree entry is invalid")
        mode, kind, raw_object_id = fields
        if kind != b"blob":
            raise RuntimeError("exact-client revision contains an unsupported non-blob entry")
        try:
            relative = raw_path.decode("utf-8", errors="strict")
            object_id = raw_object_id.decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise RuntimeError("exact-client revision path or object id is invalid") from error
        path = repository / relative
        if mode == b"120000":
            if not path.is_symlink():
                raise RuntimeError("exact-client checkout symlink identity changed")
            data = os.readlink(path).encode()
        elif mode in {b"100644", b"100755"}:
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("exact-client checkout file identity changed")
            executable = bool(path.stat().st_mode & 0o111)
            if executable != (mode == b"100755"):
                raise RuntimeError("exact-client checkout executable mode changed")
            data = path.read_bytes()
        else:
            raise RuntimeError("exact-client revision contains an unsupported file mode")
        if _git_blob_digest(data, len(object_id)) != object_id:
            raise RuntimeError("exact-client checkout content does not match the revision")


def _assert_checkout_at_revision(repository: Path, revision: str) -> str:
    head = _resolve_revision(repository, "HEAD")
    if head != revision:
        raise RuntimeError("exact-client execution requires the requested revision at HEAD")
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=no"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    if status.returncode != 0:
        raise RuntimeError("exact-client checkout status is unavailable")
    if status.stdout:
        raise RuntimeError("exact-client execution requires a clean tracked checkout")
    _verify_checkout_tree(repository, revision)
    return _revision_tree(repository, revision)


def _assert_contract_at_revision(
    contract: ExactClientContract, repository: Path, revision: str
) -> None:
    canonical = (repository / EXACT_CLIENT_CONTRACT_PATH).resolve()
    if contract.path != canonical:
        raise RuntimeError("exact-client execution requires the canonical contract")
    expected = _revision_file_hashes(repository, revision)[str(EXACT_CLIENT_CONTRACT_PATH)]
    if contract.sha256 != expected:
        raise RuntimeError("exact-client contract does not match the requested revision")


def _make_writable(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o700)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(0o700 if path.is_dir() else 0o600)


def _publish_verified_directory(
    source: Path,
    target: Path,
    verify: Callable[[Path], object],
) -> object:
    verification = verify(source)
    source_identity = source.stat()
    try:
        publish_directory_no_replace(
            source,
            target,
            required_mode=0o500,
            label="exact-client evaluation",
        )
    except BaseException:
        try:
            target_identity = target.lstat()
        except FileNotFoundError:
            target_identity = None
        if (
            target_identity is not None
            and stat.S_ISDIR(target_identity.st_mode)
            and target_identity.st_dev == source_identity.st_dev
            and target_identity.st_ino == source_identity.st_ino
        ):
            try:
                verification = verify(target)
                parent_descriptor = open_directory_no_symlinks(
                    target.parent, "exact-client publication parent"
                )
                try:
                    os.fsync(parent_descriptor)
                finally:
                    os.close(parent_descriptor)
            except BaseException as recovery_error:
                raise RuntimeError(
                    "exact-client publication moved but could not be durably recovered"
                ) from recovery_error
            return verification
        raise
    return verification


def run_exact_client_evaluation(
    *,
    contract_path: Path,
    output: Path,
    codex_bundled: Path,
    codex_path: Path,
    claude: Path,
    grok: Path,
    sandbox_exec: Path,
    revision: str = "HEAD",
    execute: bool = False,
) -> dict[str, Any]:
    contract = load_exact_client_contract(contract_path)
    destination = output.expanduser().resolve()
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"exact-client output already exists: {destination}")
    supplied_executables = {
        "codex-bundled": _regular_executable(codex_bundled, "bundled Codex executable"),
        "codex-path": _regular_executable(codex_path, "PATH Codex executable"),
        "claude-code": _regular_executable(claude, "Claude Code executable"),
        "grok-cli": _regular_executable(grok, "Grok CLI executable"),
    }
    sandbox_exec = _regular_executable(sandbox_exec, "sandbox-exec")
    preview = {
        "status": "planned" if not execute else "running",
        "execute": execute,
        "output": str(destination),
        "contract_sha256": contract.sha256,
        "clients": list(EXACT_CLIENT_IDS),
        "source_data": "public_synthetic_only",
        "external_model_requests": False,
    }
    if not execute:
        return preview
    if sandbox_exec.resolve() != Path("/usr/bin/sandbox-exec").resolve():
        raise ValueError("exact-client execution requires /usr/bin/sandbox-exec")
    repository = Path(__file__).resolve().parents[2]
    resolved_revision = _resolve_revision(repository, revision)
    revision_tree = _assert_checkout_at_revision(repository, resolved_revision)
    _assert_contract_at_revision(contract, repository, resolved_revision)
    harness_files = _revision_file_hashes(repository, resolved_revision)
    initial_identities = {
        client.client_id: executable_identity(supplied_executables[client.client_id], client)
        for client in contract.clients
    }
    if os.path.samefile(
        _native_payload_path(supplied_executables["codex-bundled"], contract.clients[0]),
        _native_payload_path(supplied_executables["codex-path"], contract.clients[1]),
    ):
        raise RuntimeError("bundled and PATH Codex must be distinct installed clients")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    publication = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.running-", dir=destination.parent)
    )
    working = Path(tempfile.mkdtemp(prefix="cam-exact-clients-", dir="/private/tmp"))
    ledger_working = Path(tempfile.mkdtemp(prefix="cam-exact-ledger-", dir="/private/tmp"))
    try:
        ledger_root, ledger_probe, event_id, fixture_identity = _build_fixture_ledger(
            contract, ledger_working
        )
        before = ledger_tree_snapshot(ledger_root)
        execution_paths = tuple(
            _client_execution_path(supplied_executables[client.client_id], client)
            for client in contract.clients
        )
        executables = (*supplied_executables.values(), *execution_paths, sandbox_exec)
        real_home = _system_home()
        context = LoopbackContext(contract, event_id)
        with LoopbackServer(context) as server, LoopbackServer(context) as denied_server:
            profile = build_sandbox_profile(
                real_home=real_home,
                repository=repository,
                working_root=working,
                ledger_root=ledger_root,
                loopback_port=server.port,
                executables=executables,
            )
            preflight_home = working / "preflight-home"
            preflight_tmp = working / "preflight-tmp"
            preflight_home.mkdir(mode=0o700)
            preflight_tmp.mkdir(mode=0o700)
            preflight_env = _base_environment(
                preflight_home, preflight_tmp, Path("/usr/bin/python3")
            )
            sandbox = run_sandbox_preflight(
                sandbox_exec=sandbox_exec,
                profile=profile,
                working_root=working,
                port=server.port,
                denied_loopback_port=denied_server.port,
                ledger_probe=ledger_probe,
                real_home=real_home,
                env=preflight_env,
            )
            rows: list[dict[str, Any]] = []
            for client in contract.clients:
                client_root = working / "clients" / client.client_id
                client_root.mkdir(mode=0o700, parents=True, exist_ok=False)
                if client.family == "codex":
                    runner = _run_codex_client
                elif client.family == "claude_code":
                    runner = _run_claude_client
                elif client.family == "grok_cli":
                    runner = _run_grok_client
                else:
                    raise RuntimeError(f"unsupported exact-client family: {client.family}")
                rows.append(
                    runner(
                        client=client,
                        executable=supplied_executables[client.client_id],
                        sandbox_exec=sandbox_exec,
                        profile=profile,
                        client_root=client_root,
                        repository=repository,
                        ledger_root=ledger_root,
                        port=server.port,
                        context=context,
                        sandbox=sandbox,
                    )
                )
        if {
            client.client_id: executable_identity(supplied_executables[client.client_id], client)
            for client in contract.clients
        } != initial_identities:
            raise RuntimeError("exact-client executable identities changed during evaluation")
        if _assert_checkout_at_revision(repository, resolved_revision) != revision_tree:
            raise RuntimeError("exact-client checkout changed during evaluation")
        after = ledger_tree_snapshot(ledger_root)
        if before != after:
            raise RuntimeError("exact-client evaluation mutated the read-only ledger")
        write_json(publication / "ledger-before.json", {"entries": before})
        write_json(publication / "ledger-after.json", {"entries": after})
        write_jsonl(publication / "clients.jsonl", rows)
        write_json(publication / "sandbox.json", sandbox)
        config = {
            "format_version": EXACT_CLIENT_FORMAT_VERSION,
            "contract_sha256": contract.sha256,
            "revision": resolved_revision,
            "revision_tree": revision_tree,
            "checkout_bound": True,
            "harness_files": harness_files,
            "fixture": fixture_identity,
            "client_ids": list(EXACT_CLIENT_IDS),
            "expected_tools": list(EXACT_CLIENT_TOOLS),
            "expected_final_sha256": _sha256_text(EXACT_CLIENT_FINAL_MARKER),
            "source_data": "public_synthetic_only",
            "model_transport": "deterministic_loopback_protocol_stub",
            "external_model_requests": False,
            "real_account_credentials_used": False,
            "exact_process_output_persisted": False,
            "verification_scope": "revision_bound_consistency_and_live_client_identity",
            "cryptographic_execution_attestation": False,
        }
        write_json(publication / "config.json", config)
        metrics = {
            "status": "passed",
            "client_count": len(rows),
            "passed_clients": sum(row["status"] == "passed" for row in rows),
            "total_elapsed_ms": round(sum(cast(float, row["elapsed_ms"]) for row in rows), 3),
            "mcp_tool_completions": sum(
                len(cast(dict[str, Any], row["trace"])["completed_tools"]) for row in rows
            ),
            "ledger_entry_count": len(before),
            "ledger_unchanged": before == after,
        }
        write_json(publication / "metrics.json", metrics)
        (publication / "report.md").write_text(
            "# Exact Client Evaluation\n\n"
            "Status: passed\n\n"
            "Four exact installed client launchers crossed their native model protocols and "
            "read-only stdio MCP boundary under an offline macOS sandbox. The immutable result "
            "contains only versions, hashes, counts, timings, protocol verdicts, and synthetic "
            "fixture identifiers. Raw process output and retrieved text were not persisted.\n",
            encoding="utf-8",
        )
        manifest = {
            "format_version": EXACT_CLIENT_FORMAT_VERSION,
            "run_id": destination.name,
            "created_at": _now(),
            "publication_id": str(uuid.uuid4()),
            "status": "passed",
            "result_kind": "exact_client_matrix",
            "revision": resolved_revision,
            "config_sha256": sha256_file(publication / "config.json"),
            "files": file_entries(publication, exclude={"manifest.json"}),
        }
        write_json(publication / "manifest.json", manifest)
        set_read_only_tree(publication)
        manifest_sha256 = sha256_file(publication / "manifest.json")
        verification = cast(
            dict[str, Any],
            _publish_verified_directory(
                publication,
                destination,
                lambda candidate: verify_exact_client_evaluation(
                    candidate,
                    expected_manifest_sha256=manifest_sha256,
                    contract_path=contract.path,
                    codex_bundled=supplied_executables["codex-bundled"],
                    codex_path=supplied_executables["codex-path"],
                    claude=supplied_executables["claude-code"],
                    grok=supplied_executables["grok-cli"],
                    expected_run_id=destination.name,
                ),
            ),
        )
        verification["run"] = str(destination)
        return {
            **preview,
            "status": "passed",
            "manifest_sha256": manifest_sha256,
            "metrics": metrics,
            "verification": verification,
        }
    except BaseException:
        if publication.exists():
            _make_writable(publication)
            shutil.rmtree(publication)
        raise
    finally:
        if working.exists():
            _make_writable(working)
            shutil.rmtree(working)
        if ledger_working.exists():
            _make_writable(ledger_working)
            shutil.rmtree(ledger_working)


def _verify_read_only_tree(root: Path) -> None:
    if root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o500:
        raise ValueError("exact-client run root is not an immutable regular directory")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("exact-client run must not contain symlinks")
        expected_mode = 0o500 if path.is_dir() else 0o400
        if stat.S_IMODE(path.stat().st_mode) != expected_mode:
            raise ValueError(f"exact-client run entry has an invalid mode: {path.name}")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            raw: object = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError(f"exact-client JSONL row {line_number} is not an object")
            rows.append(cast(dict[str, Any], raw))
    return rows


def _verify_sha256(value: object, label: str) -> str:
    normalized = _require_string(value, label)
    if SHA256_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} is not a SHA-256 digest")
    return normalized


def _verify_snapshot(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    snapshot = cast(dict[str, Any], value)
    _require_exact_fields(snapshot, {"entries"}, label)
    raw_entries = snapshot.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ValueError(f"{label} entries must be a non-empty list")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in cast(list[object], raw_entries):
        if not isinstance(raw, dict):
            raise ValueError(f"{label} entry must be an object")
        entry = cast(dict[str, Any], raw)
        _require_exact_fields(
            entry,
            {"path", "kind", "mode", "bytes", "mtime_ns", "sha256"},
            f"{label} entry",
        )
        path = _require_string(entry.get("path"), f"{label} path")
        if path in seen or path.startswith("/") or ".." in Path(path).parts:
            raise ValueError(f"{label} contains an invalid path")
        seen.add(path)
        kind = _require_string(entry.get("kind"), f"{label} kind")
        mode = _require_int(entry.get("mode"), f"{label} mode")
        _require_int(entry.get("bytes"), f"{label} bytes")
        _require_int(entry.get("mtime_ns"), f"{label} mtime")
        digest = entry.get("sha256")
        if kind == "file":
            _verify_sha256(digest, f"{label} file digest")
            if mode != 0o400:
                raise ValueError(f"{label} file is not read-only")
        elif kind == "directory":
            if digest is not None or mode != 0o500:
                raise ValueError(f"{label} directory is invalid")
        else:
            raise ValueError(f"{label} entry kind is invalid")
        if path.endswith("-wal") or path.endswith("-shm"):
            raise ValueError(f"{label} contains a SQLite sidecar")
        entries.append(entry)
    return entries


def _verify_sandbox(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("exact-client sandbox evidence must be an object")
    sandbox = cast(dict[str, Any], value)
    expected = {
        "sandbox_enforced",
        "command_executed",
        "profile_sha256",
        "real_home_read_denied",
        "loopback_allowed",
        "other_loopback_port_denied",
        "non_loopback_denied",
        "outside_write_denied",
        "ledger_write_denied",
        "working_write_allowed",
    }
    _require_exact_fields(sandbox, expected, "exact-client sandbox evidence")
    _verify_sha256(sandbox.get("profile_sha256"), "sandbox profile digest")
    for key in expected - {"profile_sha256"}:
        if not _require_bool(sandbox.get(key), f"sandbox {key}"):
            raise ValueError(f"sandbox check did not pass: {key}")
    return sandbox


def _verify_executable_identity(
    value: object,
    expected: ExactClientSpec,
    observed: dict[str, Any],
) -> None:
    if not isinstance(value, dict):
        raise ValueError("exact-client executable identity is invalid")
    identity = cast(dict[str, Any], value)
    _require_exact_fields(
        identity,
        {
            "install_kind",
            "supplied_path_sha256",
            "resolved_path_sha256",
            "execution_path_sha256",
            "package_name",
            "package_version",
            "entries",
        },
        "executable identity",
    )
    if identity.get("install_kind") != expected.install_kind:
        raise ValueError("exact-client installation kind is invalid")
    _verify_sha256(identity.get("supplied_path_sha256"), "supplied executable path digest")
    _verify_sha256(identity.get("resolved_path_sha256"), "resolved executable path digest")
    _verify_sha256(identity.get("execution_path_sha256"), "execution executable path digest")
    package_name = identity.get("package_name")
    package_version = identity.get("package_version")
    if expected.package_name is None:
        if package_name is not None or package_version is not None:
            raise ValueError("native exact client unexpectedly recorded package metadata")
    elif package_name != expected.package_name:
        raise ValueError("exact-client package identity is invalid")
    else:
        _require_string(package_version, "exact-client package version")
    raw_entries = identity.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ValueError("exact-client executable identity entries are invalid")
    native_payloads = 0
    for raw in cast(list[object], raw_entries):
        if not isinstance(raw, dict):
            raise ValueError("exact-client executable identity entry is invalid")
        entry = cast(dict[str, Any], raw)
        _require_exact_fields(
            entry,
            {"role", "bytes", "sha256", "code_identifier", "team_id"},
            "executable identity entry",
        )
        role = _require_string(entry.get("role"), "executable identity role")
        if role not in {"launcher", "native_payload"}:
            raise ValueError("exact-client executable identity role is invalid")
        native_payloads += role == "native_payload"
        if _require_int(entry.get("bytes"), "executable bytes") <= 0:
            raise ValueError("exact-client executable is empty")
        _verify_sha256(entry.get("sha256"), "executable digest")
        if role == "native_payload":
            if (
                entry.get("code_identifier") != expected.code_identifier
                or entry.get("team_id") != expected.team_id
            ):
                raise ValueError("exact-client vendor signing identity is invalid")
        elif entry.get("code_identifier") is not None or entry.get("team_id") is not None:
            raise ValueError("unsigned launcher recorded a signing identity")
    if native_payloads != 1:
        raise ValueError("exact-client identity must bind one native payload")
    if identity != observed:
        raise ValueError("exact-client executable no longer matches the recorded identity")


def _verify_protocol_events(trace: dict[str, Any], expected: ExactClientSpec) -> None:
    raw_events = trace.get("protocol_events")
    if not isinstance(raw_events, list) or not raw_events:
        raise ValueError("exact-client protocol event evidence is invalid")
    events = cast(list[object], raw_events)
    issued_tools: list[str] = []
    completed_tools: list[str] = []
    model_ids: set[str] = set()
    endpoints: Counter[str] = Counter()
    search_tool_calls = 0
    title_requests = 0
    final_states: list[bool] = []
    for sequence, raw in enumerate(events, start=1):
        if not isinstance(raw, dict):
            raise ValueError("exact-client protocol event must be an object")
        event = cast(dict[str, Any], raw)
        _require_exact_fields(
            event,
            {
                "sequence",
                "endpoint",
                "model_id",
                "request_sha256",
                "response_sha256",
                "issued_tool",
                "completed_tool",
                "search_tool_delta",
                "title_request_delta",
                "final_issued",
            },
            "exact-client protocol event",
        )
        if _require_int(event.get("sequence"), "protocol event sequence") != sequence:
            raise ValueError("exact-client protocol event sequence is invalid")
        endpoint = _require_string(event.get("endpoint"), "protocol endpoint")
        endpoints[endpoint] += 1
        model_id = _require_string(event.get("model_id"), "protocol model id")
        model_ids.add(model_id)
        _verify_sha256(event.get("request_sha256"), "protocol request digest")
        _verify_sha256(event.get("response_sha256"), "protocol response digest")
        for field_name, target in (
            ("issued_tool", issued_tools),
            ("completed_tool", completed_tools),
        ):
            tool = event.get(field_name)
            if tool is not None:
                target.append(_require_string(tool, f"protocol {field_name}"))
        search_delta = _require_int(event.get("search_tool_delta"), "search tool delta")
        title_delta = _require_int(event.get("title_request_delta"), "title request delta")
        if search_delta not in {0, 1} or title_delta not in {0, 1}:
            raise ValueError("exact-client protocol counter delta is invalid")
        search_tool_calls += search_delta
        title_requests += title_delta
        final_states.append(_require_bool(event.get("final_issued"), "protocol final state"))
    if final_states != [False] * (len(final_states) - 1) + [True]:
        raise ValueError("exact-client protocol final-state sequence is invalid")
    derived = {
        "model_requests": len(events),
        "title_requests": title_requests,
        "model_ids": sorted(model_ids),
        "endpoint_counts": dict(sorted(endpoints.items())),
        "issued_tools": issued_tools,
        "completed_tools": completed_tools,
        "search_tool_calls": search_tool_calls,
        "final_issued": True,
    }
    for key, value in derived.items():
        if trace.get(key) != value:
            raise ValueError(f"exact-client trace {key} is not backed by protocol events")
    expected_endpoint = {
        "codex": "/v1/responses",
        "claude_code": "/v1/messages",
        "grok_cli": "/chat/completions",
    }[expected.family]
    if set(endpoints) != {expected_endpoint}:
        raise ValueError("exact-client trace used an unexpected model endpoint")


def _verify_client_row(
    row: dict[str, Any],
    expected: ExactClientSpec,
    sandbox: dict[str, Any],
    observed_identity: dict[str, Any],
) -> None:
    _require_exact_fields(
        row,
        {
            "client_id",
            "family",
            "protocol",
            "status",
            "version",
            "version_sha256",
            "executable_identity",
            "exit_code",
            "elapsed_ms",
            "stdout_bytes",
            "stdout_sha256",
            "stderr_bytes",
            "stderr_sha256",
            "exact_output_persisted",
            "final_marker_seen",
            "trace",
            "sandbox",
        },
        "exact-client result",
    )
    if (
        row.get("client_id") != expected.client_id
        or row.get("family") != expected.family
        or row.get("protocol") != expected.protocol
        or row.get("status") != "passed"
    ):
        raise ValueError("exact-client result identity or status is invalid")
    version = _require_string(row.get("version"), "exact-client version")
    if _verify_sha256(row.get("version_sha256"), "version digest") != _sha256_text(version):
        raise ValueError("exact-client version digest does not match")
    if _require_int(row.get("exit_code"), "exact-client exit code") != 0:
        raise ValueError("exact-client process did not exit successfully")
    elapsed = row.get("elapsed_ms")
    if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool) or elapsed < 0:
        raise ValueError("exact-client elapsed time is invalid")
    for prefix in ("stdout", "stderr"):
        size = _require_int(row.get(f"{prefix}_bytes"), f"{prefix} bytes")
        if size < 0 or size > MAX_PROCESS_OUTPUT_BYTES:
            raise ValueError(f"exact-client {prefix} size is invalid")
        _verify_sha256(row.get(f"{prefix}_sha256"), f"{prefix} digest")
    if _require_bool(row.get("exact_output_persisted"), "exact output persisted"):
        raise ValueError("exact-client raw process output must not be persisted")
    if not _require_bool(row.get("final_marker_seen"), "final marker seen"):
        raise ValueError("exact-client final marker was not seen")
    _verify_executable_identity(row.get("executable_identity"), expected, observed_identity)
    if row.get("sandbox") != sandbox:
        raise ValueError("exact-client sandbox evidence is inconsistent")
    raw_trace = row.get("trace")
    if not isinstance(raw_trace, dict):
        raise ValueError("exact-client trace must be an object")
    trace = cast(dict[str, Any], raw_trace)
    _require_exact_fields(
        trace,
        {
            "model_requests",
            "title_requests",
            "model_ids",
            "endpoint_counts",
            "issued_tools",
            "completed_tools",
            "search_tool_calls",
            "final_issued",
            "protocol_events",
        },
        "exact-client trace",
    )
    _verify_protocol_events(trace, expected)
    if trace.get("issued_tools") != list(EXACT_CLIENT_TOOLS):
        raise ValueError("exact-client issued tool sequence is invalid")
    if trace.get("completed_tools") != list(EXACT_CLIENT_TOOLS):
        raise ValueError("exact-client completed tool sequence is invalid")
    if not _require_bool(trace.get("final_issued"), "trace final issued"):
        raise ValueError("exact-client trace did not reach the final response")
    if _require_int(trace.get("model_requests"), "model request count") < 4:
        raise ValueError("exact-client model request count is too small")
    expected_search_calls = 3 if expected.family == "grok_cli" else 0
    if (
        _require_int(trace.get("search_tool_calls"), "search tool call count")
        != expected_search_calls
    ):
        raise ValueError("exact-client search tool call count is invalid")
    title_requests = _require_int(trace.get("title_requests"), "title request count")
    if (expected.family == "grok_cli" and title_requests < 1) or (
        expected.family != "grok_cli" and title_requests != 0
    ):
        raise ValueError("exact-client title request count is invalid")
    model_ids = trace.get("model_ids")
    endpoints = trace.get("endpoint_counts")
    if (
        not isinstance(model_ids, list)
        or not model_ids
        or not all(isinstance(item, str) for item in cast(list[object], model_ids))
    ):
        raise ValueError("exact-client model identifiers are invalid")
    if not isinstance(endpoints, dict) or not endpoints:
        raise ValueError("exact-client endpoint counts are invalid")
    endpoint_counts = cast(dict[object, object], endpoints)
    if any(
        not isinstance(key, str)
        or not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
        for key, value in endpoint_counts.items()
    ):
        raise ValueError("exact-client endpoint count values are invalid")


def verify_exact_client_evaluation(
    run: Path,
    *,
    expected_manifest_sha256: str,
    contract_path: Path,
    codex_bundled: Path,
    codex_path: Path,
    claude: Path,
    grok: Path,
    expected_run_id: str | None = None,
) -> dict[str, Any]:
    supplied = run.expanduser()
    if supplied.is_symlink():
        raise ValueError("exact-client run must not be a symlink")
    root = supplied.resolve()
    _verify_read_only_tree(root)
    expected_digest = _verify_sha256(expected_manifest_sha256, "manifest digest")
    if sha256_file(root / "manifest.json") != expected_digest:
        raise ValueError("exact-client manifest digest does not match")
    contract = load_exact_client_contract(contract_path)
    supplied_executables = {
        "codex-bundled": _regular_executable(codex_bundled, "bundled Codex executable"),
        "codex-path": _regular_executable(codex_path, "PATH Codex executable"),
        "claude-code": _regular_executable(claude, "Claude Code executable"),
        "grok-cli": _regular_executable(grok, "Grok CLI executable"),
    }
    observed_identities = {
        client.client_id: executable_identity(supplied_executables[client.client_id], client)
        for client in contract.clients
    }
    if os.path.samefile(
        _native_payload_path(supplied_executables["codex-bundled"], contract.clients[0]),
        _native_payload_path(supplied_executables["codex-path"], contract.clients[1]),
    ):
        raise ValueError("bundled and PATH Codex must be distinct installed clients")
    manifest = _load_json_object(root / "manifest.json", "exact-client manifest")
    _require_exact_fields(
        manifest,
        {
            "format_version",
            "run_id",
            "created_at",
            "publication_id",
            "status",
            "result_kind",
            "revision",
            "config_sha256",
            "files",
        },
        "exact-client manifest",
    )
    run_id = expected_run_id if expected_run_id is not None else root.name
    if (
        manifest.get("format_version") != EXACT_CLIENT_FORMAT_VERSION
        or manifest.get("run_id") != run_id
        or manifest.get("status") != "passed"
        or manifest.get("result_kind") != "exact_client_matrix"
    ):
        raise ValueError("exact-client manifest identity is invalid")
    _require_string(manifest.get("created_at"), "manifest timestamp")
    try:
        uuid.UUID(_require_string(manifest.get("publication_id"), "publication id"))
    except ValueError as error:
        raise ValueError("exact-client publication id is invalid") from error
    revision = _require_string(manifest.get("revision"), "manifest revision")
    if GIT_OBJECT_PATTERN.fullmatch(revision) is None:
        raise ValueError("exact-client manifest revision is invalid")
    repository = Path(__file__).resolve().parents[2]
    revision_tree = _assert_checkout_at_revision(repository, revision)
    _assert_contract_at_revision(contract, repository, revision)
    config_digest = _verify_sha256(manifest.get("config_sha256"), "config digest")
    if sha256_file(root / "config.json") != config_digest:
        raise ValueError("exact-client config digest does not match")
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise ValueError("exact-client manifest files must be a list")
    if file_entries(root, exclude={"manifest.json"}) != raw_files:
        raise ValueError("exact-client file manifest does not match")
    config = _load_json_object(root / "config.json", "exact-client config")
    _require_exact_fields(
        config,
        {
            "format_version",
            "contract_sha256",
            "revision",
            "revision_tree",
            "checkout_bound",
            "harness_files",
            "fixture",
            "client_ids",
            "expected_tools",
            "expected_final_sha256",
            "source_data",
            "model_transport",
            "external_model_requests",
            "real_account_credentials_used",
            "exact_process_output_persisted",
            "verification_scope",
            "cryptographic_execution_attestation",
        },
        "exact-client config",
    )
    if (
        config.get("format_version") != EXACT_CLIENT_FORMAT_VERSION
        or config.get("contract_sha256") != contract.sha256
        or config.get("revision") != revision
        or config.get("revision_tree") != revision_tree
        or config.get("checkout_bound") is not True
        or config.get("client_ids") != list(EXACT_CLIENT_IDS)
        or config.get("expected_tools") != list(EXACT_CLIENT_TOOLS)
        or config.get("expected_final_sha256") != _sha256_text(EXACT_CLIENT_FINAL_MARKER)
        or config.get("source_data") != "public_synthetic_only"
        or config.get("model_transport") != "deterministic_loopback_protocol_stub"
        or config.get("external_model_requests") is not False
        or config.get("real_account_credentials_used") is not False
        or config.get("exact_process_output_persisted") is not False
        or config.get("verification_scope") != "revision_bound_consistency_and_live_client_identity"
        or config.get("cryptographic_execution_attestation") is not False
    ):
        raise ValueError("exact-client config contract is invalid")
    raw_harness = config.get("harness_files")
    if not isinstance(raw_harness, dict):
        raise ValueError("exact-client harness file map is invalid")
    harness = cast(dict[str, Any], raw_harness)
    if set(harness) != set(EXACT_CLIENT_HARNESS_PATHS):
        raise ValueError("exact-client harness file set is invalid")
    recorded_hashes = {
        path: _verify_sha256(harness[path], f"harness digest for {path}")
        for path in EXACT_CLIENT_HARNESS_PATHS
    }
    if _revision_file_hashes(repository, revision) != recorded_hashes:
        raise ValueError("exact-client harness revision does not match")
    fixture = config.get("fixture")
    if not isinstance(fixture, dict):
        raise ValueError("exact-client fixture identity is invalid")
    _require_exact_fields(
        cast(dict[str, Any], fixture),
        {"source_sha256", "event_id_sha256", "query_sha256", "canary_sha256"},
        "exact-client fixture identity",
    )
    fixture_identity = cast(dict[str, Any], fixture)
    for key, value in fixture_identity.items():
        _verify_sha256(value, f"fixture {key}")
    expected_fixture_hashes = {
        "source_sha256": _sha256_bytes(_fixture_source_bytes(contract)),
        "query_sha256": _sha256_text(cast(str, contract.fixture["query"])),
        "canary_sha256": _sha256_text(cast(str, contract.fixture["canary"])),
    }
    if any(fixture_identity[key] != value for key, value in expected_fixture_hashes.items()):
        raise ValueError("exact-client fixture identity does not match the contract")
    before = _verify_snapshot(
        _load_json_object(root / "ledger-before.json", "ledger-before snapshot"),
        "ledger-before snapshot",
    )
    after = _verify_snapshot(
        _load_json_object(root / "ledger-after.json", "ledger-after snapshot"),
        "ledger-after snapshot",
    )
    if before != after:
        raise ValueError("exact-client ledger snapshots do not match")
    sandbox = _verify_sandbox(_load_json_object(root / "sandbox.json", "sandbox evidence"))
    rows = _read_jsonl(root / "clients.jsonl")
    if len(rows) != len(contract.clients):
        raise ValueError("exact-client result count is invalid")
    for row, expected in zip(rows, contract.clients, strict=True):
        _verify_client_row(
            row,
            expected,
            sandbox,
            observed_identities[expected.client_id],
        )
    metrics = _load_json_object(root / "metrics.json", "exact-client metrics")
    _require_exact_fields(
        metrics,
        {
            "status",
            "client_count",
            "passed_clients",
            "total_elapsed_ms",
            "mcp_tool_completions",
            "ledger_entry_count",
            "ledger_unchanged",
        },
        "exact-client metrics",
    )
    if (
        metrics.get("status") != "passed"
        or metrics.get("client_count") != len(EXACT_CLIENT_IDS)
        or metrics.get("passed_clients") != len(EXACT_CLIENT_IDS)
        or metrics.get("mcp_tool_completions") != len(EXACT_CLIENT_IDS) * len(EXACT_CLIENT_TOOLS)
        or metrics.get("ledger_entry_count") != len(before)
        or metrics.get("ledger_unchanged") is not True
    ):
        raise ValueError("exact-client metrics are invalid")
    total_elapsed = metrics.get("total_elapsed_ms")
    if (
        not isinstance(total_elapsed, (int, float))
        or isinstance(total_elapsed, bool)
        or total_elapsed < 0
    ):
        raise ValueError("exact-client total elapsed time is invalid")
    forbidden = (
        cast(str, contract.fixture["canary"]).encode(),
        contract.expected_final.encode(),
    )
    for path in root.rglob("*"):
        if path.is_file() and path.name != "manifest.json":
            data = path.read_bytes()
            if any(value in data for value in forbidden):
                raise ValueError("exact-client run persisted forbidden retrieved text")
    return {
        "status": "verified",
        "run": str(root),
        "manifest_sha256": expected_digest,
        "revision": revision,
        "client_count": len(rows),
        "ledger_unchanged": True,
        "sandbox_enforced": True,
        "raw_output_persisted": False,
        "cryptographic_execution_attestation": False,
    }
