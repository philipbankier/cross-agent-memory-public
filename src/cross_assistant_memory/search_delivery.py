from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from cross_assistant_memory.retrieval import MAX_WORKSET_RESULTS

MAX_SEARCH_RESPONSE_BYTES = 512 * 1024
SEARCH_CHANGED_MESSAGE = "Search results changed; restart from the first page."
SEARCH_TOO_LARGE_MESSAGE = "Search response cannot fit; narrow the query or use an uncapped client."


class SearchChangedError(ValueError):
    pass


class SearchTooLargeError(ValueError):
    pass


class SearchPageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_offset: Annotated[StrictInt, Field(ge=0, le=MAX_WORKSET_RESULTS)] = 0
    expected_search_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None


def deliver_search(
    workset: dict[str, Any],
    search_arguments: dict[str, Any],
    request: SearchPageRequest | None = None,
    *,
    text_max_bytes: int | None = None,
    continuation_arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Page an authorized workset; omit optional context only when a single hit cannot fit."""
    request = request or SearchPageRequest()
    binding = hashlib.sha256(
        json.dumps(
            {"version": 1, "arguments": search_arguments, "workset": workset},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if request.result_offset and request.expected_search_sha256 is None:
        raise ValueError("search continuation requires its version digest")
    if request.expected_search_sha256 is not None and request.expected_search_sha256 != binding:
        raise SearchChangedError("search changed; restart from the first page")

    items = workset["results"]
    offset = request.result_offset
    if offset and offset >= len(items):
        raise ValueError("search offset is outside the workset")
    if not offset and (text_max_bytes is None or _fits(workset, text_max_bytes)):
        return workset

    for end in range(len(items), offset, -1):
        result = {
            "search_page": {
                "version": 1,
                "search_sha256": binding,
                "offset_unit": "results",
                "result_offset": offset,
                "returned_count": end - offset,
                "total_results": len(items),
                "next_result_offset": end if end < len(items) else None,
                "complete": offset == 0 and end == len(items),
                "selection_scope": "whole_workset",
            },
            **workset,
            "results": items[offset:end],
        }
        if continuation_arguments is not None and end < len(items):
            result = {
                "search_page": result["search_page"],
                "next_search_request": {
                    **continuation_arguments,
                    "page": {"result_offset": end, "expected_search_sha256": binding},
                },
                **result,
            }
        if _fits(result, text_max_bytes):
            return result
        if end == offset + 1 and "next_search_request" in result:
            without_helper = {
                key: value for key, value in result.items() if key != "next_search_request"
            }
            if _fits(without_helper, text_max_bytes):
                return without_helper
        if end == offset + 1 and "conversation_context" in items[offset]:
            # Preserve the matching hit and explicitly disclose the omitted adjunct.
            result["results"] = [
                {
                    **items[offset],
                    "conversation_context": {
                        **items[offset]["conversation_context"],
                        "results": [],
                        "history_complete": False,
                        "omitted_reason": "response_limit_fetch_omitted_event_ids",
                        "omitted_event_ids": [
                            row["event_id"]
                            for row in items[offset]["conversation_context"]["results"]
                        ],
                        "omitted_count": len(items[offset]["conversation_context"]["results"]),
                    },
                }
            ]
            if len(items) == 1:
                result.pop("search_page")
            if _fits(result, text_max_bytes):
                return result
            result.pop("next_search_request", None)
            if _fits(result, text_max_bytes):
                return result
    raise SearchTooLargeError("search metadata or one result exceeds the bounded response limit")


def _fits(value: dict[str, Any], text_max_bytes: int | None) -> bool:
    text = json.dumps(value, indent=2)
    envelope = CallToolResult(
        content=[TextContent(type="text", text=text)], structured_content=value
    ).model_dump(mode="json", by_alias=True)
    limit = MAX_SEARCH_RESPONSE_BYTES
    if text_max_bytes is not None:
        limit = min(limit, text_max_bytes)
    return len(json.dumps(envelope).encode()) <= limit
