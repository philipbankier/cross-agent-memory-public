from __future__ import annotations

from collections.abc import Callable
from importlib.resources import files
from typing import Any

from mcp.server.apps import Apps, ResourceCsp, ResourcePermissions
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.types import ResourcesCapability, ServerCapabilities, ToolAnnotations, ToolsCapability

MEMORY_APP_URI = "ui://cross-agent-memory/browser.html"


def refuse_unadvertised_method(method: str) -> None:
    if method in {"prompts/list", "prompts/get", "subscriptions/listen"}:
        raise MCPError(-32601, "Method not found")


def create_memory_app(read_status: Callable[[], dict[str, Any]]) -> Apps:
    app = Apps()
    html = files("cross_assistant_memory").joinpath("static/memory-app.html").read_text("utf-8")
    app.add_html_resource(
        MEMORY_APP_URI,
        html,
        name="cross-agent-memory",
        title="Cross-Agent Memory",
        csp=ResourceCsp(
            connect_domains=[], resource_domains=[], frame_domains=[], base_uri_domains=[]
        ),
        permissions=ResourcePermissions(),
    )

    @app.tool(
        resource_uri=MEMORY_APP_URI,
        visibility=["model", "app"],
        annotations=ToolAnnotations(
            read_only_hint=True, destructive_hint=False, open_world_hint=False
        ),
    )
    def memory_open() -> dict[str, Any]:
        """Open read-only memory search, exact evidence and source coverage.

        Returns the same observations as memory_status when a client cannot render the app.
        Opening the app does not capture this conversation or grant administrative access.
        """
        return read_status()

    return app


async def memory_app_discovery(
    context: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    refuse_unadvertised_method(context.method)
    # One immutable UI asset, never a URI-to-filesystem or arbitrary resource proxy.
    if context.method == "resources/read":
        params = context.params or {}
        if params.get("uri") != MEMORY_APP_URI or set(params) - {"uri", "_meta"}:
            raise MCPError(-32602, "Memory app resource request refused")
    if context.method in {"resources/list", "resources/templates/list"} and (
        set(context.params or {}) - {"_meta"}
    ):
        raise MCPError(-32602, "Memory app resource request refused")
    result = await call_next(context)
    if context.method in {"initialize", "server/discover"} and isinstance(result, dict):
        return {
            **result,
            "capabilities": ServerCapabilities(
                tools=ToolsCapability(list_changed=False),
                resources=ResourcesCapability(subscribe=False, list_changed=False),
                extensions={"io.modelcontextprotocol/ui": {}},
            ).model_dump(by_alias=True, exclude_none=True, mode="json"),
        }
    return result
