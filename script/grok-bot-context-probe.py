"""Disposable native-client qualification. No ledger, credentials, files or network listener."""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations


def create_server() -> MCPServer[Any]:
    server: MCPServer[Any] = MCPServer("CAM Native Context Probe", version="1")

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=True, destructive_hint=False, open_world_hint=False
        )
    )
    def cam_context_probe(ctx: Context[Any, Any]) -> dict[str, Any]:
        """Inspect request structure only. This tool cannot search or read any real history."""
        request = ctx.request_context
        meta = request.meta or {}
        # Values and field names can both carry sensitive data; expose only aggregate types.
        kinds: dict[str, int] = {}
        for value in meta.values():
            kind = type(value).__name__
            kinds[kind] = kinds.get(kind, 0) + 1
        return {
            "format_version": 1,
            "real_history_access": False,
            "identity_authority": "not_established",
            "caller_identity_verified": False,
            "request_method": request.method,
            "metadata_field_count": len(meta),
            "metadata_value_types": kinds,
            "transport_request_present": request.request is not None,
            "protocol_version": request.protocol_version,
        }

    return server


if __name__ == "__main__":
    create_server().run(transport="stdio")
