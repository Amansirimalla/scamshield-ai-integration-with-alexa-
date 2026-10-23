"""MCP client gateway used by the FastAPI orchestration layer.

The default client connects in-process to the real ScamShield MCP server
object. This still uses the official MCP client/server protocol, rather than
calling analyzer functions directly. A deployed configuration can set
``SCAMSHIELD_MCP_URL`` to use a Streamable HTTP MCP endpoint instead.
"""

from __future__ import annotations

import os
from typing import Any


class MCPToolError(RuntimeError):
    """Raised when an MCP tool cannot be called or returns an error."""


class ScamShieldMCPClient:
    """Small async gateway around the official MCP SDK client."""

    def __init__(self, server_url: str | None = None, server: Any | None = None) -> None:
        self.server_url = server_url or os.getenv("SCAMSHIELD_MCP_URL")
        self.server = server

    async def _call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            from mcp import Client
        except ImportError as exc:
            raise MCPToolError("The MCP SDK is unavailable in this runtime.") from exc

        if self.server_url:
            target = self.server_url
        else:
            if self.server is None:
                from .mcp_server import mcp

                target = mcp
            else:
                target = self.server
        try:
            async with Client(target, raise_exceptions=True) as client:
                result = await client.call_tool(name, arguments)
        except Exception as exc:
            raise MCPToolError("The MCP tool request failed.") from exc

        structured = result.structured_content
        if not isinstance(structured, dict):
            raise MCPToolError("The MCP tool returned an invalid structured result.")
        if structured.get("ok") is not True:
            error = structured.get("error")
            message = error.get("message") if isinstance(error, dict) else "The MCP tool reported an error."
            raise MCPToolError(message)
        payload = structured.get("result")
        if not isinstance(payload, dict):
            raise MCPToolError("The MCP tool returned no structured result.")
        return payload

    async def analyze_message(self, message: str) -> dict[str, Any]:
        return await self._call("analyze_message", {"message": message})

    async def check_url_reputation(self, url: str) -> dict[str, Any]:
        return await self._call("check_url_reputation", {"url": url})
