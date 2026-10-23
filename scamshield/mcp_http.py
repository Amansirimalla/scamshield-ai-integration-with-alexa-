"""Streamable HTTP entrypoint for a separately deployed MCP service."""

from __future__ import annotations

import os

from .mcp_server import mcp


def main() -> None:
    """Run the MCP server on the container's network interface."""

    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    mcp.run(transport="streamable-http", host=host, port=port)


if __name__ == "__main__":
    main()
