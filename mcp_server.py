#!/usr/bin/env python3
"""
Starts the monomi MCP server (the Claude app's config points at this file).

The code lives in monomi/mcp_server.py. This wrapper stays at the repo root so
existing MCP configs keep working without any change.
"""

from monomi.mcp_server import main

if __name__ == "__main__":
    main()
