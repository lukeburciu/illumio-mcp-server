from . import server
from . import server_fastmcp
import asyncio
import sys

def main():
    """Main entry point for the package - uses FastMCP by default."""
    # Use FastMCP server as the default
    server_fastmcp.main()

def main_legacy():
    """Legacy entry point using original MCP SDK."""
    asyncio.run(server.main())

# Optionally expose other important items at package level
__all__ = ['main', 'main_legacy', 'server', 'server_fastmcp']