from . import server_fastmcp

def main():
    """Main entry point for the package - uses FastMCP by default."""
    # Use FastMCP server as the default
    server_fastmcp.main()

# Optionally expose other important items at package level
__all__ = ['main', 'server_fastmcp']