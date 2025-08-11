from . import server

def main():
    """Main entry point for the package - uses FastMCP by default."""
    # Use FastMCP server as the default
    server.main()

# Optionally expose other important items at package level
__all__ = ['main', 'server']