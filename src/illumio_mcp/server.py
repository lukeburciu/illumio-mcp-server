"""
Illumio MCP Server using FastMCP framework - Main entry point
"""
from fastmcp import FastMCP

# Import core modules
from .core.config import READ_ONLY
from .core.logging import logger

# Import tool registration functions
from .tools.workloads import register_workload_tools
from .tools.labels import register_label_tools
from .tools.policies import register_policy_tools
from .tools.traffic import register_traffic_tools
from .tools.misc import register_misc_tools

# Import prompt registration
from .prompts.prompts import register_prompts

# Create FastMCP server instance
mcp = FastMCP("illumio-mcp")

# Log server mode
if READ_ONLY:
    logger.info("Server running in READ-ONLY mode - all modifying operations are disabled")
else:
    logger.info("Server running in READ-WRITE mode")

# Register all tools with the MCP server
register_workload_tools(mcp)
register_label_tools(mcp)
register_policy_tools(mcp)
register_traffic_tools(mcp)
register_misc_tools(mcp)

# Register prompts
register_prompts(mcp)

# Main entry point
def main():
    """Main entry point for the MCP server"""
    logger.info("Starting Illumio MCP server with FastMCP")
    mcp.run()

if __name__ == "__main__":
    main()