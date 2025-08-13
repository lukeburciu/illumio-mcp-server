"""Miscellaneous tools (notes, events, services, connection check) for Illumio MCP server"""
from typing import Optional, Dict
from fastmcp import FastMCP
from ..core.connection import get_pce_connection
from ..core.config import READ_ONLY
from ..core.logging import logger
from ..core.encoders import IllumioJSONEncoder

# Store notes as a simple key-value dict to demonstrate state management
notes: Dict[str, str] = {}

def register_misc_tools(mcp: FastMCP):
    """Register miscellaneous tools with the MCP server"""
    
    @mcp.tool(enabled=not READ_ONLY)
    async def add_note(name: str, content: str) -> str:
        """Add a new note"""
        notes[name] = content
        return f"Note '{name}' added successfully"
    
    @mcp.tool
    async def check_pce_connection() -> str:
        """Check PCE connection status"""
        logger.debug("Checking PCE connection")
        try:
            pce = get_pce_connection()
            connection_status = pce.check_connection()
            logger.debug(f"PCE connection status: {connection_status}")
            return "PCE connection successful"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool
    async def get_services() -> str:
        """Get services from the PCE"""
        logger.debug("Getting services from PCE")
        try:
            pce = get_pce_connection()
            resp = pce.get('/sec_policy/draft/services')
            services = resp.json()
            
            # Custom encoding for complex objects
            encoder = IllumioJSONEncoder()
            services_json = encoder.encode(services)
            
            return f"Services: {services_json}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool
    async def get_events(
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        max_results: int = 100
    ) -> str:
        """Get events from the PCE"""
        logger.debug(f"Getting events - type: {event_type}, severity: {severity}, status: {status}")
        
        try:
            pce = get_pce_connection()
            
            params = {"max_results": max_results}
            if event_type:
                params["event_type"] = event_type
            if severity:
                params["severity"] = severity
            if status:
                params["status"] = status
            
            resp = pce.get('/events', params=params)
            events = resp.json()
            
            encoder = IllumioJSONEncoder()
            events_json = encoder.encode(events)
            
            return f"Events: {events_json}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"

def get_notes() -> Dict[str, str]:
    """Get all notes (for use in prompts)"""
    return notes