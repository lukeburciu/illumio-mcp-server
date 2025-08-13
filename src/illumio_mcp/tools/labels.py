"""Label management tools for Illumio MCP server"""
from typing import Optional
from fastmcp import FastMCP
from illumio import Label
from ..core.connection import get_pce_connection
from ..core.config import READ_ONLY
from ..core.logging import logger

def register_label_tools(mcp: FastMCP):
    """Register label-related tools with the MCP server"""
    
    @mcp.tool
    async def get_labels() -> str:
        """Get all labels from PCE"""
        logger.debug("Getting labels from PCE")
        try:
            pce = get_pce_connection()
            resp = pce.get('/labels')
            labels = resp.json()
            return f"Labels: {labels}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool
    async def get_label(
        key: Optional[str] = None,
        value: Optional[str] = None
    ) -> str:
        """Get labels from PCE filtered by key and/or value. Value parameter supports partial matches."""
        logger.debug(f"Getting labels with filters - key: '{key}', value: '{value}'")
        try:
            pce = get_pce_connection()
            # Build query parameters as key:value pairs
            params = {}
            if key is not None and value is not None:
                params[key] = value  # Use the key parameter as the actual key
            elif value is not None:
                params["value"] = value  # Default to "value" key when only value provided

            # Make API call with filters
            if params:
                labels = pce.labels.get(params=params)
            else:
                labels = pce.labels.get()
                
            # Handle different response types
            if hasattr(labels, '__len__'):
                count = len(labels)
                logger.debug(f"Successfully retrieved {count} labels")
                # Format output based on data structure
                if isinstance(labels, list):
                    return f"Found {count} labels: {labels}"
                else:
                    return f"Labels ({count}): {labels}"
            else:
                logger.debug("Successfully retrieved labels (count unknown)")
                return f"Labels: {labels}"
                
        except AttributeError as e:
            error_msg = f"PCE API method not found: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except ConnectionError as e:
            error_msg = f"PCE connection failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except Exception as e:
            error_msg = f"PCE operation failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def create_label(key: str, value: str) -> str:
        """Create a label of a specific type and value in the PCE"""
        logger.debug(f"Creating label with key: {key} and value: {value}")
        try:
            pce = get_pce_connection()
            label = Label(key=key, value=value)
            label = pce.labels.create(label)
            logger.debug(f"Label created with status: {label}")
            return f"Label created with status: {label}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def delete_label(key: str, value: str) -> str:
        """Delete a label in the PCE"""
        logger.debug(f"Deleting label with key: {key} and value: {value}")
        try:
            pce = get_pce_connection()
            label = pce.labels.get(params={"key": key, "value": value})
            if label:
                pce.labels.delete(label[0])
                return f"Label deleted with status: {label}"
            else:
                return "Label not found"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def update_label(
        key: str,
        value: str,
        new_value: Optional[str] = None,
        new_key: Optional[str] = None
    ) -> str:
        """Update a label in the PCE - change key or value"""
        logger.debug(f"Updating label with key: {key} and value: {value}")
        try:
            pce = get_pce_connection()
            labels = pce.labels.get(params={"key": key, "value": value})
            
            if not labels:
                return "Label not found"
            
            label = labels[0]
            
            if new_value:
                label.value = new_value
            if new_key:
                label.key = new_key
            
            updated_label = pce.labels.update(label)
            logger.debug(f"Label updated: {updated_label}")
            return f"Label updated successfully: {updated_label}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"