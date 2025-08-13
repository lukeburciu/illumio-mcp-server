"""Workload management tools for Illumio MCP server"""
import json
from typing import Optional, List, Dict
from fastmcp import FastMCP
from illumio import Workload, Interface, Label
from ..core.connection import get_pce_connection
from ..core.config import READ_ONLY
from ..core.logging import logger
from ..core.encoders import IllumioJSONEncoder
from ..utils.filters import filter_workload_fields

def register_workload_tools(mcp: FastMCP):
    """Register workload-related tools with the MCP server"""
    
    @mcp.tool
    async def get_workloads(name: str) -> str:
        """Get workloads from the PCE"""
        logger.debug("=" * 80)
        logger.debug("GET WORKLOADS CALLED")
        logger.debug(f"Arguments received: name={name}")
        logger.debug("=" * 80)
        
        try:
            pce = get_pce_connection()
            logger.debug("Fetching workloads from PCE")
            workloads = pce.workloads.get(params={"include": "labels", "max_results": 10000})
            logger.debug(f"Successfully retrieved {len(workloads)} workloads")
            return f"Workloads: {workloads}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool
    async def get_managed_workloads_by_label(
        app: Optional[str] = None,
        env: Optional[str] = None,
        role: Optional[str] = None,
        loc: Optional[str] = None,
        max_results: int = 10000
    ) -> str:
        """Get managed workloads from the PCE filtered by label values
        
        Retrieves only managed workloads (those with an agent installed and connected).
        
        Args:
            app: Application label value to filter by
            env: Environment label value to filter by
            role: Role label value to filter by
            loc: Location label value to filter by
            max_results: Maximum number of results to return (default: 10000)
        
        Returns:
            JSON string containing filtered managed workloads
        """
        logger.debug("=" * 80)
        logger.debug("GET MANAGED WORKLOADS BY LABEL CALLED")
        logger.debug(f"Arguments received: app={app}, env={env}, role={role}, loc={loc}, max_results={max_results}")
        logger.debug("=" * 80)
        
        try:
            pce = get_pce_connection()
            logger.debug("Fetching managed workloads with label filters from PCE")
            
            # Build query parameters - include managed=true
            params = {
                "include": "labels",
                "max_results": max_results,
                "managed": "true"  # Only get managed workloads
            }
            
            # Get all labels first to find URIs for the specified values
            all_labels = pce.labels.get()
            label_uris = []
            
            # Find URIs for matching label values
            for label in all_labels:
                if hasattr(label, 'key') and hasattr(label, 'value') and hasattr(label, 'href'):
                    if (app and label.key == 'app' and label.value == app) or \
                       (env and label.key == 'env' and label.value == env) or \
                       (role and label.key == 'role' and label.value == role) or \
                       (loc and label.key == 'loc' and label.value == loc):
                        label_uris.append(label.href)
            
            # Add labels parameter as JSON string if we found matching labels
            if label_uris:
                params["labels"] = json.dumps([label_uris])
            
            workloads = pce.workloads.get(params=params)
            
            # Handle different response types
            if hasattr(workloads, '__len__'):
                count = len(workloads)
                logger.debug(f"Successfully retrieved {count} managed workloads with label filters")
            else:
                logger.debug("Successfully retrieved managed workloads with label filters (count unknown)")
            
            # Use custom encoder for proper JSON serialization first
            encoder = IllumioJSONEncoder()
            workloads_json = encoder.encode(workloads)
            
            # Parse JSON and filter fields
            workloads_data = json.loads(workloads_json)
            filtered_workloads = filter_workload_fields(workloads_data)
            
            # Re-encode filtered data
            filtered_json = json.dumps(filtered_workloads)
            
            return f"Managed Workloads: {filtered_json}"
            
        except AttributeError as e:
            error_msg = f"PCE API method not found: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except ConnectionError as e:
            error_msg = f"PCE connection failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except json.JSONDecodeError as e:
            error_msg = f"JSON parsing failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except Exception as e:
            error_msg = f"PCE operation failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool
    async def get_unmanaged_workloads_by_label(
        app: Optional[str] = None,
        env: Optional[str] = None,
        role: Optional[str] = None,
        loc: Optional[str] = None,
        max_results: int = 10000
    ) -> str:
        """Get unmanaged workloads from the PCE filtered by label values
        
        Retrieves only unmanaged workloads (those without an agent or with disconnected agents).
        
        Args:
            app: Application label value to filter by
            env: Environment label value to filter by
            role: Role label value to filter by
            loc: Location label value to filter by
            max_results: Maximum number of results to return (default: 10000)
        
        Returns:
            JSON string containing filtered unmanaged workloads
        """
        logger.debug("=" * 80)
        logger.debug("GET UNMANAGED WORKLOADS BY LABEL CALLED")
        logger.debug(f"Arguments received: app={app}, env={env}, role={role}, loc={loc}, max_results={max_results}")
        logger.debug("=" * 80)
        
        try:
            pce = get_pce_connection()
            logger.debug("Fetching unmanaged workloads with label filters from PCE")
            
            # Build query parameters - include managed=false
            params = {
                "include": "labels",
                "max_results": max_results,
                "managed": "false"  # Only get unmanaged workloads
            }
            
            # Get all labels first to find URIs for the specified values
            all_labels = pce.labels.get()
            label_uris = []
            
            # Find URIs for matching label values
            for label in all_labels:
                if hasattr(label, 'key') and hasattr(label, 'value') and hasattr(label, 'href'):
                    if (app and label.key == 'app' and label.value == app) or \
                       (env and label.key == 'env' and label.value == env) or \
                       (role and label.key == 'role' and label.value == role) or \
                       (loc and label.key == 'loc' and label.value == loc):
                        label_uris.append(label.href)
            
            # Add labels parameter as JSON string if we found matching labels
            if label_uris:
                params["labels"] = json.dumps([label_uris])
            
            workloads = pce.workloads.get(params=params)
            
            # Handle different response types
            if hasattr(workloads, '__len__'):
                count = len(workloads)
                logger.debug(f"Successfully retrieved {count} unmanaged workloads with label filters")
            else:
                logger.debug("Successfully retrieved unmanaged workloads with label filters (count unknown)")
            
            # Use custom encoder for proper JSON serialization first
            encoder = IllumioJSONEncoder()
            workloads_json = encoder.encode(workloads)
            
            # Parse JSON and filter fields
            workloads_data = json.loads(workloads_json)
            filtered_workloads = filter_workload_fields(workloads_data)
            
            # Re-encode filtered data
            filtered_json = json.dumps(filtered_workloads)
            
            return f"Unmanaged Workloads: {filtered_json}"
            
        except AttributeError as e:
            error_msg = f"PCE API method not found: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except ConnectionError as e:
            error_msg = f"PCE connection failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except json.JSONDecodeError as e:
            error_msg = f"JSON parsing failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except Exception as e:
            error_msg = f"PCE operation failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool
    async def get_workloads_by_label(
        app: Optional[str] = None,
        env: Optional[str] = None,
        role: Optional[str] = None,
        loc: Optional[str] = None,
        max_results: int = 10000
    ) -> str:
        """Get workloads from the PCE filtered by label values"""
        logger.debug("=" * 80)
        logger.debug("GET WORKLOAD BY LABEL CALLED")
        logger.debug(f"Arguments received: app={app}, env={env}, role={role}, loc={loc}, max_results={max_results}")
        logger.debug("=" * 80)
        
        try:
            pce = get_pce_connection()
            logger.debug("Fetching workloads with label filters from PCE")
            
            # Build query parameters
            params = {"include": "labels", "max_results": max_results}
            
            # Get all labels first to find URIs for the specified values
            all_labels = pce.labels.get()
            label_uris = []
            
            # Find URIs for matching label values
            for label in all_labels:
                if hasattr(label, 'key') and hasattr(label, 'value') and hasattr(label, 'href'):
                    if (app and label.key == 'app' and label.value == app) or \
                       (env and label.key == 'env' and label.value == env) or \
                       (role and label.key == 'role' and label.value == role) or \
                       (loc and label.key == 'loc' and label.value == loc):
                        label_uris.append(label.href)
            
            # Add labels parameter as JSON string if we found matching labels
            if label_uris:
                params["labels"] = json.dumps([label_uris])
            
            workloads = pce.workloads.get(params=params)
            
            # Handle different response types
            if hasattr(workloads, '__len__'):
                count = len(workloads)
                logger.debug(f"Successfully retrieved {count} workloads with label filters")
            else:
                logger.debug("Successfully retrieved workloads with label filters (count unknown)")
            
            # Use custom encoder for proper JSON serialization first
            encoder = IllumioJSONEncoder()
            workloads_json = encoder.encode(workloads)
            
            # Parse JSON and filter fields
            workloads_data = json.loads(workloads_json)
            filtered_workloads = filter_workload_fields(workloads_data)
            
            # Re-encode filtered data
            filtered_json = json.dumps(filtered_workloads)
            
            return f"Workloads: {filtered_json}"
            
        except AttributeError as e:
            error_msg = f"PCE API method not found: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except ConnectionError as e:
            error_msg = f"PCE connection failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except json.JSONDecodeError as e:
            error_msg = f"JSON parsing failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except Exception as e:
            error_msg = f"PCE operation failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def create_workload(
        name: str,
        ip_addresses: List[str],
        labels: List[Dict[str, str]] = None
    ) -> str:
        """Create an Illumio Core unmanaged workload in the PCE"""
        logger.debug(f"Creating workload with name: {name} and ip_addresses: {ip_addresses}")
        logger.debug(f"Labels: {labels}")
        
        try:
            pce = get_pce_connection()
            
            # Create interfaces
            interfaces = []
            for i, ip in enumerate(ip_addresses):
                intf = Interface(name=f"eth{i}", address=ip)
                interfaces.append(intf)
            
            # Process labels
            workload_labels = []
            if labels:
                for label in labels:
                    logger.debug(f"Label: {label}")
                    # Check if label already exists
                    label_resp = pce.labels.get(params={"key": label['key'], "value": label['value']})
                    if label_resp:
                        logger.debug(f"Label already exists: {label_resp}")
                        workload_label = label_resp[0]
                    else:
                        logger.debug(f"Label does not exist, creating: {label}")
                        new_label = Label(key=label['key'], value=label['value'])
                        workload_label = pce.labels.create(new_label)
                    
                    workload_labels.append(workload_label)
            
            logger.debug(f"Labels: {workload_labels}")
            
            workload = Workload(
                name=name,
                interfaces=interfaces,
                labels=workload_labels,
                hostname=name
            )
            status = pce.workloads.create(workload)
            logger.debug(f"Workload creation status: {status}")
            return f"Workload created with status: {status}, workload: {workload}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def update_workload(
        name: str,
        ip_addresses: List[str],
        labels: List[Dict[str, str]] = None
    ) -> str:
        """Update a workload in the PCE"""
        logger.debug(f"Updating workload with name: {name} and ip_addresses: {ip_addresses}")
        logger.debug(f"Labels: {labels}")
        
        try:
            pce = get_pce_connection()
            
            workload = pce.workloads.get(params={"name": name})
            if not workload:
                return "Workload not found"
            
            workload = workload[0]
            logger.debug(f"Workload found: {workload}")
            
            # Update interfaces
            interfaces = []
            for i, ip in enumerate(ip_addresses):
                intf = Interface(name=f"eth{i}", address=ip)
                interfaces.append(intf)
            workload.interfaces = interfaces
            
            # Update labels if provided
            if labels:
                workload_labels = []
                for label in labels:
                    label_resp = pce.labels.get(params={"key": label['key'], "value": label['value']})
                    if label_resp:
                        workload_label = label_resp[0]
                    else:
                        new_label = Label(key=label['key'], value=label['value'])
                        workload_label = pce.labels.create(new_label)
                    workload_labels.append(workload_label)
                workload.labels = workload_labels
            
            status = pce.workloads.update(workload)
            logger.debug(f"Workload update status: {status}")
            return f"Workload updated with status: {status}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def delete_workload(name: str) -> str:
        """Delete a workload from the PCE"""
        logger.debug(f"Deleting workload with name: {name}")
        try:
            pce = get_pce_connection()
            workload = pce.workloads.get(params={"name": name})
            
            if not workload:
                return "Workload not found"
            
            pce.workloads.delete(workload[0])
            return f"Workload deleted: {workload[0]}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"