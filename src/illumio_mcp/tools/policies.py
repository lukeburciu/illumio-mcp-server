"""Policy management tools (rulesets and IP lists) for Illumio MCP server"""
import json
from typing import Optional, List, Dict, Any
from fastmcp import FastMCP
from ..core.connection import get_pce_connection
from ..core.config import READ_ONLY
from ..core.logging import logger
from ..core.encoders import IllumioJSONEncoder

def register_policy_tools(mcp: FastMCP):
    """Register policy-related tools with the MCP server"""
    
    # Ruleset Tools
    @mcp.tool
    async def get_rulesets(
        name: Optional[str] = None,
        enabled: Optional[bool] = None,
        scopes: Optional[List[List[Dict[str, str]]]] = None
    ) -> str:
        """Get rulesets from the PCE"""
        logger.debug(f"Getting rulesets with filters - name: {name}, enabled: {enabled}, scopes: {scopes}")
        
        try:
            pce = get_pce_connection()
            
            # Build query parameters
            params = {}
            if name:
                params["name"] = name
            if enabled is not None:
                params["enabled"] = enabled
            if scopes:
                params["scopes"] = json.dumps(scopes)
            
            resp = pce.get('/sec_policy/active/rule_sets', params=params)
            rulesets = resp.json()
            
            encoder = IllumioJSONEncoder()
            rulesets_json = encoder.encode(rulesets)
            
            return f"Rulesets: {rulesets_json}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def create_ruleset(
        name: str,
        scopes: List[List[Dict[str, str]]],
        rules: List[Dict[str, Any]],
        enabled: bool = True,
        description: Optional[str] = None
    ) -> str:
        """Create a ruleset in the PCE"""
        logger.debug(f"Creating ruleset: {name}")
        
        try:
            pce = get_pce_connection()
            
            # Build ruleset
            ruleset_data = {
                "name": name,
                "scopes": scopes,
                "enabled": enabled,
                "rules": rules
            }
            
            if description:
                ruleset_data["description"] = description
            
            resp = pce.post('/sec_policy/draft/rule_sets', json=ruleset_data)
            
            if resp.status_code == 201:
                created_ruleset = resp.json()
                return f"Ruleset created successfully: {created_ruleset}"
            else:
                return f"Failed to create ruleset: {resp.status_code} - {resp.text}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def update_ruleset(
        href: str,
        name: Optional[str] = None,
        scopes: Optional[List[List[Dict[str, str]]]] = None,
        rules: Optional[List[Dict[str, Any]]] = None,
        enabled: Optional[bool] = None,
        description: Optional[str] = None
    ) -> str:
        """Update a ruleset in the PCE"""
        logger.debug(f"Updating ruleset: {href}")
        
        try:
            pce = get_pce_connection()
            
            # Get current ruleset
            resp = pce.get(href)
            if resp.status_code != 200:
                return f"Ruleset not found: {href}"
            
            ruleset = resp.json()
            
            # Update fields
            if name is not None:
                ruleset['name'] = name
            if scopes is not None:
                ruleset['scopes'] = scopes
            if rules is not None:
                ruleset['rules'] = rules
            if enabled is not None:
                ruleset['enabled'] = enabled
            if description is not None:
                ruleset['description'] = description
            
            # Send update
            resp = pce.put(href, json=ruleset)
            
            if resp.status_code == 200:
                updated_ruleset = resp.json()
                return f"Ruleset updated successfully: {updated_ruleset}"
            else:
                return f"Failed to update ruleset: {resp.status_code} - {resp.text}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def delete_ruleset(href: Optional[str] = None, name: Optional[str] = None) -> str:
        """Delete a ruleset from the PCE"""
        logger.debug(f"Deleting ruleset - href: {href}, name: {name}")
        
        try:
            pce = get_pce_connection()
            
            if href:
                resp = pce.delete(href)
                if resp.status_code == 204:
                    return f"Ruleset deleted successfully: {href}"
                else:
                    return f"Failed to delete ruleset: {resp.status_code} - {resp.text}"
            elif name:
                # Find ruleset by name
                resp = pce.get('/sec_policy/draft/rule_sets')
                rulesets = resp.json()
                matching = [rs for rs in rulesets if rs.get('name') == name]
                
                if not matching:
                    return f"Ruleset not found: {name}"
                
                ruleset = matching[0]
                resp = pce.delete(ruleset['href'])
                
                if resp.status_code == 204:
                    return f"Ruleset deleted successfully: {name}"
                else:
                    return f"Failed to delete ruleset: {resp.status_code} - {resp.text}"
            else:
                return "Either href or name must be provided"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    # IP List Tools
    @mcp.tool
    async def get_iplists(
        name: Optional[str] = None,
        description: Optional[str] = None,
        ip_ranges: Optional[List[Dict[str, str]]] = None,
        fqdn: Optional[str] = None
    ) -> str:
        """Get IP lists from the PCE"""
        logger.debug(f"Getting IP lists with filters - name: {name}")
        
        try:
            pce = get_pce_connection()
            resp = pce.get('/sec_policy/draft/ip_lists')
            iplists = resp.json()
            
            # Apply filters
            filtered_iplists = iplists
            if name:
                filtered_iplists = [ipl for ipl in filtered_iplists if name.lower() in ipl.get('name', '').lower()]
            if description:
                filtered_iplists = [ipl for ipl in filtered_iplists if description.lower() in ipl.get('description', '').lower()]
            
            encoder = IllumioJSONEncoder()
            iplists_json = encoder.encode(filtered_iplists)
            
            return f"IP Lists: {iplists_json}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def create_iplist(
        name: str,
        ip_ranges: Optional[List[Dict[str, str]]] = None,
        fqdn: Optional[str] = None,
        description: Optional[str] = None
    ) -> str:
        """Create an IP list in the PCE"""
        logger.debug(f"Creating IP list: {name}")
        
        try:
            pce = get_pce_connection()
            
            iplist_data = {"name": name}
            
            if ip_ranges:
                iplist_data["ip_ranges"] = ip_ranges
            if fqdn:
                iplist_data["fqdn"] = fqdn
            if description:
                iplist_data["description"] = description
            
            resp = pce.post('/sec_policy/draft/ip_lists', json=iplist_data)
            
            if resp.status_code == 201:
                created_iplist = resp.json()
                return f"IP List created successfully: {created_iplist}"
            else:
                return f"Failed to create IP list: {resp.status_code} - {resp.text}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def update_iplist(
        href: str,
        name: Optional[str] = None,
        ip_ranges: Optional[List[Dict[str, str]]] = None,
        fqdn: Optional[str] = None,
        description: Optional[str] = None
    ) -> str:
        """Update an IP list in the PCE"""
        logger.debug(f"Updating IP list: {href}")
        
        try:
            pce = get_pce_connection()
            
            # Get current IP list
            resp = pce.get(href)
            if resp.status_code != 200:
                return f"IP list not found: {href}"
            
            iplist = resp.json()
            
            # Update fields
            if name is not None:
                iplist['name'] = name
            if ip_ranges is not None:
                iplist['ip_ranges'] = ip_ranges
            if fqdn is not None:
                iplist['fqdn'] = fqdn
            if description is not None:
                iplist['description'] = description
            
            # Send update
            resp = pce.put(href, json=iplist)
            
            if resp.status_code == 200:
                updated_iplist = resp.json()
                return f"IP List updated successfully: {updated_iplist}"
            else:
                return f"Failed to update IP list: {resp.status_code} - {resp.text}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool(enabled=not READ_ONLY)
    async def delete_iplist(href: str) -> str:
        """Delete an IP list from the PCE"""
        logger.debug(f"Deleting IP list: {href}")
        
        try:
            pce = get_pce_connection()
            
            resp = pce.delete(href)
            if resp.status_code == 204:
                return f"IP List deleted successfully: {href}"
            else:
                return f"Failed to delete IP list: {resp.status_code} - {resp.text}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"