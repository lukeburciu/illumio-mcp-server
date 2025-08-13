"""Traffic flow analysis tools for Illumio MCP server"""
import json
import asyncio
from typing import Optional, List, Dict, Any
from fastmcp import FastMCP
from ..core.connection import get_pce_connection
from ..core.config import MCP_BUG_MAX_RESULTS
from ..core.logging import logger
from ..core.encoders import IllumioJSONEncoder
from ..utils.filters import to_dataframe, summarize_traffic

def register_traffic_tools(mcp: FastMCP):
    """Register traffic-related tools with the MCP server"""
    
    @mcp.tool
    async def get_traffic_flows(
        sources_include: Optional[List[List[Dict[str, str]]]] = None,
        sources_exclude: Optional[List[List[Dict[str, str]]]] = None,
        destinations_include: Optional[List[List[Dict[str, str]]]] = None,
        destinations_exclude: Optional[List[List[Dict[str, str]]]] = None,
        services_include: Optional[List[Dict[str, Any]]] = None,
        services_exclude: Optional[List[Dict[str, Any]]] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        policy_decisions: Optional[List[str]] = None,
        max_results: int = MCP_BUG_MAX_RESULTS
    ) -> str:
        """Get traffic flows from the PCE with advanced filtering"""
        logger.debug("Getting traffic flows from PCE")
        logger.debug(f"Filters - sources_include: {sources_include}, destinations_include: {destinations_include}")
        
        try:
            pce = get_pce_connection()
            
            # Build query parameters
            query_params = {
                "max_results": min(max_results, MCP_BUG_MAX_RESULTS)
            }
            
            # Add filters to query
            filters = {}
            if sources_include:
                filters["sources_include"] = sources_include
            if sources_exclude:
                filters["sources_exclude"] = sources_exclude
            if destinations_include:
                filters["destinations_include"] = destinations_include
            if destinations_exclude:
                filters["destinations_exclude"] = destinations_exclude
            if services_include:
                filters["services_include"] = services_include
            if services_exclude:
                filters["services_exclude"] = services_exclude
            if policy_decisions:
                filters["policy_decisions"] = policy_decisions
            
            if start_date or end_date:
                filters["timestamp_range"] = {}
                if start_date:
                    filters["timestamp_range"]["first_detected"] = start_date
                if end_date:
                    filters["timestamp_range"]["last_detected"] = end_date
            
            # Make API call
            resp = pce.post('/traffic_flows/traffic_analysis_queries', json=filters)
            
            if resp.status_code == 201:
                query_href = resp.headers.get('Location')
                
                # Poll for results
                max_attempts = 30
                for _ in range(max_attempts):
                    result_resp = pce.get(query_href)
                    if result_resp.status_code == 200:
                        result = result_resp.json()
                        if result.get('status') == 'completed':
                            flows = result.get('result', [])
                            logger.debug(f"Retrieved {len(flows)} traffic flows")
                            
                            encoder = IllumioJSONEncoder()
                            flows_json = encoder.encode(flows)
                            return f"Traffic flows: {flows_json}"
                        elif result.get('status') == 'failed':
                            return f"Query failed: {result.get('error', 'Unknown error')}"
                    
                    await asyncio.sleep(1)
                
                return "Query timeout - results not ready"
            else:
                return f"Failed to create traffic query: {resp.status_code} - {resp.text}"
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
    
    @mcp.tool
    async def get_traffic_flows_summary(
        sources_include: Optional[List[List[Dict[str, str]]]] = None,
        sources_exclude: Optional[List[List[Dict[str, str]]]] = None,
        destinations_include: Optional[List[List[Dict[str, str]]]] = None,
        destinations_exclude: Optional[List[List[Dict[str, str]]]] = None,
        services_include: Optional[List[Dict[str, Any]]] = None,
        services_exclude: Optional[List[Dict[str, Any]]] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        policy_decisions: Optional[List[str]] = None,
        max_results: int = MCP_BUG_MAX_RESULTS
    ) -> str:
        """Get summarized traffic flows from the PCE"""
        logger.debug("Getting traffic flows summary from PCE")
        
        try:
            # Get the raw traffic flows first
            flows_result = await get_traffic_flows(
                sources_include=sources_include,
                sources_exclude=sources_exclude,
                destinations_include=destinations_include,
                destinations_exclude=destinations_exclude,
                services_include=services_include,
                services_exclude=services_exclude,
                start_date=start_date,
                end_date=end_date,
                policy_decisions=policy_decisions,
                max_results=max_results
            )
            
            # Extract flows from result
            if flows_result.startswith("Error:"):
                return flows_result
            
            # Parse the flows
            flows_str = flows_result.replace("Traffic flows: ", "")
            flows = json.loads(flows_str)
            
            # Convert to DataFrame and summarize
            df = to_dataframe(flows)
            summary = summarize_traffic(df)
            
            encoder = IllumioJSONEncoder()
            summary_json = encoder.encode(summary)
            
            return f"Traffic summary: {summary_json}"
        except Exception as e:
            error_msg = f"Failed to summarize traffic: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"