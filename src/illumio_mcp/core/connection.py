"""PCE connection management for Illumio MCP server"""
from illumio import PolicyComputeEngine
from .config import PCE_HOST, PCE_PORT, PCE_ORG_ID, API_KEY, API_SECRET

def get_pce_connection():
    """Get a connected PCE instance"""
    pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
    pce.set_credentials(API_KEY, API_SECRET)
    return pce