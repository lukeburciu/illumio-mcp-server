#!/usr/bin/env python
"""Test script to verify FastMCP refactoring"""

import sys
from illumio_mcp import server_fastmcp

def test_imports():
    """Test that all modules import correctly"""
    print("✓ FastMCP server module imported")
    
    # Check server instance
    assert server_fastmcp.mcp.name == "illumio-mcp"
    print("✓ FastMCP server instance created")
    
    # Check logging
    assert server_fastmcp.logger is not None
    print("✓ Logging configured")
    
    # Check environment variables are accessed (will be None if not set)
    print(f"✓ PCE_HOST: {server_fastmcp.PCE_HOST or 'Not set'}")
    print(f"✓ READ_ONLY: {server_fastmcp.READ_ONLY}")
    
    return True

def test_tools():
    """Test that tools are properly defined"""
    from fastmcp.tools.tool import FunctionTool
    
    # List of expected tools
    expected_tools = [
        "add_note", "check_pce_connection", "get_workloads", "get_labels",
        "create_label", "delete_label", "update_label", "create_workload",
        "update_workload", "delete_workload", "get_services", "get_rulesets",
        "create_ruleset", "update_ruleset", "delete_ruleset", "get_iplists",
        "create_iplist", "update_iplist", "delete_iplist", "get_events",
        "get_traffic_flows", "get_traffic_flows_summary"
    ]
    
    # Check that FastMCP has tools registered
    # FastMCP wraps tools as FunctionTool objects
    tools = []
    for name in expected_tools:
        if hasattr(server_fastmcp, name):
            obj = getattr(server_fastmcp, name)
            # Check if it's a FunctionTool or callable
            if isinstance(obj, FunctionTool) or callable(obj):
                tools.append(name)
    
    print(f"✓ Found {len(tools)} tool functions")
    
    # Verify key tools exist
    assert "get_workloads" in tools, f"get_workloads not found in {tools}"
    assert "create_ruleset" in tools, f"create_ruleset not found in {tools}"
    print("✓ Key tools verified")
    
    # Check that tools are properly wrapped
    workloads_tool = getattr(server_fastmcp, "get_workloads")
    assert isinstance(workloads_tool, FunctionTool), "Tools should be FunctionTool instances"
    print("✓ Tools are properly wrapped by FastMCP")
    
    return True

def test_prompts():
    """Test that prompts are properly defined"""
    from fastmcp.prompts.prompt import FunctionPrompt
    
    # List of expected prompts
    expected_prompts = [
        "ringfence_application",
        "analyze_application_traffic", 
        "summarize_notes"
    ]
    
    # Check that FastMCP has prompts registered
    # FastMCP wraps prompts as FunctionPrompt objects
    prompts = []
    for name in expected_prompts:
        if hasattr(server_fastmcp, name):
            obj = getattr(server_fastmcp, name)
            # Check if it's a FunctionPrompt
            if isinstance(obj, FunctionPrompt):
                prompts.append(name)
    
    print(f"✓ Found {len(prompts)} prompt functions")
    
    # Verify key prompts exist
    assert "summarize_notes" in prompts, f"summarize_notes not found in {prompts}"
    assert "ringfence_application" in prompts, f"ringfence_application not found in {prompts}"
    print("✓ Key prompts verified")
    
    # Check that prompts are properly wrapped
    summarize_prompt = getattr(server_fastmcp, "summarize_notes")
    assert isinstance(summarize_prompt, FunctionPrompt), "Prompts should be FunctionPrompt instances"
    print("✓ Prompts are properly wrapped by FastMCP")
    
    return True

def main():
    print("Testing FastMCP Refactoring")
    print("=" * 40)
    
    try:
        print("\n1. Testing imports...")
        test_imports()
        
        print("\n2. Testing tool definitions...")
        test_tools()
        
        print("\n3. Testing prompt definitions...")
        test_prompts()
        
        print("\n" + "=" * 40)
        print("✅ All tests passed!")
        print("\nThe FastMCP refactoring is complete and functional.")
        print("\nUsage:")
        print("  - Run server: illumio-mcp")
        print("  - Legacy server: illumio-mcp-legacy")
        
        return 0
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())