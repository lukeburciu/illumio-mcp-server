# FastMCP Migration Guide

## Overview

The Illumio MCP server has been refactored to use FastMCP, a high-level Pythonic framework for building MCP servers. FastMCP provides a cleaner, decorator-based API that simplifies server development while maintaining full compatibility with the MCP protocol.

## What Changed

### 1. Framework
- **Before**: Direct use of `mcp.server` SDK with manual handler registration
- **After**: FastMCP decorators (`@mcp.tool`, `@mcp.prompt`) for cleaner code organization

### 2. Tool Definitions
- **Before**: Tools defined in `handle_list_tools()` with JSON schema, implemented in large `handle_call_tool()` function
- **After**: Each tool is a decorated async function with type hints

### 3. Prompt Handling
- **Before**: Prompts listed in `handle_list_prompts()`, content generated in `handle_get_prompt()`
- **After**: Simple `@mcp.prompt` decorated functions that return prompt text

### 4. Code Organization
- **Before**: Single large file with 2400+ lines
- **After**: Same functionality, cleaner structure with FastMCP patterns

## Installation

```bash
# Install dependencies (FastMCP added)
pip install -r requirements.txt

# Or with uv
uv pip install -e .
```

## Running the Server

### Using FastMCP (Default)
```bash
# This now uses FastMCP by default
illumio-mcp

# Or with environment variables
PCE_HOST=your-host PCE_PORT=your-port PCE_ORG_ID=1 API_KEY=key API_SECRET=secret illumio-mcp
```

### Using Legacy MCP SDK
```bash
# If you need the original implementation
illumio-mcp-legacy
```

## Key Benefits of FastMCP

1. **Cleaner Code**: Decorator-based API reduces boilerplate
2. **Better Type Safety**: Direct use of Python type hints
3. **Simpler Tool Definition**: Each tool is a standalone function
4. **Easier Testing**: Tools can be tested as regular Python functions
5. **Improved Maintainability**: More modular code structure

## Migration Details

### Tool Migration Example

**Before (MCP SDK):**
```python
@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(
            name="get-labels",
            description="Get all labels from PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
                "required": [],
            }
        ),
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict):
    if name == "get-labels":
        # Implementation here
        pass
```

**After (FastMCP):**
```python
@mcp.tool
async def get_labels() -> str:
    """Get all labels from PCE"""
    # Implementation here
```

### Prompt Migration Example

**Before:**
```python
@server.list_prompts()
async def handle_list_prompts():
    return [types.Prompt(name="summarize-notes", ...)]

@server.get_prompt()
async def handle_get_prompt(name: str, arguments: dict):
    if name == "summarize-notes":
        return types.GetPromptResult(...)
```

**After:**
```python
@mcp.prompt
def summarize_notes(style: str = "brief") -> str:
    """Creates a summary of all notes"""
    # Return prompt text directly
```

## Compatibility

- All existing tools and prompts are preserved with identical functionality
- The same environment variables are used
- Read-only mode support is maintained
- Logging configuration remains the same
- Docker deployment unchanged

## File Structure

```
src/illumio_mcp/
├── __init__.py           # Entry points for both versions
├── server.py             # Original MCP SDK implementation (legacy)
└── server_fastmcp.py     # New FastMCP implementation (default)
```

## Testing

Test both implementations to ensure they work correctly:

```bash
# Test FastMCP version
illumio-mcp

# Test legacy version
illumio-mcp-legacy

# Check connection
# Both should respond identically to MCP clients
```

## Troubleshooting

If you encounter issues:

1. **Import Errors**: Ensure FastMCP is installed: `pip install fastmcp>=2.0.0`
2. **Connection Issues**: Check that all environment variables are set correctly
3. **Tool Not Found**: Verify tool names match (underscores vs hyphens)
4. **Legacy Compatibility**: Use `illumio-mcp-legacy` if needed

## Future Improvements

With FastMCP, future enhancements are easier:
- Add middleware for authentication
- Implement rate limiting
- Add request/response logging
- Create tool groups for better organization
- Add streaming responses for large datasets