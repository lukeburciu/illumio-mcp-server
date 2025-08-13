# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an Illumio MCP (Model Context Protocol) server that provides an interface to interact with Illumio PCE (Policy Compute Engine). The server enables programmatic access to workload management, label operations, traffic flow analysis, and security policy management.

## Development Commands

### Important: Always Use UV
**Always use `uv` for Python operations in this project.** UV is a fast Python package manager that ensures consistent dependency resolution and virtual environment management.

### Running the Server
```bash
# Using uvx (ALWAYS use this method)
uvx --from git+https://github.com/lukeburciu/illumio-mcp-server@main illumio-mcp

# Or if running locally with uv
uv run illumio-mcp
```

### Testing
```bash
# Run the test script with uv
uv run python test_server.py
```

### Installation
```bash
# Install dependencies with uv (ALWAYS use this instead of pip)
uv pip install -r requirements.txt

# Or sync with lock file
uv sync

# Install the package in development mode
uv pip install -e .
```

### Python Execution
```bash
# ALWAYS use uv to run Python scripts
uv run python script.py

# NOT: python script.py
```

## Architecture

### Core Structure
The project uses FastMCP framework and is organized into modular components:

- **`src/illumio_mcp/server.py`**: Main entry point that creates FastMCP instance and registers all tools/prompts
- **`src/illumio_mcp/core/`**: Core functionality
  - `config.py`: Environment variable configuration (PCE_HOST, API_KEY, etc.)
  - `connection.py`: PCE connection management using illumio SDK
  - `logging.py`: Centralized logging configuration
  - `encoders.py`: JSON encoding utilities for Illumio objects
  
- **`src/illumio_mcp/tools/`**: MCP tool implementations (registered with FastMCP decorators)
  - `workloads.py`: Workload CRUD operations
  - `labels.py`: Label management
  - `policies.py`: Ruleset and IP list management
  - `traffic.py`: Traffic flow analysis and summaries
  - `misc.py`: Utility tools (connection check, events, notes)
  
- **`src/illumio_mcp/prompts/`**: MCP prompt implementations
  - `prompts.py`: Contains ringfence_application, analyze_application_traffic, summarize_notes
  
- **`src/illumio_mcp/utils/`**: Utility functions
  - `filters.py`: Traffic flow filtering logic

### Key Design Patterns

1. **FastMCP Registration Pattern**: All tools and prompts are registered using FastMCP's decorator-based approach:
   ```python
   @mcp.tool()
   def tool_name(param: str) -> dict:
       # Implementation
   ```

2. **Read-Only Mode**: Global READ_ONLY flag in config.py controls whether modifying operations are allowed

3. **Connection Management**: Centralized PCE connection through `get_pce_connection()` function

4. **Error Handling**: All tools implement comprehensive try-catch blocks with detailed error logging

5. **JSON Encoding**: Custom encoder (IllumioEncoder) handles Illumio SDK objects that aren't JSON-serializable

## Environment Variables

Required environment variables for PCE connection:
- `PCE_HOST`: PCE hostname
- `PCE_PORT`: PCE port (default: 443)
- `PCE_ORG_ID`: Organization ID (default: 1)
- `API_KEY`: API key for authentication
- `API_SECRET`: API secret
- `READ_ONLY`: Set to "true" to enable read-only mode (optional)

## Testing Approach

The project includes `test_server.py` which verifies:
- Module imports
- FastMCP server instance creation
- Tool registration and wrapping
- Prompt registration
- Environment variable configuration

Note: Full integration tests are not yet implemented.

## Key Dependencies

- `fastmcp>=2.11.2`: MCP server framework
- `illumio>=1.1.3`: Illumio PCE SDK
- `pandas>=2.2.3`: Data manipulation for traffic analysis
- `python-dotenv>=1.0.1`: Environment variable management

## Common Tasks

### Adding a New Tool
1. Create function in appropriate module under `src/illumio_mcp/tools/`
2. Use `@mcp.tool()` decorator
3. Register in the module's `register_*_tools()` function
4. Follow existing error handling patterns

### Adding a New Prompt
1. Add function to `src/illumio_mcp/prompts/prompts.py`
2. Use `@mcp.prompt()` decorator
3. Register in `register_prompts()` function

### Debugging
- Check logs for detailed error messages (logging level can be adjusted in core/logging.py)
- Use `test_server.py` to verify tool/prompt registration
- Environment variables can be tested with `check_pce_connection` tool

## Development Rules

### Code Style and Patterns
1. **Always use UV for Python operations** - use `uv run python` instead of `python`, `uv pip` instead of `pip`
2. **Always use FastMCP decorators** for new tools and prompts - do not create standalone functions
3. **Follow the existing module organization** - place tools in appropriate files (workloads, labels, policies, traffic, misc)
4. **Implement comprehensive error handling** - wrap all PCE operations in try-catch blocks with detailed logging
5. **Use the centralized connection** - always get PCE instance via `get_pce_connection()`, never create direct connections
6. **Respect read-only mode** - check READ_ONLY flag before any modifying operations

### Security and Safety
1. **Never commit credentials** - all sensitive data must come from environment variables
2. **Validate all inputs** - especially when creating or modifying PCE resources
3. **Log operations** - use the centralized logger for all significant operations
4. **Handle PCE errors gracefully** - provide meaningful error messages to users

### Testing and Quality
1. **Update test_server.py** when adding new tools or prompts
2. **Test with read-only mode** first before enabling write operations
3. **Verify PCE connection** using the check_pce_connection tool before other operations
4. **Document tool parameters** clearly in docstrings and type hints

### MCP-Specific Guidelines
1. **Return structured data** - tools should return dictionaries or lists that can be JSON-serialized
2. **Use IllumioEncoder** for any Illumio SDK objects that need JSON encoding
3. **Keep tool functions focused** - each tool should do one thing well
4. **Provide helpful descriptions** in tool decorators for better MCP client integration

### When Modifying Code
1. **Preserve existing functionality** - don't break existing tools when adding new features
2. **Update CLAUDE.md** if you change architecture or add significant new capabilities
3. **Follow the registration pattern** - new tools must be registered in their module's register function
4. **Maintain backwards compatibility** with environment variables and tool interfaces