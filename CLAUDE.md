# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an Illumio MCP (Model Context Protocol) server that provides an interface to interact with Illumio PCE (Policy Compute Engine). The server enables programmatic access to workload management, label operations, traffic flow analysis, and security policy management.

## Development Commands

### Running the Server

```bash
# Using uv (recommended)
uv --directory /path/to/illumio-mcp run illumio-mcp

# With environment variables
PCE_HOST=your-host PCE_PORT=your-port PCE_ORG_ID=1 API_KEY=key API_SECRET=secret uv run illumio-mcp

# Via Docker
docker run -i --init --rm \
  -v /path/to/logs:/var/log/illumio-mcp \
  -e DOCKER_CONTAINER=true \
  -e PYTHONWARNINGS=ignore \
  --env-file ~/.illumio-mcp.env \
  ghcr.io/alexgoller/illumio-mcp-server:latest
```

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install with uv
uv pip install -e .
```

## Architecture

### Core Structure

- **MCP Server Implementation**: Built on the Model Context Protocol using `mcp.server` framework
- **Main Entry Point**: `src/illumio_mcp/server.py` - Contains all server logic, tool definitions, and PCE interactions
- **Python Package**: Configured via `pyproject.toml` with entry point `illumio-mcp`

### Key Components

1. **PCE Connection**: Uses Illumio SDK with credentials from environment variables (PCE_HOST, PCE_PORT, PCE_ORG_ID, API_KEY, API_SECRET, READ_ONLY)

2. **MCP Tools**: Implemented as decorated async functions with `@server.list_tools()` handling:
   - Workload operations (get, create, update, delete)
   - Label management (create, delete, get)
   - Traffic analysis (flows, summaries)
   - Policy management (rulesets, IP lists)
   - Event monitoring
   - Connection health checks

3. **MCP Prompts**: Pre-configured workflows at lines 66-113:
   - `ringfence-application`: Creates security policies for application isolation
   - `analyze-application-traffic`: Analyzes traffic patterns with visualization

4. **Error Handling**: Comprehensive try/catch blocks with detailed logging to file (local: `./illumio-mcp.log`, Docker: `/var/log/illumio-mcp/`)

### Important Implementation Details

- **Max Results Limit**: `MCP_BUG_MAX_RESULTS = 500` (line 58) - Hardcoded limit for API responses
- **Read-Only Mode**: When `READ_ONLY=true`, all modifying operations are blocked at line 850-856
  - Modifying operations list defined at lines 842-847
  - Includes all create, update, delete operations for workloads, labels, rulesets, and IP lists
  - Server logs read-only mode status at startup (lines 65-68)
- **Logging**: Custom setup function that detects Docker environment and adjusts log paths accordingly
- **JSON Encoding**: Custom encoder for handling Illumio SDK objects that aren't JSON serializable
- **Async Architecture**: All MCP tool handlers are async functions using `asyncio`

## Key PCE API Interactions

The server wraps Illumio PCE API calls, handling:
- Authentication via API key/secret
- Workload CRUD operations with label assignments
- Traffic flow queries with extensive filtering options
- Policy ruleset and IP list management
- Event stream monitoring

## Docker Deployment

- Multi-stage build using `uv` for dependency management
- Runs as non-root user `illumio` (UID 1000)
- Log directory at `/var/log/illumio-mcp` with proper permissions
- Entry point: `illumio-mcp` command