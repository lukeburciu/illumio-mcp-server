# Illumio MCP Server

A Model Context Protocol (MCP) server that provides a conversational AI interface to interact with Illumio PCE (Policy Compute Engine). This server enables programmatic access to workload management, label operations, traffic flow analysis, and security policy management through natural language.

## Features

### 🎯 Core Capabilities
- **Workload Management**: Create, update, delete, and query workloads
- **Label Operations**: Manage labels for application segmentation
- **Traffic Analysis**: Analyze traffic flows with detailed filtering and summaries
- **Policy Management**: Create and manage rulesets and IP lists
- **Security Analysis**: Generate security assessments and remediation plans
- **Event Monitoring**: Track PCE events and system health

### 🛡️ Safety Features
- **Read-Only Mode**: Safely explore PCE without risk of changes
- **Comprehensive Error Handling**: Detailed logging and error reporting
- **Input Validation**: Secure handling of all PCE operations

## Quick Start

### Installation via UV (Recommended)

```bash
# Install directly from GitHub
uvx --from git+https://github.com/lukeburciu/illumio-mcp-server@main illumio-mcp
```

### Claude Desktop Configuration

Add to your Claude Desktop config file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`  
**Claude Code**: `$PROJECT_DIR/.mcp.json`

```json
{
  "mcpServers": {
    "illumio-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/lukeburciu/illumio-mcp-server@main",
        "illumio-mcp"
      ],
      "env": {
        "PCE_HOST": "your-pce-host.com",
        "PCE_PORT": "443",
        "PCE_ORG_ID": "1",
        "API_KEY": "your-api-key",
        "API_SECRET": "your-api-secret",
        "READ_ONLY": "false"
      }
    }
  }
}
```

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PCE_HOST` | PCE hostname | - | ✅ |
| `PCE_PORT` | PCE port | 443 | ❌ |
| `PCE_ORG_ID` | Organization ID | 1 | ❌ |
| `API_KEY` | API key for authentication | - | ✅ |
| `API_SECRET` | API secret | - | ✅ |
| `READ_ONLY` | Enable read-only mode | false | ❌ |

## Available Tools

### Workload Management
- **`get-workloads`**: Retrieve workloads with optional filtering
- **`create-workload`**: Create unmanaged workloads with labels
- **`update-workload`**: Modify existing workload properties
- **`delete-workload`**: Remove workloads from PCE

### Label Operations
- **`get-labels`**: List all labels in PCE
- **`create-label`**: Create new key-value labels
- **`delete-label`**: Remove existing labels

### Traffic Analysis
- **`get-traffic-flows`**: Detailed traffic flow data with filtering:
  - Date range selection
  - Source/destination filtering
  - Service and port filtering
  - Policy decision analysis
- **`get-traffic-flows-summary`**: Aggregated traffic summaries

### Policy Management
- **`get-rulesets`**: Query rulesets with name/status filtering
- **`get-iplists`**: Manage IP lists with range filtering

### System Operations
- **`check-pce-connection`**: Verify connectivity and credentials
- **`get-events`**: Monitor PCE events by type/severity/status

## MCP Prompts

### 🔒 Ringfence Application
Creates comprehensive security policies to isolate applications:
```
Arguments:
- application_name: Target application
- application_environment: Target environment

Creates:
- Inter-tier communication rules
- Inbound/outbound restrictions
- External connection policies
```

### 📊 Analyze Application Traffic
Provides detailed traffic pattern analysis:
```
Arguments:
- application_name: Application to analyze
- application_environment: Environment to analyze

Returns:
- Traffic flow patterns
- Service identification
- Label categorization
- Internet exposure status
```

### Using Prompts in Claude Desktop

1. Click "Attach from MCP" button
2. Select "illumio-mcp" from available servers
3. Choose your prompt (e.g., "analyze-application-traffic")
4. Fill in required parameters
5. Submit to generate analysis

## Read-Only Mode

Enable safe exploration without modifications:

```json
"env": {
  "READ_ONLY": "true"
}
```

When enabled, blocks:
- Workload creation/updates/deletion
- Label modifications
- Policy changes
- Any PCE state modifications

All read operations remain available.

## Development

### Local Development Setup

```bash
# Clone repository
git clone https://github.com/lukeburciu/illumio-mcp-server
cd illumio-mcp-server

# Install with UV
uv pip install -e .

# Run locally
uv run illumio-mcp
```

### Running Tests

```bash
uv run python test_server.py
```

### Project Structure

```
src/illumio_mcp/
├── server.py           # Main FastMCP entry point
├── core/              # Core functionality
│   ├── config.py      # Environment configuration
│   ├── connection.py  # PCE connection management
│   └── logging.py     # Centralized logging
├── tools/             # MCP tool implementations
│   ├── workloads.py   # Workload operations
│   ├── labels.py      # Label management
│   ├── policies.py    # Policy operations
│   ├── traffic.py     # Traffic analysis
│   └── misc.py        # Utility tools
└── prompts/           # MCP prompt definitions
```

## Use Cases

### Security Analysis
- Generate compliance reports (PCI, SWIFT, etc.)
- Identify high-risk vulnerabilities
- Create remediation plans
- Analyze application dependencies

### Infrastructure Management
- Monitor service communications
- Track workload metrics
- Manage segmentation policies
- Audit label usage

### Traffic Intelligence
- Identify unknown services
- Map application flows
- Detect policy violations
- Optimize rule sets

## Visual Examples

The server enables creation of rich visualizations through Claude Desktop:

- **Application Analysis**: Communication patterns and dependencies
- **Security Assessments**: Compliance reports and risk findings
- **Traffic Patterns**: Service role inference and flow analysis
- **Policy Management**: Ruleset organization and IP list management
- **Workload Insights**: Detailed metrics and traffic identification

## Troubleshooting

### Connection Issues
1. Verify PCE_HOST is accessible
2. Check API credentials are valid
3. Confirm PCE_ORG_ID is correct
4. Use `check-pce-connection` tool to diagnose

### Permission Errors
- Ensure API key has required permissions
- Enable READ_ONLY mode for testing
- Check PCE role assignments

### Common Errors
- **"Resource not found"**: Verify resource names/IDs
- **"Authentication failed"**: Check API_KEY and API_SECRET
- **"Connection timeout"**: Verify network connectivity to PCE

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

[License information to be added]

## Support

For issues and questions:
- Open an issue on [GitHub](https://github.com/lukeburciu/illumio-mcp-server/issues)
- Check existing documentation in `/docs`
- Review CLAUDE.md for development guidelines

## Acknowledgments

Built with:
- [FastMCP](https://github.com/jlowin/fastmcp) - MCP server framework
- [Illumio SDK](https://github.com/illumio/illumio-py) - Python SDK for PCE
- [Model Context Protocol](https://modelcontextprotocol.io) - AI integration protocol