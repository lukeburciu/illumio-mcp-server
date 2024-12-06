# Illumio MCP Server

A Machine Conversation Protocol (MCP) server that provides an interface to interact with Illumio PCE (Policy Compute Engine). This server enables programmatic access to Illumio workload management, label operations, and traffic flow analysis.

## Prerequisites

- Python 3.8+
- Access to an Illumio PCE instance
- Valid API credentials for the PCE

## Installation

1. Clone the repository:

```bash
git clone [repository-url]
cd illumio-mcp
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

You should run this using the `uv` command, which makes it easier to pass in environment variables and run it in the background.

## Using uv and Claude Desktop

On MacOS: `~/Library/Application\ Support/Claude/claude_desktop_config.json`
On Windows: `%APPDATA%/Claude/claude_desktop_config.json`

Add the following to the `custom_settings` section:

```json
"mcpServers": {
    "illumio-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "/Users/alex.goller/git/illumio-mcp",
        "run",
        "illumio-mcp"
      ],
      "env": {
        "PCE_HOST": "your-pce-host",
        "PCE_PORT": "your-pce-port",
        "PCE_ORG_ID": "1", # your org id
        "API_KEY": "api_key",
        "API_SECRET": "api_secret"
      }
    }
  }
}
```

## Features

### Resources

Resources are not finished yet and i will look into that later.

- `illumio://workloads` - Get workloads from the PCE
- `illumio://labels` - Get all labels from PCE

### Tools

#### Workload Management
- `get-workloads` - Retrieve workloads from PCE
- `create-workload` - Create an unmanaged workload
- `update-workload` - Update existing workload properties
- `delete-workload` - Remove a workload from PCE

#### Label Operations
- `create-label` - Create a new label
- `delete-label` - Remove an existing label
- `get-labels` - Retrieve all labels from PCE

#### Traffic Analysis
- `get-traffic-flows` - Get detailed traffic flow data
- `get-traffic-flows-summary` - Get summarized traffic flow information

## Error Handling

The server implements comprehensive error handling and logging:
- PCE connection issues
- API authentication failures
- Resource creation/update failures
- Invalid input validation

All errors are logged with full stack traces and returned as formatted error messages to the client.

## Development

### Running Tests

Testing is not implemented yet.

```bash
python -m pytest tests/
```

### Debug Mode
Set logging level to DEBUG in the code or environment for detailed operation logs.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

For support, please [create an issue](https://github.com/illumio/illumio-mcp/issues).
