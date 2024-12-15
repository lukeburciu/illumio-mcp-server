# Illumio MCP Server

A Model Context Protocol (MCP) server that provides an interface to interact with Illumio PCE (Policy Compute Engine). This server enables programmatic access to Illumio workload management, label operations, and traffic flow analysis.

## What can it do?

Use conversational AI to talk to your PCE:

- Create, update and delete workloads
- Create, update and delete labels
- Get traffic summaries and do security analysis on them
- Get PCE health

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
- `get-workloads` - Retrieve all workloads from PCE
- `create-workload` - Create an unmanaged workload with specified name, IP addresses, and labels
- `update-workload` - Update an existing workload's properties
- `delete-workload` - Remove a workload from PCE by name

#### Label Operations
- `create-label` - Create a new label with key-value pair
- `delete-label` - Remove an existing label by key-value pair
- `get-labels` - Retrieve all labels from PCE

#### Traffic Analysis
- `get-traffic-flows` - Get detailed traffic flow data with comprehensive filtering options:
  - Date range filtering
  - Source/destination filtering
  - Service (port/protocol) filtering
  - Policy decision filtering
  - Workload and IP list query options
  - Results limiting
  
- `get-traffic-flows-summary` - Get summarized traffic flow information with the same filtering capabilities as get-traffic-flows

#### Policy Management
- `get-rulesets` - Get rulesets from the PCE with optional filtering:
  - Filter by name
  - Filter by enabled status

#### IP Lists Management
- `get-iplists` - Get IP lists from the PCE with optional filtering:
  - Filter by name
  - Filter by description
  - Filter by IP ranges

#### Connection Testing
- `check-pce-connection` - Verify PCE connectivity and credentials

#### Event Management
- `get-events` - Get events from the PCE with optional filtering:
  - Filter by event type (e.g., 'system_task.expire_service_account_api_keys')
  - Filter by severity (emerg, alert, crit, err, warning, notice, info, debug)
  - Filter by status (success, failure)
  - Limit number of results returned

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
