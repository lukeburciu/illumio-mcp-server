import asyncio
import os
import json
import logging
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
import mcp.server.stdio
import dotenv
import sys
from datetime import datetime, timedelta
from illumio import *
import pandas as pd

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.debug("Loading environment variables")

dotenv.load_dotenv()

PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")

# Store notes as a simple key-value dict to demonstrate state management
notes: dict[str, str] = {}

server = Server("illumio-mcp")

# Update logging configuration at the top of the file after imports
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr),  # Log to stderr since stdout is used for MCP
        logging.FileHandler('illumio-mcp.log')  # Also log to a file for persistence
    ]
)

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """
    List available note resources.
    Each note is exposed as a resource with a custom note:// URI scheme.
    """
    return [
        types.Resource(
            uri=AnyUrl(f"illumio://workloads"),
            name=f"Workloads",
            description=f"Get workloads from the PCE",
            mimeType="application/json",
        ),
        types.Resource(
            uri=AnyUrl(f"illumio://labels"),
            name=f"Labels",
            description=f"Get all labels from PCE",
            mimeType="application/json",
        )
    ]

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """
    Read a specific note's content by its URI.
    The note name is extracted from the URI host component.
    """
    if uri.scheme == "illumio":
        if uri.path == "workloads":
            return json.dumps({"workload": { "name": "server", "ip": "10.1.1.1" }})
        if uri.path == "labels":
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            labels = pce.labels.get()
            return json.dumps({"labels": labels})

    if uri.scheme != "note":
        raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

    name = uri.path
    if name is not None:
        name = name.lstrip("/")
        return notes[name]
    raise ValueError(f"Note not found: {name}")

@server.list_prompts()
async def handle_list_prompts() -> list[types.Prompt]:
    """
    List available prompts.
    Each prompt can have optional arguments to customize its behavior.
    """
    return [
        types.Prompt(
            name="summarize-notes",
            description="Creates a summary of all notes",
            arguments=[
                types.PromptArgument(
                    name="style",
                    description="Style of the summary (brief/detailed)",
                    required=False,
                )
            ],
        )
    ]

@server.get_prompt()
async def handle_get_prompt(
    name: str, arguments: dict[str, str] | None
) -> types.GetPromptResult:
    """
    Generate a prompt by combining arguments with server state.
    The prompt includes all current notes and can be customized via arguments.
    """
    if name != "summarize-notes":
        raise ValueError(f"Unknown prompt: {name}")

    style = (arguments or {}).get("style", "brief")
    detail_prompt = " Give extensive details." if style == "detailed" else ""

    return types.GetPromptResult(
        description="Summarize the current notes",
        messages=[
            types.PromptMessage(
                role="user",
                content=types.TextContent(
                    type="text",
                    text=f"Here are the current notes to summarize:{detail_prompt}\n\n"
                    + "\n".join(
                        f"- {name}: {content}"
                        for name, content in notes.items()
                    ),
                ),
            )
        ],
    )

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available tools.
    Each tool specifies its arguments using JSON Schema validation.
    """
    return [
        types.Tool(
            name="add-note",
            description="Add a new note",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["name", "content"],
            },
        ),
        types.Tool(
            name="get-workloads",
            description="Get workloads from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
                "required": ["name"],
            },
        ),
        types.Tool(
            name="update-workload",
            description="Update a workload in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "ip_addresses": {"type": "array", "items": {"type": "string"}},
                    "labels": {"type": "array", "items": 
                               {"key": {"type": "string"}, "value": {"type": "string"}}
                    },
                },
                "required": ["name", "ip_addresses"],
            }
        ),
        types.Tool(
            name="get-labels",
            description="Get all labels from PCE",
            mimeType="application/json",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
                "required": [],
            }
        ),
        types.Tool(
            name="create-workload",
            description="Create a Illumio Core unmanaged workload in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "ip_addresses": {"type": "array", "items": {"type": "string"}},
                    "labels": {"type": "array", "items": 
                               {"key": {"type": "string"}, "value": {"type": "string"}}
                    },
                },
                "required": ["name", "ip_addresses"],
            }
        ),
        types.Tool(
            name="create-label",
            description="Create a label of a specific type and the value in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"]
            }
        ),
        types.Tool(
            name="delete-label",
            description="Delete a label in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"]
            }
        ),
        types.Tool(
            name="delete-workload",
            description="Delete a workload from the PCE",
            inputSchema={
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"]
            }
        ),
        types.Tool(
            name="get-traffic-flows",
            description="Get traffic flows from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer"},
                    "start_date": {"type": "string"},
                    "end_date": {"type": "string"},
                    "include_sources": {"type": "array", "items": {"type": "object"}},
                    "include_services": {"type": "array", "items": {"type": "object"}},
                    "exclude_services": {"type": "array", "items": {"type": "object"}},
                    "exclude_destinations": {"type": "array", "items": {"type": "object"}},
                    "policy_decisions": {"type": "array", "items": {"type": "string"}},
                }
            }
        ),
        types.Tool(
            name="get-traffic-flows-summary",
            description="Get traffic flows from the PCE in a summarized text format",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string"},
                    "end_date": {"type": "string"},
                }
            }
        ),
        types.Tool(
            name="check-pce-connection",
            description="Are my credentials and the connection to the PCE working?",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    logger.debug(f"Handling tool call: {name} with arguments: {arguments}")
    
    if name == "get-workloads":
        logger.debug("Initializing PCE connection")
        try:
            logger.debug(f"PCE connection details - Host: {PCE_HOST}, Port: {PCE_PORT}, Org: {PCE_ORG_ID}")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            logger.debug("PCE instance created")
            
            logger.debug("Setting PCE credentials")
            pce.set_credentials(API_KEY, API_SECRET)
            logger.debug("Credentials set")
            
            logger.debug("Checking PCE connection")
            connection_status = pce.check_connection()
            logger.debug(f"PCE connection status: {connection_status}")
            
            logger.debug("Fetching workloads from PCE")
            workloads = pce.workloads.get(params={"include": "labels"})
            logger.debug(f"Successfully retrieved {len(workloads)} workloads")
            return [types.TextContent(
                type="text",
                text=f"Workloads: {workloads}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "check-pce-connection":
        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            return [types.TextContent(
                type="text",
                text=f"PCE connection successful"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "create-label":
        logger.debug(f"Creating label with key: {arguments['key']} and value: {arguments['value']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            label = Label(key=arguments['key'], value=arguments['value'])
            label = pce.labels.create(label)
            logger.debug(f"Label created with status: {label}")
            return [types.TextContent(
                type="text",
                text=f"Label created with status: {label}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "delete-label":
        logger.debug(f"Deleting label with key: {arguments['key']} and value: {arguments['value']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            label = pce.labels.get(params = { "key": arguments['key'], "value": arguments['value'] })
            if label:
                pce.labels.delete(label[0])
                return [types.TextContent(
                    type="text",
                    text=f"Label deleted with status: {label}"
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text=f"Label not found"
                )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "get-labels":
        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            resp = pce.get('/labels')
            labels = resp.json()
            return [types.TextContent(
                type="text",
                text= f"Labels: {labels}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="json",
                text=f"Error: {error_msg}"
            )]
    elif name == "create-workload":
        logger.debug(f"Creating workload with name: {arguments['name']} and ip_addresses: {arguments['ip_addresses']}")
        logger.debug(f"Labels: {arguments['labels']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            interfaces = []
            prefix = "eth"
            if_count = 0
            for ip in arguments['ip_addresses']:
                intf = Interface(name = f"{prefix}{if_count}", address = ip)
                interfaces.append(intf)
                if_count += 1

            workload_labels = []

            for label in arguments['labels']:
                logger.debug(f"Label: {label}")
                # check if label already exists
                label_resp = pce.labels.get(params = { "key": label['key'], "value": label['value'] })
                if label_resp:
                    logger.debug(f"Label already exists: {label_resp}")
                    workload_label = label_resp[0]  # Get the first matching label
                else:
                    logger.debug(f"Label does not exist, creating: {label}")
                    new_label = Label(key=label['key'], value=label['value'])
                    workload_label = pce.labels.create(new_label)

                workload_labels.append(workload_label)

            logger.debug(f"Labels: {workload_labels}")

            workload = Workload(
                name=arguments['name'], 
                interfaces=interfaces, 
                labels=workload_labels,
                hostname=arguments['name']  # Adding hostname which might be required
            )
            status = pce.workloads.create(workload)
            logger.debug(f"Workload creation status: {status}")
            return [types.TextContent(
                type="text",
                text=f"Workload created with status: {status}, workload: {workload}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "update-workload":
        logger.debug(f"Updating workload with name: {arguments['name']} and ip_addresses: {arguments['ip_addresses']}")
        logger.debug(f"Labels: {arguments['labels']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            workload = pce.workloads.get(params = { "name": arguments['name'] })
            if workload:
                logger.debug(f"Workload found: {workload}")
                interfaces = []
                prefix = "eth"
                if_count = 0
                for ip in arguments['ip_addresses']:
                    intf = Interface(name = f"{prefix}{if_count}", address = ip)
                    interfaces.append(intf)
                    if_count += 1

                workload_labels = []

                for label in arguments['labels']:
                    logger.debug(f"Label: {label}")
                    # check if label already exists
                    label_resp = pce.labels.get(params = { "key": label['key'], "value": label['value'] })
                    if label_resp:
                        logger.debug(f"Label already exists: {label_resp}")
                        workload_label = label_resp[0]  # Get the first matching label
                    else:
                        logger.debug(f"Label does not exist, creating: {label}")
                        new_label = Label(key=label['key'], value=label['value'])
                        workload_label = pce.labels.create(new_label)

                    workload_labels.append(workload_label)

                logger.debug(f"Labels: {workload_labels}")
                if workload_labels:
                    workload = pce.workloads.update(workload[0], labels=workload_labels)
                    logger.debug(f"Workload update status: {workload}")
                    return [types.TextContent(
                    type="text",
                    text=f"Workload updated with status: {workload}"
                )]

                elif interfaces:
                    workload = pce.workloads.update(workload[0], interfaces=interfaces)
                    logger.debug(f"Workload update status: {workload}")
                    return [types.TextContent(
                    type="text",
                    text=f"Workload updated with status: {workload}"
                )]
                elif interfaces and workload_labels:
                    workload = pce.workloads.update(workload[0], interfaces=interfaces, labels=workload_labels)
                    logger.debug(f"Workload update status: {workload}")
                    return [types.TextContent(
                    type="text",
                    text=f"Workload updated with status: {workload}"
                )]
            else:
                logger.debug(f"Workload not found")
                return [types.TextContent(
                    type="text",
                    text=f"Workload not found"
                )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "delete-workload":
        logger.debug(f"Deleting workload with name: {arguments['name']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            workload = pce.workloads.get(params = { "name": arguments['name'] })
            if workload:
                pce.workloads.delete(workload[0])
                return [types.TextContent(
                    type="text",
                    text=f"Workload deleted with status: {status}"
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text=f"Workload not found"
                )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "get-traffic-flows":
        logger.debug(f"Getting traffic flows with limit: {arguments['limit']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            # d_end is now, d_start is 30 days ago
            d_end = datetime.now()
            d_start = d_end - timedelta(days=30)

            traffic_query = TrafficQuery.build(
                start_date=d_start.strftime("%Y-%m-%d"),
                end_date=d_end.strftime("%Y-%m-%d"),
                include_services=[],
                exclude_services=[
                        {"port": 53},
                        {"port": 137},
                        {"port": 138},
                        {"port": 139},
                        {"proto": "udp"}
                ],
                exclude_destinations=[
                        {"transmission": "broadcast"},
                        {"transmission": "multicast"}
                ],
                policy_decisions=['allowed', 'potentially_blocked', 'unknown'],
                max_results=arguments['limit']
            )

            all_traffic = pce.get_traffic_flows_async(
                query_name='all-traffic',
                traffic_query=traffic_query
            )
            return [types.TextContent(
                type="text",
                text=f"Traffic flows: {all_traffic}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
        raise ValueError("Missing arguments")
    elif name == "get-traffic-flows-summary":
        logger.debug(f"Getting traffic flows summary with start_date: {arguments['start_date']} and end_date: {arguments['end_date']}") 
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            query = TrafficQuery.build(
                start_date=arguments['start_date'],
                end_date=arguments['end_date'],
                max_results=10000
            )

            all_traffic = pce.get_traffic_flows_async(
                query_name='all-traffic',
                traffic_query=query
            )

            df = to_dataframe(all_traffic)
            summary = summarize_traffic(df)

            return [types.TextContent(
                type="text",
                text=f"Traffic flows summary: {summary}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]

    note_name = arguments.get("name")
    content = arguments.get("content")

    if not note_name or not content:
        raise ValueError("Missing name or content")

    # Update server state
    notes[note_name] = content

    # Notify clients that resources have changed
    await server.request_context.session.send_resource_list_changed()

    return [
        types.TextContent(
            type="text",
            text=f"Added note '{note_name}' with content: {content}",
        )
    ]

def to_dataframe(flows):
    pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
    pce.set_credentials(API_KEY, API_SECRET)

    label_href_map = {}
    value_href_map = {}
    for l in pce.labels.get(params={'max_results': 10000}):
        label_href_map[l.href] = {"key": l.key, "value": l.value}
        value_href_map["{}={}".format(l.key, l.value)] = l.href

    if not flows:
        print("Warning: Empty flows list received.")
        return pd.DataFrame()

    series_array = []
    for flow in flows:
        try:
            f = {
                'src_ip': flow.src.ip,
                    'src_hostname': flow.src.workload.name if flow.src.workload is not None else None,
                    'dst_ip': flow.dst.ip,
                    'dst_hostname': flow.dst.workload.name if flow.dst.workload is not None else None,
                    'proto': flow.service.proto,
                    'port': flow.service.port,
                    'process_name': flow.service.process_name,
                    'service_name': flow.service.service_name,
                    'policy_decision': flow.policy_decision,
                    'flow_direction': flow.flow_direction,
                    'num_connections': flow.num_connections,
                    'first_detected': flow.timestamp_range.first_detected,
                    'last_detected': flow.timestamp_range.last_detected,
            }

            # Add src and dst app and env labels
            if flow.src.workload:
                for l in flow.src.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'src_{key}'] = value

            if flow.dst.workload:
                for l in flow.dst.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'dst_{key}'] = value

                series_array.append(f)
        except AttributeError as e:
            print(f"Error processing flow: {e}")
            print(f"Flow object: {flow}")

    df = pd.DataFrame(series_array)
    print(f"DataFrame info:\n{df.info()}")
    return df
  
def summarize_traffic(df):
    logger.debug(f"Summarizing traffic with dataframe: {df}")
    group_columns = ['src_app', 'src_env', 'dst_app', 'dst_env', 'proto', 'port']

    print(f"Group columns: {group_columns}")
    print(f"DataFrame shape before grouping: {df.shape}")
    print(f"DataFrame columns: {df.columns.tolist()}")
    print(f"First few rows of DataFrame:\n{df.head()}")

    # Group by available columns
    summary = df.groupby(group_columns)['num_connections'].sum().reset_index()
        
    print(f"Summary shape after grouping: {summary.shape}")
    print(f"Summary columns: {summary.columns.tolist()}")
    print(f"First few rows of summary:\n{summary.head()}")

    # Sort by number of connections in descending order
    summary = summary.sort_values('num_connections', ascending=False)

    # Convert to a more readable format
    summary_list = []
    for _, row in summary.iterrows():
        src_info = f"{row['src_app']} ({row['src_env']})" if 'src_app' in row else row['src_ip']
        dst_info = f"{row['dst_app']} ({row['dst_env']})" if 'dst_app' in row else row['dst_ip']

        if src_info != dst_info:
            summary_list.append(
                f"From {src_info} to {dst_info} on port {row['port']}: {row['num_connections']} connections"
            )
    return "\n".join(summary_list)

async def main():
    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="illumio-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

# After loading environment variables
logger.debug("Environment check:")
logger.debug(f"PCE_HOST set: {PCE_HOST}")
logger.debug(f"PCE_PORT set: {PCE_PORT}")
logger.debug(f"PCE_ORG_ID set: {PCE_ORG_ID}")
logger.debug(f"API_KEY set: {API_KEY}")
logger.debug(f"API_SECRET set: {bool(API_SECRET)}")