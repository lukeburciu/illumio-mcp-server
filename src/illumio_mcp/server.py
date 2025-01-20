import asyncio
import os
import json
import logging
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl, BaseModel
import mcp.server.stdio
import dotenv
import sys
from datetime import datetime, timedelta
from illumio import *
import pandas as pd
from json import JSONEncoder, dumps

def setup_logging():
    """Configure logging based on environment"""
    logger = logging.getLogger('illumio_mcp')
    logger.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Check if running in Docker
    in_docker = os.environ.get('DOCKER_CONTAINER', False)
    
    if in_docker:
        # Configure logging to write to a file in /var/log
        log_dir = '/var/log/illumio-mcp'
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            filename=f'{log_dir}/illumio-mcp.log',
            level=logging.INFO
        )
    else:
        # Use file handler for local development
        log_dir = os.path.expanduser('~/.illumio-mcp/logs')
        os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.FileHandler(
            os.path.join(log_dir, 'illumio-mcp.log')
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)
    
    return logger

# Initialize logging
logger = setup_logging()
logger.debug("Loading environment variables")

if dotenv.load_dotenv():
    logger.debug("Environment variables loaded")

PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")

MCP_BUG_MAX_RESULTS = 500

# Store notes as a simple key-value dict to demonstrate state management
notes: dict[str, str] = {}

server = Server("illumio-mcp")

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
        ),
        types.Prompt(
            name="ringfence-application",
            description="Ringfence an application by deploying rulesets to limit the inbound and outbound traffic",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to ringfence",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to ringfence",
                    required=True,
                )
            ],
        ),
        types.Prompt(
            name="analyze-application-traffic",
            description="Analyze the traffic flows for an application and environment",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to analyze",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to analyze",
                    required=True,
                )
            ]
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
    if name == "ringfence-application":
        return types.GetPromptResult(
            description="Ringfence an application by deploying rulesets to limit the inbound and outbound traffic",
        messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
                            Ringfence the application {arguments['application_name']} in the environment {arguments['application_environment']}.
                            Always reference labels as hrefs like /orgs/1/labels/57 or similar.
                            Consumers means the source of the traffic, providers means the destination of the traffic.
                            First, retrieve all the traffic flows inside the application and environment. Analyze the connections. Then retrieve all the traffic flows inbound to the application and environment.
                            Inside the app, please be sure to have rules for each role or app tier to connect to the other tiers.  
                            Always use traffic flows to find out what other applications and environemnts need to connect into {arguments['application_name']}, 
                            and then deploy rulesets to limit the inbound traffic to those applications and environments. 
                            For traffic that is required to connect outbound from {arguments['application_name']}, deploy rulesets to limit the 
                            outbound traffic to those applications and environments. If a consumer is coming from the same app and env, please use 
                            all workloads for the rules inside the scope (intra-scope). If it comes from the outside, please use app, env and if possible role
                            If a remote app is connected as destination, a new ruleset needs to be created that has the name of the remote app and env,
                            all incoming connections need to be added as extra-scope rules in that ruleset.
                            The logic in illumio is the following.

If a scope exists. Rules define connections within the scope if unscoped consumers is not set to true. Unscoped consumers define inbound traffic from things outside the scope. The unscoped consumer is a set of labels being the source of inbound traffic. Provider is the destination. For the provider a value of AMS (short for all workloads) means that a connection is allowed for all workloads inside the scope. So for example if the source is role=monitoring, app=nagios, env=prod, then the rule for the app=ordering, env=prod application would be:

  consumer: role=monitoring,app=nagios,env=prod 
  provider: role=All workloads
  service: 5666/tcp

  If a rule is setting unscoped consumers to "false", this means that the rule is intra scope. Repeating any label that is in the scope does not make sense for this. Instead use role or whatever specific label to characterize the thing in the scope.

e.g. for the loadbalancer to connect to the web-tier in ordering, prod the rule is:

scope: app=ordering, env=prod
consumers: role=loadbalancer
providers: role=web
service: 8080/tcp
unscoped consumers: false

This is a intra-scope rule allowing the role=loadbalancer,app=ordering,env=prod workloads to connect to the role=web,app=ordering,env=prod workloads on port 8080/tcp. 

                        """
                    )
                )
            ]
        )
    elif name == "analyze-application-traffic":
        return types.GetPromptResult(
            description="Analyze the traffic flows for an application and environment",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
                            Please provide the traffic flows for {arguments['application_name']} in the environment {arguments['application_environment']}.
                            Order by inbound and outbound traffic and app/env/role tupels.
                            Find other label types that are of interest and show them. Display your results in a react component. Show protocol, port and try to
                            understand the traffic flows (e.g. 5666/tcp likely could be nagios).
                            Categorize traffic into infrastructure and application traffic.
                            Find out if the application is internet facing or not.
                            Show illumio role labels, as well as application and environment labels in the output.
                        """
                    )
                )
            ]
        )

    else:
        raise ValueError(f"Unknown prompt: {name}")

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
            description="Get traffic flows from the PCE with comprehensive filtering options",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "Starting datetime (YYYY-MM-DD or timestamp)"},
                    "end_date": {"type": "string", "description": "Ending datetime (YYYY-MM-DD or timestamp)"},
                    "include_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "exclude_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to exclude (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "include_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to include (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "exclude_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to exclude (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "include_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "exclude_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "policy_decisions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["allowed", "blocked", "potentially_blocked", "unknown"]
                        }
                    },
                    "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                    "query_name": {"type": "string"}
                },
                "required": ["start_date", "end_date"]
            }
        ),
        types.Tool(
            name="get-traffic-flows-summary",
            description="Get traffic flows from the PCE in a summarized text format, this is a text format that is not a dataframe, it also is not json, the form is: 'From <source> to <destination> on <port> <proto>: <number of connections>'",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "Starting datetime (YYYY-MM-DD or timestamp)"},
                    "end_date": {"type": "string", "description": "Ending datetime (YYYY-MM-DD or timestamp)"},
                    "include_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "exclude_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to exclude (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "include_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to include (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "exclude_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to exclude (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "include_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "exclude_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "policy_decisions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["allowed", "potentially_blocked", "blocked", "unknown"]
                        }
                    },
                    "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                    "query_name": {"type": "string"}
                },
                "required": ["start_date", "end_date"]
            }
        ),
        types.Tool(
            name="check-pce-connection",
            description="Are my credentials and the connection to the PCE working?",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        types.Tool(
            name="get-rulesets",
            description="Get rulesets from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Filter rulesets by name (optional)"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Filter by enabled/disabled status (optional)"
                    }
                }
            }
        ),
        types.Tool(
            name="get-iplists",
            description="Get IP lists from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Filter IP lists by name (optional)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Filter by description (optional)"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "Filter by IP ranges (optional)"
                    }
                }
            }
        ),
        types.Tool(
            name="get-events",
            description="Get events from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {
                        "type": "string",
                        "description": "Filter by event type (e.g., 'system_task.expire_service_account_api_keys')"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                        "description": "Filter by event severity"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["success", "failure"],
                        "description": "Filter by event status"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 100
                    }
                }
            }
        ),
        types.Tool(
            name="create-ruleset",
            description="Create a ruleset in the PCE with support for ring-fencing patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the ruleset (e.g., 'RS-ELK'). Must be unique in the PCE."},
                    "description": {"type": "string", "description": "Description of the ruleset (optional)"},
                    "scopes": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "description": "List of label combinations that define scopes. Each scope is an array of label values. This need to be label references like /orgs/1/labels/57 or similar. Get the label href from the get-labels tool."
                    },
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "providers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Array of provider labels, 'ams' for all workloads, or IP list references (e.g., 'iplist:Any (0.0.0.0/0)')"
                                },
                                "consumers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Array of consumer labels, 'ams' for all workloads, or IP list references (e.g., 'iplist:Any (0.0.0.0/0)')"
                                },
                                "ingress_services": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "port": {"type": "integer"},
                                            "proto": {"type": "string"}
                                        },
                                        "required": ["port", "proto"]
                                    }
                                },
                                "unscoped_consumers": {
                                    "type": "boolean",
                                    "description": "Whether to allow unscoped consumers (extra-scope rule)",
                                    "default": False
                                }
                            },
                            "required": ["providers", "consumers", "ingress_services"]
                        }
                    }
                },
                "required": ["name", "scopes"]
            }
        ),
        types.Tool(
            name="get-services",
            description="Get services from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Filter services by name"
                    },
                    "description": {
                        "type": "string",
                        "description": "Filter services by description"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Filter services by port number"
                    },
                    "proto": {
                        "type": "string",
                        "description": "Filter services by protocol (e.g., tcp, udp)"
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Filter services by process name"
                    }
                }
            }
        ),
        types.Tool(
            name="update-label",
            description="Update an existing label in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Label href (e.g., /orgs/1/labels/42). Either href or both key and value must be provided to identify the label."
                    },
                    "key": {
                        "type": "string",
                        "description": "Label type (e.g., role, app, env, loc)"
                    },
                    "value": {
                        "type": "string",
                        "description": "Current value of the label"
                    },
                    "new_value": {
                        "type": "string",
                        "description": "New value for the label"
                    }
                },
                "oneOf": [
                    {"required": ["href", "key", "new_value"]},
                    {"required": ["key", "value", "new_value"]}
                ]
            }
        ),
        types.Tool(
            name="create-iplist",
            description="Create a new IP List in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List"
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the IP List"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "description": "List of IP ranges to include",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_ip": {
                                    "type": "string",
                                    "description": "Starting IP address (IPv4 or IPv6)"
                                },
                                "to_ip": {
                                    "type": "string",
                                    "description": "Ending IP address (optional, for ranges)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of this IP range (optional)"
                                },
                                "exclusion": {
                                    "type": "boolean",
                                    "description": "Whether this is an exclusion range",
                                    "default": False
                                }
                            },
                            "required": ["from_ip"]
                        }
                    },
                    "fqdn": {
                        "type": "string",
                        "description": "Fully Qualified Domain Name (optional)"
                    }
                },
                "required": ["name", "ip_ranges"]
            }
        ),
        types.Tool(
            name="update-iplist",
            description="Update an existing IP List in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to update"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to update (alternative to href)"
                    },
                    "description": {
                        "type": "string",
                        "description": "New description for the IP List (optional)"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "description": "New list of IP ranges",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_ip": {
                                    "type": "string",
                                    "description": "Starting IP address (IPv4 or IPv6)"
                                },
                                "to_ip": {
                                    "type": "string",
                                    "description": "Ending IP address (optional, for ranges)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of this IP range (optional)"
                                },
                                "exclusion": {
                                    "type": "boolean",
                                    "description": "Whether this is an exclusion range",
                                    "default": False
                                }
                            },
                            "required": ["from_ip"]
                        }
                    },
                    "fqdn": {
                        "type": "string",
                        "description": "New Fully Qualified Domain Name (optional)"
                    }
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
        types.Tool(
            name="delete-iplist",
            description="Delete an IP List from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to delete"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to delete (alternative to href)"
                    }
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
        types.Tool(
            name="update-ruleset",
            description="Update an existing ruleset in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to update"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the ruleset to update (alternative to href)"
                    },
                    "description": {
                        "type": "string",
                        "description": "New description for the ruleset"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether the ruleset is enabled"
                    },
                    "scopes": {
                        "type": "array",
                        "description": "New scopes for the ruleset",
                        "items": {
                            "type": "array",
                            "items": {
                                "oneOf": [
                                    {
                                        "type": "string",
                                        "description": "Label href or key=value string"
                                    },
                                    {
                                        "type": "object",
                                        "properties": {
                                            "href": {
                                                "type": "string",
                                                "description": "Label href"
                                            }
                                        },
                                        "required": ["href"]
                                    }
                                ]
                            }
                        }
                    }
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
        types.Tool(
            name="delete-ruleset",
            description="Delete a ruleset from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to delete"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the ruleset to delete (alternative to href)"
                    }
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
    elif name == "create-ruleset":
        logger.debug("=" * 80)
        logger.debug("CREATE RULESET CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            
            # populate the label maps
            label_href_map = {}
            value_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}
                value_href_map["{}={}".format(l.key, l.value)] = l.href

            # Check if ruleset already exists
            logger.debug(f"Checking if ruleset '{arguments['name']}' already exists...")
            existing_rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
            if existing_rulesets:
                error_msg = f"Ruleset with name '{arguments['name']}' already exists"
                logger.error(error_msg)
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": error_msg,
                        "existing_ruleset": {
                            "href": existing_rulesets[0].href,
                            "name": existing_rulesets[0].name
                        }
                    }, indent=2)
                )]

            # Create the ruleset
            logger.debug(f"Instantiating ruleset object: {arguments['name']}")
            ruleset = RuleSet(
                name=arguments["name"],
                description=arguments.get("description", "")
            )

            # Handle scopes
            label_sets = []
            if arguments.get("scopes"):
                logger.debug(f"Processing scopes: {json.dumps(arguments['scopes'], indent=2)}")
                
                for scope in arguments["scopes"]:
                    label_set = LabelSet(labels=[])
                    for label in scope:
                        logger.debug(f"Processing label: {label}")
                        if isinstance(label, dict) and "href" in label:
                            # Handle direct href references
                            logger.debug(f"Found label with href: {label['href']}")
                            append_label = pce.labels.get_by_reference(label["href"])
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)
                        elif isinstance(label, str):
                            # Handle string references (either href or label value)
                            if label in value_href_map:
                                logger.debug(f"Found label value: {value_href_map[label]}")
                                append_label = pce.labels.get_by_reference(value_href_map[label])
                            else:
                                logger.debug(f"Assuming direct href: {label}")
                                append_label = pce.labels.get_by_reference(label)
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)
                        else:
                            logger.warning(f"Unexpected label format: {label}")
                            continue
                            
                    label_sets.append(label_set)
                    logger.debug(f"Label set: {label_set}")
            else:
                # If no scopes provided, create a default scope with all workloads
                logger.debug("No scopes provided, creating default scope with all workloads")
                label_sets = [LabelSet(labels=[])]

            logger.debug(f"Final ruleset scopes count: {len(label_sets)}")
            ruleset.scopes = label_sets

            # Create the ruleset in PCE
            logger.debug("Creating ruleset in PCE...")
            logger.debug(f"Ruleset object scopes: {[str(ls.labels) for ls in ruleset.scopes]}")
            ruleset = pce.rule_sets.create(ruleset)
            logger.debug(f"Ruleset created with href: {ruleset.href}")

            # Create rules if provided
            created_rules = []
            if arguments.get("rules"):
                logger.debug(f"Processing rules: {json.dumps(arguments['rules'], indent=2)}")
                
                for rule_def in arguments["rules"]:
                    logger.debug(f"Processing rule: {json.dumps(rule_def, indent=2)}")
                    
                    # Process providers
                    providers = []
                    for provider in rule_def["providers"]:
                        if provider == "ams":
                            providers.append(AMS)
                        elif provider.startswith("iplist:"):
                            # Extract IP list name and look it up
                            ip_list_name = provider.split(":", 1)[1]
                            logger.debug(f"Looking up IP list: {ip_list_name}")
                            ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                            if ip_lists:
                                providers.append(ip_lists[0])
                            else:
                                logger.error(f"IP list not found: {ip_list_name}")
                                return [types.TextContent(
                                    type="text",
                                    text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                                )]
                        elif provider in value_href_map:
                            providers.append(pce.labels.get_by_reference(value_href_map[provider]))
                        else:
                            providers.append(pce.labels.get_by_reference(provider))
                    
                    # Process consumers
                    consumers = []
                    for consumer in rule_def["consumers"]:
                        if consumer == "ams":
                            consumers.append(AMS)
                        elif consumer.startswith("iplist:"):
                            # Extract IP list name and look it up
                            ip_list_name = consumer.split(":", 1)[1]
                            logger.debug(f"Looking up IP list: {ip_list_name}")
                            ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                            if ip_lists:
                                consumers.append(ip_lists[0])
                            else:
                                logger.error(f"IP list not found: {ip_list_name}")
                                return [types.TextContent(
                                    type="text",
                                    text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                                )]
                        elif consumer in value_href_map:
                            consumers.append(pce.labels.get_by_reference(value_href_map[consumer]))
                        else:
                            consumers.append(pce.labels.get_by_reference(consumer))
                    
                    # Create ingress services
                    ingress_services = []
                    for svc in rule_def["ingress_services"]:
                        service_port = ServicePort(
                            port=svc["port"],
                            proto=svc["proto"]
                        )
                        ingress_services.append(service_port)
                    
                    # Build and create the rule
                    rule = Rule.build(
                        providers=providers,
                        consumers=consumers,
                        ingress_services=ingress_services,
                        unscoped_consumers=rule_def.get("unscoped_consumers", False)
                    )
                    
                    created_rule = pce.rules.create(rule, parent=ruleset)
                    created_rules.append({
                        "href": created_rule.href,
                        "providers": [str(p) for p in providers],
                        "consumers": [str(c) for c in consumers],
                        "services": [f"{s.port}/{s.proto}" for s in ingress_services],
                        "unscoped_consumers": rule_def.get("unscoped_consumers", False)
                    })
            
            # Update the response to include rules
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "ruleset": {
                        "href": ruleset.href,
                        "name": ruleset.name,
                        "description": ruleset.description,
                        "rules": created_rules
                    }
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to create ruleset: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]

def to_dataframe(flows):
    pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
    pce.set_credentials(API_KEY, API_SECRET)

    label_href_map = {}
    value_href_map = {}
    for l in pce.labels.get(params={'max_results': 10000}):
        label_href_map[l.href] = {"key": l.key, "value": l.value}
        value_href_map["{}={}".format(l.key, l.value)] = l.href

    if not flows:
        logger.warning("Warning: Empty flows list received.")
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
            logger.debug(f"Error processing flow: {e}")
            logger.debug(f"Flow object: {flow}")

    df = pd.DataFrame(series_array)
    return df

def summarize_traffic(df):
    logger.debug(f"Summarizing traffic with dataframe: {df}")
    
    # Define all possible group columns
    potential_columns = ['src_app', 'src_env', 'dst_app', 'dst_env', 'proto', 'port']
    
    # Filter to only use columns that exist in the DataFrame
    group_columns = [col for col in potential_columns if col in df.columns]
    
    if not group_columns:
        logger.warning("No grouping columns found in DataFrame")
        return "No traffic data available for summarization"

    if df.empty:
        logger.warning("Empty DataFrame received")
        return "No traffic data available for summarization"

    logger.debug(f"Using group columns: {group_columns}")
    logger.debug(f"DataFrame shape before grouping: {df.shape}")
    logger.debug(f"DataFrame columns: {df.columns.tolist()}")
    logger.debug(f"First few rows of DataFrame:\n{df.head()}")

    # Group by available columns
    summary = df.groupby(group_columns)['num_connections'].sum().reset_index()
        
    logger.debug(f"Summary shape after grouping: {summary.shape}")
    logger.debug(f"Summary columns: {summary.columns.tolist()}")
    logger.debug(f"First few rows of summary:\n{summary.head()}")

    # Sort by number of connections in descending order
    summary = summary.sort_values('num_connections', ascending=False)

    # Convert to a more readable format
    summary_list = []
    for _, row in summary.iterrows():
        # Build source and destination info based on available columns
        src_info = []
        if 'src_app' in row:
            src_info.append(row['src_app'])
        if 'src_env' in row:
            src_info.append(f"({row['src_env']})")
        src_str = " ".join(src_info) if src_info else "Unknown Source"

        dst_info = []
        if 'dst_app' in row:
            dst_info.append(row['dst_app'])
        if 'dst_env' in row:
            dst_info.append(f"({row['dst_env']})")
        dst_str = " ".join(dst_info) if dst_info else "Unknown Destination"

        if src_str != dst_str:
            port_info = f"port {row['port']}" if 'port' in row else "unknown port"
            proto_info = f"proto {row['proto']}" if 'proto' in row else ""
            summary_list.append(
                f"From {src_str} to {dst_str} on {port_info} {proto_info}: {row['num_connections']} connections"
            )
    
    if not summary_list:
        return "No traffic patterns to summarize"
        
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

class ServicePortEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ServicePort):
            return {
                'port': obj.port,
                'protocol': obj.protocol
            }
        return super().default(obj)

if os.getenv('DOCKER_CONTAINER'):
    # Configure logging to write to a file in /var/log
    log_dir = '/var/log/illumio-mcp'
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        filename=f'{log_dir}/illumio-mcp.log',
        level=logging.INFO
    )