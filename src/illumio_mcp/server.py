"""
Illumio MCP Server using FastMCP framework
"""
import os
import json
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from json import JSONEncoder

import dotenv
import pandas as pd
from fastmcp import FastMCP, Context
from illumio import *

# Custom JSON encoder for Illumio objects
class IllumioJSONEncoder(JSONEncoder):
    def default(self, obj):
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        elif isinstance(obj, list):
            return [self.default(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self.default(value) for key, value in obj.items()}
        else:
            return super().default(obj)

def setup_logging():
    """Configure logging based on environment"""
    logger = logging.getLogger('illumio_mcp')
    logger.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Determine log path based on environment
    if os.environ.get('DOCKER_CONTAINER'):
        log_path = Path('/var/log/illumio-mcp/illumio-mcp.log')
    else:
        # Use home directory for local logging
        log_path = './illumio-mcp.log'
    
    file_handler = logging.FileHandler(str(log_path))
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    
    # Prevent logs from propagating to root logger
    logger.propagate = False
    
    return logger

# Initialize logging
logger = setup_logging()
logger.debug("Loading environment variables")

# Load environment variables
dotenv.load_dotenv()

PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
READ_ONLY = os.getenv("READ_ONLY", "false").lower() in ["true", "1", "yes"]

MCP_BUG_MAX_RESULTS = 500

# Store notes as a simple key-value dict to demonstrate state management
notes: Dict[str, str] = {}

# Create FastMCP server instance
mcp = FastMCP("illumio-mcp")

if READ_ONLY:
    logger.info("Server running in READ-ONLY mode - all modifying operations are disabled")
else:
    logger.info("Server running in READ-WRITE mode")

# Note: Modifying operations are now controlled via @mcp.tool(enabled=not READ_ONLY)

def get_pce_connection():
    """Get a connected PCE instance"""
    pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
    pce.set_credentials(API_KEY, API_SECRET)
    return pce

# ========== PROMPTS ==========

@mcp.prompt
def ringfence_application(application_name: str, application_environment: str) -> str:
    """Ringfence an application by deploying rulesets to limit the inbound and outbound traffic"""
    return f"""
Ringfence the application {application_name} in the environment {application_environment}.
Always reference labels as hrefs like /orgs/1/labels/57 or similar.
Consumers means the source of the traffic, providers means the destination of the traffic.
First, retrieve all the traffic flows inside the application and environment. Analyze the connections. Then retrieve all the traffic flows inbound to the application and environment.
Inside the app, please be sure to have rules for each role or app tier to connect to the other tiers.  
Always use traffic flows to find out what other applications and environemnts need to connect into {application_name}, 
and then deploy rulesets to limit the inbound traffic to those applications and environments. 
For traffic that is required to connect outbound from {application_name}, deploy rulesets to limit the 
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

@mcp.prompt
def analyze_application_traffic(application_name: str, application_environment: str) -> str:
    """Analyze the traffic flows for an application and environment"""
    return f"""
Please provide the traffic flows for {application_name} in the environment {application_environment}.
Order by inbound and outbound traffic and app/env/role tupels.
Find other label types that are of interest and show them. Display your results in a react component. Show protocol, port and try to
understand the traffic flows (e.g. 5666/tcp likely could be nagios).
Categorize traffic into infrastructure and application traffic.
Find out if the application is internet facing or not.
Show illumio role labels, as well as application and environment labels in the output.
"""

@mcp.prompt
def summarize_notes(style: str = "brief") -> str:
    """Creates a summary of all notes"""
    if not notes:
        return "No notes available."
    
    summary = "Summary of notes:\n"
    for name, content in notes.items():
        if style == "detailed":
            summary += f"- {name}: {content}\n"
        else:
            summary += f"- {name}\n"
    
    return summary

# ========== TOOLS ==========

@mcp.tool(enabled=not READ_ONLY)
async def add_note(name: str, content: str) -> str:
    """Add a new note"""
    notes[name] = content
    return f"Note '{name}' added successfully"

@mcp.tool
async def check_pce_connection() -> str:
    """Check PCE connection status"""
    logger.debug("Checking PCE connection")
    try:
        pce = get_pce_connection()
        connection_status = pce.check_connection()
        logger.debug(f"PCE connection status: {connection_status}")
        return "PCE connection successful"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_workloads(name: str) -> str:
    """Get workloads from the PCE"""
    logger.debug("=" * 80)
    logger.debug("GET WORKLOADS CALLED")
    logger.debug(f"Arguments received: name={name}")
    logger.debug("=" * 80)
    
    try:
        pce = get_pce_connection()
        logger.debug("Fetching workloads from PCE")
        workloads = pce.workloads.get(params={"include": "labels", "max_results": 10000})
        logger.debug(f"Successfully retrieved {len(workloads)} workloads")
        return f"Workloads: {workloads}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_workloads_by_label(
    app: Optional[str] = None,
    env: Optional[str] = None,
    role: Optional[str] = None,
    loc: Optional[str] = None,
    max_results: int = 10000
) -> str:
    """Get workloads from the PCE filtered by label values"""
    logger.debug("=" * 80)
    logger.debug("GET WORKLOAD BY LABEL CALLED")
    logger.debug(f"Arguments received: app={app}, env={env}, role={role}, loc={loc}, max_results={max_results}")
    logger.debug("=" * 80)
    
    try:
        pce = get_pce_connection()
        logger.debug("Fetching workloads with label filters from PCE")
        
        # Build query parameters
        params = {"include": "labels", "max_results": max_results}
        
        # Get all labels first to find URIs for the specified values
        all_labels = pce.labels.get()
        label_uris = []
        
        # Find URIs for matching label values
        for label in all_labels:
            if hasattr(label, 'key') and hasattr(label, 'value') and hasattr(label, 'href'):
                if (app and label.key == 'app' and label.value == app) or \
                   (env and label.key == 'env' and label.value == env) or \
                   (role and label.key == 'role' and label.value == role) or \
                   (loc and label.key == 'loc' and label.value == loc):
                    label_uris.append(label.href)
        
        # Add labels parameter as JSON string if we found matching labels
        if label_uris:
            params["labels"] = json.dumps([label_uris])
        
        workloads = pce.workloads.get(params=params)
        
        # Handle different response types
        if hasattr(workloads, '__len__'):
            count = len(workloads)
            logger.debug(f"Successfully retrieved {count} workloads with label filters")
        else:
            logger.debug("Successfully retrieved workloads with label filters (count unknown)")
        
        # Use custom encoder for proper JSON serialization first
        encoder = IllumioJSONEncoder()
        workloads_json = encoder.encode(workloads)
        
        # Parse JSON and filter fields
        workloads_data = json.loads(workloads_json)
        filtered_workloads = filter_workload_fields(workloads_data)
        
        # Re-encode filtered data
        filtered_json = json.dumps(filtered_workloads)
        
        return f"Workloads: {filtered_json}"
        
    except AttributeError as e:
        error_msg = f"PCE API method not found: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"
    except ConnectionError as e:
        error_msg = f"PCE connection failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"
    except json.JSONDecodeError as e:
        error_msg = f"JSON parsing failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"
    except Exception as e:
        error_msg = f"PCE operation failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_labels() -> str:
    """Get all labels from PCE"""
    logger.debug("Getting labels from PCE")
    try:
        pce = get_pce_connection()
        resp = pce.get('/labels')
        labels = resp.json()
        return f"Labels: {labels}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_label(
    key: Optional[str] = None,
    value: Optional[str] = None
) -> str:
    """Get labels from PCE filtered by key and/or value. Value parameter supports partial matches."""
    logger.debug(f"Getting labels with filters - key: '{key}', value: '{value}'")
    try:
        pce = get_pce_connection()
        # Build query parameters as key:value pairs
        params = {}
        if key is not None and value is not None:
            params[key] = value  # Use the key parameter as the actual key
        elif value is not None:
            params["value"] = value  # Default to "value" key when only value provided

        # Make API call with filters
        if params:
            labels = pce.labels.get(params=params)
        else:
            labels = pce.labels.get()
            
        # Handle different response types
        if hasattr(labels, '__len__'):
            count = len(labels)
            logger.debug(f"Successfully retrieved {count} labels")
            # Format output based on data structure
            if isinstance(labels, list):
                return f"Found {count} labels: {labels}"
            else:
                return f"Labels ({count}): {labels}"
        else:
            logger.debug("Successfully retrieved labels (count unknown)")
            return f"Labels: {labels}"
            
    except AttributeError as e:
        error_msg = f"PCE API method not found: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"
    except ConnectionError as e:
        error_msg = f"PCE connection failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"
    except Exception as e:
        error_msg = f"PCE operation failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def create_label(key: str, value: str) -> str:
    """Create a label of a specific type and value in the PCE"""
    logger.debug(f"Creating label with key: {key} and value: {value}")
    try:
        pce = get_pce_connection()
        label = Label(key=key, value=value)
        label = pce.labels.create(label)
        logger.debug(f"Label created with status: {label}")
        return f"Label created with status: {label}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def delete_label(key: str, value: str) -> str:
    """Delete a label in the PCE"""
    logger.debug(f"Deleting label with key: {key} and value: {value}")
    try:
        pce = get_pce_connection()
        label = pce.labels.get(params={"key": key, "value": value})
        if label:
            pce.labels.delete(label[0])
            return f"Label deleted with status: {label}"
        else:
            return "Label not found"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def update_label(
    key: str,
    value: str,
    new_value: Optional[str] = None,
    new_key: Optional[str] = None
) -> str:
    """Update a label in the PCE - change key or value"""
    logger.debug(f"Updating label with key: {key} and value: {value}")
    try:
        pce = get_pce_connection()
        labels = pce.labels.get(params={"key": key, "value": value})
        
        if not labels:
            return "Label not found"
        
        label = labels[0]
        
        if new_value:
            label.value = new_value
        if new_key:
            label.key = new_key
        
        updated_label = pce.labels.update(label)
        logger.debug(f"Label updated: {updated_label}")
        return f"Label updated successfully: {updated_label}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def create_workload(
    name: str,
    ip_addresses: List[str],
    labels: List[Dict[str, str]] = None
) -> str:
    """Create an Illumio Core unmanaged workload in the PCE"""
    logger.debug(f"Creating workload with name: {name} and ip_addresses: {ip_addresses}")
    logger.debug(f"Labels: {labels}")
    
    try:
        pce = get_pce_connection()
        
        # Create interfaces
        interfaces = []
        for i, ip in enumerate(ip_addresses):
            intf = Interface(name=f"eth{i}", address=ip)
            interfaces.append(intf)
        
        # Process labels
        workload_labels = []
        if labels:
            for label in labels:
                logger.debug(f"Label: {label}")
                # Check if label already exists
                label_resp = pce.labels.get(params={"key": label['key'], "value": label['value']})
                if label_resp:
                    logger.debug(f"Label already exists: {label_resp}")
                    workload_label = label_resp[0]
                else:
                    logger.debug(f"Label does not exist, creating: {label}")
                    new_label = Label(key=label['key'], value=label['value'])
                    workload_label = pce.labels.create(new_label)
                
                workload_labels.append(workload_label)
        
        logger.debug(f"Labels: {workload_labels}")
        
        workload = Workload(
            name=name,
            interfaces=interfaces,
            labels=workload_labels,
            hostname=name
        )
        status = pce.workloads.create(workload)
        logger.debug(f"Workload creation status: {status}")
        return f"Workload created with status: {status}, workload: {workload}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def update_workload(
    name: str,
    ip_addresses: List[str],
    labels: List[Dict[str, str]] = None
) -> str:
    """Update a workload in the PCE"""
    logger.debug(f"Updating workload with name: {name} and ip_addresses: {ip_addresses}")
    logger.debug(f"Labels: {labels}")
    
    try:
        pce = get_pce_connection()
        
        workload = pce.workloads.get(params={"name": name})
        if not workload:
            return "Workload not found"
        
        workload = workload[0]
        logger.debug(f"Workload found: {workload}")
        
        # Update interfaces
        interfaces = []
        for i, ip in enumerate(ip_addresses):
            intf = Interface(name=f"eth{i}", address=ip)
            interfaces.append(intf)
        workload.interfaces = interfaces
        
        # Update labels if provided
        if labels:
            workload_labels = []
            for label in labels:
                label_resp = pce.labels.get(params={"key": label['key'], "value": label['value']})
                if label_resp:
                    workload_label = label_resp[0]
                else:
                    new_label = Label(key=label['key'], value=label['value'])
                    workload_label = pce.labels.create(new_label)
                workload_labels.append(workload_label)
            workload.labels = workload_labels
        
        status = pce.workloads.update(workload)
        logger.debug(f"Workload update status: {status}")
        return f"Workload updated with status: {status}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def delete_workload(name: str) -> str:
    """Delete a workload from the PCE"""
    logger.debug(f"Deleting workload with name: {name}")
    try:
        pce = get_pce_connection()
        workload = pce.workloads.get(params={"name": name})
        
        if not workload:
            return "Workload not found"
        
        pce.workloads.delete(workload[0])
        return f"Workload deleted: {workload[0]}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_services() -> str:
    """Get services from the PCE"""
    logger.debug("Getting services from PCE")
    try:
        pce = get_pce_connection()
        resp = pce.get('/sec_policy/draft/services')
        services = resp.json()
        
        # Custom encoding for complex objects
        encoder = IllumioJSONEncoder()
        services_json = encoder.encode(services)
        
        return f"Services: {services_json}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_rulesets(
    name: Optional[str] = None,
    enabled: Optional[bool] = None,
    scopes: Optional[List[List[Dict[str, str]]]] = None
) -> str:
    """Get rulesets from the PCE"""
    logger.debug(f"Getting rulesets with filters - name: {name}, enabled: {enabled}, scopes: {scopes}")
    
    try:
        pce = get_pce_connection()
        resp = pce.get('/sec_policy/draft/rule_sets')
        rulesets = resp.json()
        
        # Apply filters
        filtered_rulesets = rulesets
        if name:
            filtered_rulesets = [rs for rs in filtered_rulesets if name.lower() in rs.get('name', '').lower()]
        if enabled is not None:
            filtered_rulesets = [rs for rs in filtered_rulesets if rs.get('enabled') == enabled]
        if scopes:
            # Complex scope filtering would go here
            pass
        
        encoder = IllumioJSONEncoder()
        rulesets_json = encoder.encode(filtered_rulesets)
        
        return f"Rulesets: {rulesets_json}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def create_ruleset(
    name: str,
    scopes: List[List[Dict[str, str]]],
    rules: List[Dict[str, Any]],
    enabled: bool = True,
    description: Optional[str] = None
) -> str:
    """Create a ruleset in the PCE"""
    logger.debug(f"Creating ruleset: {name}")
    
    try:
        pce = get_pce_connection()
        
        # Build ruleset
        ruleset_data = {
            "name": name,
            "scopes": scopes,
            "enabled": enabled,
            "rules": rules
        }
        
        if description:
            ruleset_data["description"] = description
        
        resp = pce.post('/sec_policy/draft/rule_sets', json=ruleset_data)
        
        if resp.status_code == 201:
            created_ruleset = resp.json()
            return f"Ruleset created successfully: {created_ruleset}"
        else:
            return f"Failed to create ruleset: {resp.status_code} - {resp.text}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def update_ruleset(
    href: str,
    name: Optional[str] = None,
    scopes: Optional[List[List[Dict[str, str]]]] = None,
    rules: Optional[List[Dict[str, Any]]] = None,
    enabled: Optional[bool] = None,
    description: Optional[str] = None
) -> str:
    """Update a ruleset in the PCE"""
    logger.debug(f"Updating ruleset: {href}")
    
    try:
        pce = get_pce_connection()
        
        # Get current ruleset
        resp = pce.get(href)
        if resp.status_code != 200:
            return f"Ruleset not found: {href}"
        
        ruleset = resp.json()
        
        # Update fields
        if name is not None:
            ruleset['name'] = name
        if scopes is not None:
            ruleset['scopes'] = scopes
        if rules is not None:
            ruleset['rules'] = rules
        if enabled is not None:
            ruleset['enabled'] = enabled
        if description is not None:
            ruleset['description'] = description
        
        # Send update
        resp = pce.put(href, json=ruleset)
        
        if resp.status_code == 200:
            updated_ruleset = resp.json()
            return f"Ruleset updated successfully: {updated_ruleset}"
        else:
            return f"Failed to update ruleset: {resp.status_code} - {resp.text}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def delete_ruleset(href: Optional[str] = None, name: Optional[str] = None) -> str:
    """Delete a ruleset from the PCE"""
    logger.debug(f"Deleting ruleset - href: {href}, name: {name}")
    
    try:
        pce = get_pce_connection()
        
        if href:
            resp = pce.delete(href)
            if resp.status_code == 204:
                return f"Ruleset deleted successfully: {href}"
            else:
                return f"Failed to delete ruleset: {resp.status_code} - {resp.text}"
        elif name:
            # Find ruleset by name
            resp = pce.get('/sec_policy/draft/rule_sets')
            rulesets = resp.json()
            matching = [rs for rs in rulesets if rs.get('name') == name]
            
            if not matching:
                return f"Ruleset not found: {name}"
            
            ruleset = matching[0]
            resp = pce.delete(ruleset['href'])
            
            if resp.status_code == 204:
                return f"Ruleset deleted successfully: {name}"
            else:
                return f"Failed to delete ruleset: {resp.status_code} - {resp.text}"
        else:
            return "Either href or name must be provided"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_iplists(
    name: Optional[str] = None,
    description: Optional[str] = None,
    ip_ranges: Optional[List[Dict[str, str]]] = None,
    fqdn: Optional[str] = None
) -> str:
    """Get IP lists from the PCE"""
    logger.debug(f"Getting IP lists with filters - name: {name}")
    
    try:
        pce = get_pce_connection()
        resp = pce.get('/sec_policy/draft/ip_lists')
        iplists = resp.json()
        
        # Apply filters
        filtered_iplists = iplists
        if name:
            filtered_iplists = [ipl for ipl in filtered_iplists if name.lower() in ipl.get('name', '').lower()]
        if description:
            filtered_iplists = [ipl for ipl in filtered_iplists if description.lower() in ipl.get('description', '').lower()]
        
        encoder = IllumioJSONEncoder()
        iplists_json = encoder.encode(filtered_iplists)
        
        return f"IP Lists: {iplists_json}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def create_iplist(
    name: str,
    ip_ranges: Optional[List[Dict[str, str]]] = None,
    fqdn: Optional[str] = None,
    description: Optional[str] = None
) -> str:
    """Create an IP list in the PCE"""
    logger.debug(f"Creating IP list: {name}")
    
    try:
        pce = get_pce_connection()
        
        iplist_data = {"name": name}
        
        if ip_ranges:
            iplist_data["ip_ranges"] = ip_ranges
        if fqdn:
            iplist_data["fqdn"] = fqdn
        if description:
            iplist_data["description"] = description
        
        resp = pce.post('/sec_policy/draft/ip_lists', json=iplist_data)
        
        if resp.status_code == 201:
            created_iplist = resp.json()
            return f"IP List created successfully: {created_iplist}"
        else:
            return f"Failed to create IP list: {resp.status_code} - {resp.text}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def update_iplist(
    href: str,
    name: Optional[str] = None,
    ip_ranges: Optional[List[Dict[str, str]]] = None,
    fqdn: Optional[str] = None,
    description: Optional[str] = None
) -> str:
    """Update an IP list in the PCE"""
    logger.debug(f"Updating IP list: {href}")
    
    try:
        pce = get_pce_connection()
        
        # Get current IP list
        resp = pce.get(href)
        if resp.status_code != 200:
            return f"IP list not found: {href}"
        
        iplist = resp.json()
        
        # Update fields
        if name is not None:
            iplist['name'] = name
        if ip_ranges is not None:
            iplist['ip_ranges'] = ip_ranges
        if fqdn is not None:
            iplist['fqdn'] = fqdn
        if description is not None:
            iplist['description'] = description
        
        # Send update
        resp = pce.put(href, json=iplist)
        
        if resp.status_code == 200:
            updated_iplist = resp.json()
            return f"IP List updated successfully: {updated_iplist}"
        else:
            return f"Failed to update IP list: {resp.status_code} - {resp.text}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool(enabled=not READ_ONLY)
async def delete_iplist(href: str) -> str:
    """Delete an IP list from the PCE"""
    logger.debug(f"Deleting IP list: {href}")
    
    try:
        pce = get_pce_connection()
        
        resp = pce.delete(href)
        if resp.status_code == 204:
            return f"IP List deleted successfully: {href}"
        else:
            return f"Failed to delete IP list: {resp.status_code} - {resp.text}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    max_results: int = 100
) -> str:
    """Get events from the PCE"""
    logger.debug(f"Getting events - type: {event_type}, severity: {severity}, status: {status}")
    
    try:
        pce = get_pce_connection()
        
        params = {"max_results": max_results}
        if event_type:
            params["event_type"] = event_type
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        
        resp = pce.get('/events', params=params)
        events = resp.json()
        
        encoder = IllumioJSONEncoder()
        events_json = encoder.encode(events)
        
        return f"Events: {events_json}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

# Helper functions for traffic analysis
def filter_workload_fields(workloads):
    """Filter workload objects to include only essential and useful fields"""
    if not isinstance(workloads, list):
        workloads = [workloads]
    
    filtered_workloads = []
    for workload in workloads:
        if hasattr(workload, '__dict__'):
            workload_dict = workload.__dict__
        else:
            workload_dict = workload
        
        # Essential fields
        filtered = {
            'href': workload_dict.get('href'),
            'name': workload_dict.get('name'),
            'hostname': workload_dict.get('hostname'),
            'interfaces': workload_dict.get('interfaces'),
            'labels': workload_dict.get('labels'),
            'online': workload_dict.get('online'),
            'enforcement_mode': workload_dict.get('enforcement_mode')
        }
        
        # Useful fields
        filtered.update({
            'managed': workload_dict.get('managed'),
            'created_at': workload_dict.get('created_at'),
            'updated_at': workload_dict.get('updated_at'),
            'description': workload_dict.get('description'),
            'os_id': workload_dict.get('os_id'),
            'os_detail': workload_dict.get('os_detail')
        })
        
        # Agent info (if managed)
        if workload_dict.get('agent') and workload_dict.get('managed'):
            agent = workload_dict.get('agent', {})
            status = agent.get('status', {})
            filtered['agent'] = {
                'version': status.get('agent_version'),
                'last_heartbeat': status.get('last_heartbeat_on')
            }
        
        # Services (open ports for security analysis)
        services = workload_dict.get('services', {})
        if services and services.get('open_service_ports'):
            filtered['open_service_ports'] = services.get('open_service_ports')
        
        filtered_workloads.append(filtered)
    
    return filtered_workloads

def to_dataframe(flows):
    """Convert traffic flows to pandas DataFrame"""
    logger.debug(f"Converting {len(flows)} flows to DataFrame")
    
    data = []
    for flow in flows:
        row = {
            'src_ip': flow.get('src', {}).get('ip'),
            'src_hostname': flow.get('src', {}).get('hostname'),
            'src_app': None,
            'src_env': None,
            'src_loc': None,
            'src_role': None,
            'dst_ip': flow.get('dst', {}).get('ip'),
            'dst_hostname': flow.get('dst', {}).get('hostname'),
            'dst_app': None,
            'dst_env': None,
            'dst_loc': None,
            'dst_role': None,
            'service_name': flow.get('service', {}).get('name'),
            'service_port': flow.get('service', {}).get('port'),
            'service_proto': flow.get('service', {}).get('proto'),
            'policy_decision': flow.get('policy_decision'),
            'num_connections': flow.get('num_connections'),
            'timestamp': flow.get('timestamp_range', {}).get('last_detected')
        }
        
        # Extract source labels
        if 'labels' in flow.get('src', {}):
            for label in flow['src']['labels']:
                if label[0] == 'app':
                    row['src_app'] = label[1]
                elif label[0] == 'env':
                    row['src_env'] = label[1]
                elif label[0] == 'loc':
                    row['src_loc'] = label[1]
                elif label[0] == 'role':
                    row['src_role'] = label[1]
        
        # Extract destination labels
        if 'labels' in flow.get('dst', {}):
            for label in flow['dst']['labels']:
                if label[0] == 'app':
                    row['dst_app'] = label[1]
                elif label[0] == 'env':
                    row['dst_env'] = label[1]
                elif label[0] == 'loc':
                    row['dst_loc'] = label[1]
                elif label[0] == 'role':
                    row['dst_role'] = label[1]
        
        data.append(row)
    
    df = pd.DataFrame(data)
    logger.debug(f"Created DataFrame with shape: {df.shape}")
    return df

def summarize_traffic(df):
    """Summarize traffic patterns from DataFrame"""
    logger.debug("Summarizing traffic patterns")
    
    summary = {
        'total_flows': len(df),
        'unique_sources': df['src_ip'].nunique(),
        'unique_destinations': df['dst_ip'].nunique(),
        'unique_services': df[['service_port', 'service_proto']].drop_duplicates().shape[0],
        'policy_decisions': df['policy_decision'].value_counts().to_dict() if 'policy_decision' in df else {},
        'top_sources': df.groupby(['src_app', 'src_env', 'src_role'])['num_connections'].sum().nlargest(10).to_dict(),
        'top_destinations': df.groupby(['dst_app', 'dst_env', 'dst_role'])['num_connections'].sum().nlargest(10).to_dict(),
        'top_services': df.groupby(['service_port', 'service_proto'])['num_connections'].sum().nlargest(10).to_dict()
    }
    
    # Time-based analysis if timestamp available
    if 'timestamp' in df.columns and not df['timestamp'].isna().all():
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        summary['time_range'] = {
            'start': df['timestamp'].min().isoformat() if not df['timestamp'].isna().all() else None,
            'end': df['timestamp'].max().isoformat() if not df['timestamp'].isna().all() else None
        }
    
    return summary

@mcp.tool
async def get_traffic_flows(
    sources_include: Optional[List[List[Dict[str, str]]]] = None,
    sources_exclude: Optional[List[List[Dict[str, str]]]] = None,
    destinations_include: Optional[List[List[Dict[str, str]]]] = None,
    destinations_exclude: Optional[List[List[Dict[str, str]]]] = None,
    services_include: Optional[List[Dict[str, Any]]] = None,
    services_exclude: Optional[List[Dict[str, Any]]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    policy_decisions: Optional[List[str]] = None,
    max_results: int = MCP_BUG_MAX_RESULTS
) -> str:
    """Get traffic flows from the PCE with advanced filtering"""
    logger.debug("Getting traffic flows from PCE")
    logger.debug(f"Filters - sources_include: {sources_include}, destinations_include: {destinations_include}")
    
    try:
        pce = get_pce_connection()
        
        # Build query parameters
        query_params = {
            "max_results": min(max_results, MCP_BUG_MAX_RESULTS)
        }
        
        # Add filters to query
        filters = {}
        if sources_include:
            filters["sources_include"] = sources_include
        if sources_exclude:
            filters["sources_exclude"] = sources_exclude
        if destinations_include:
            filters["destinations_include"] = destinations_include
        if destinations_exclude:
            filters["destinations_exclude"] = destinations_exclude
        if services_include:
            filters["services_include"] = services_include
        if services_exclude:
            filters["services_exclude"] = services_exclude
        if policy_decisions:
            filters["policy_decisions"] = policy_decisions
        
        if start_date or end_date:
            filters["timestamp_range"] = {}
            if start_date:
                filters["timestamp_range"]["first_detected"] = start_date
            if end_date:
                filters["timestamp_range"]["last_detected"] = end_date
        
        # Make API call
        resp = pce.post('/traffic_flows/traffic_analysis_queries', json=filters)
        
        if resp.status_code == 201:
            query_href = resp.headers.get('Location')
            
            # Poll for results
            max_attempts = 30
            for _ in range(max_attempts):
                result_resp = pce.get(query_href)
                if result_resp.status_code == 200:
                    result = result_resp.json()
                    if result.get('status') == 'completed':
                        flows = result.get('result', [])
                        logger.debug(f"Retrieved {len(flows)} traffic flows")
                        
                        encoder = IllumioJSONEncoder()
                        flows_json = encoder.encode(flows)
                        return f"Traffic flows: {flows_json}"
                    elif result.get('status') == 'failed':
                        return f"Query failed: {result.get('error', 'Unknown error')}"
                
                await asyncio.sleep(1)
            
            return "Query timeout - results not ready"
        else:
            return f"Failed to create traffic query: {resp.status_code} - {resp.text}"
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

@mcp.tool
async def get_traffic_flows_summary(
    sources_include: Optional[List[List[Dict[str, str]]]] = None,
    sources_exclude: Optional[List[List[Dict[str, str]]]] = None,
    destinations_include: Optional[List[List[Dict[str, str]]]] = None,
    destinations_exclude: Optional[List[List[Dict[str, str]]]] = None,
    services_include: Optional[List[Dict[str, Any]]] = None,
    services_exclude: Optional[List[Dict[str, Any]]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    policy_decisions: Optional[List[str]] = None,
    max_results: int = MCP_BUG_MAX_RESULTS
) -> str:
    """Get summarized traffic flows from the PCE"""
    logger.debug("Getting traffic flows summary from PCE")
    
    try:
        # Get the raw traffic flows first
        flows_result = await get_traffic_flows(
            sources_include=sources_include,
            sources_exclude=sources_exclude,
            destinations_include=destinations_include,
            destinations_exclude=destinations_exclude,
            services_include=services_include,
            services_exclude=services_exclude,
            start_date=start_date,
            end_date=end_date,
            policy_decisions=policy_decisions,
            max_results=max_results
        )
        
        # Extract flows from result
        if flows_result.startswith("Error:"):
            return flows_result
        
        # Parse the flows
        flows_str = flows_result.replace("Traffic flows: ", "")
        flows = json.loads(flows_str)
        
        # Convert to DataFrame and summarize
        df = to_dataframe(flows)
        summary = summarize_traffic(df)
        
        encoder = IllumioJSONEncoder()
        summary_json = encoder.encode(summary)
        
        return f"Traffic summary: {summary_json}"
    except Exception as e:
        error_msg = f"Failed to summarize traffic: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

# Main entry point
def main():
    """Main entry point for the MCP server"""
    logger.info("Starting Illumio MCP server with FastMCP")
    mcp.run()

if __name__ == "__main__":
    main()