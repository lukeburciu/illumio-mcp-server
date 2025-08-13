"""MCP prompt definitions for Illumio MCP server"""
from fastmcp import FastMCP
from ..tools.misc import get_notes

def register_prompts(mcp: FastMCP):
    """Register prompts with the MCP server"""
    
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
        notes = get_notes()
        
        if not notes:
            return "No notes available."
        
        summary = "Summary of notes:\n"
        for name, content in notes.items():
            if style == "detailed":
                summary += f"- {name}: {content}\n"
            else:
                summary += f"- {name}\n"
        
        return summary