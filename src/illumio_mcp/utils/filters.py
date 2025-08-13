"""Filter utilities for Illumio MCP server"""
import pandas as pd
from ..core.logging import logger

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