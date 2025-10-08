import datetime
import pandas as pd 
import json
from datetime import datetime

class LogNormalizer:
    def __init__(self):
        self.fields = [
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "label", "message"
        ]
    
    def normalize_unsw(self, df: pd.DataFrame):
        """Normalize UNSW-NB15 dataset"""
        # UNSW-NB15 has specific column names
        df = df.rename(columns={
            "srcip": "src_ip",
            "sport": "src_port",
            "dstip": "dst_ip",
            "dsport": "dst_port",
            "proto": "protocol",
            "attack_cat": "label"
        })
        df["timestamp"] = pd.to_datetime("now")  # dataset has no timestamp
        df["message"] = df["label"].apply(lambda x: f"Attack: {x}" if x != "Normal" else "Benign traffic")
        return df[self.fields]
    
    def normalize(self, logs):
        """Legacy normalize method for backward compatibility"""
        normalized = []
        for log in logs:
            normalized.append({
                "timestamp": log.get("timestamp", str(datetime.datetime.utcnow())),
                "source_ip": log.get("src_ip", None),
                "destination_ip": log.get("dst_ip", None),
                "event": log.get("event", log.get("message", "unknown")),
                "raw": log
            })
        return normalized
    
    def normalize_to_ecs(self, parsed_log, log_type):
        """Normalize parsed log to Elastic Common Schema (ECS) format"""
        ecs_log = {}
        
        # Common fields
        ecs_log['@timestamp'] = parsed_log.get('timestamp', datetime.now().isoformat())
        ecs_log['log.source'] = log_type
        ecs_log['message'] = parsed_log.get('message', parsed_log.get('raw', ''))
        
        # Log type specific normalization
        if log_type == 'apache_error' and parsed_log:
            ecs_log['log.level'] = parsed_log.get('level', 'unknown')
            ecs_log['event.category'] = 'web'
            ecs_log['event.type'] = 'error'
            ecs_log['event.outcome'] = 'failure'
            
        elif log_type == 'apache_access' and parsed_log:
            ecs_log['source.ip'] = parsed_log.get('ip_address')
            ecs_log['http.request.method'] = parsed_log.get('http_method')
            ecs_log['url.original'] = parsed_log.get('url')
            ecs_log['url.query'] = parsed_log.get('query_params')
            ecs_log['http.version'] = parsed_log.get('http_version')
            ecs_log['http.response.status_code'] = parsed_log.get('status_code')
            ecs_log['http.response.body.bytes'] = parsed_log.get('response_size')
            ecs_log['http.request.referrer'] = parsed_log.get('referrer')
            ecs_log['user_agent.original'] = parsed_log.get('user_agent')
            ecs_log['event.category'] = 'web'
            ecs_log['event.type'] = 'access'
            
            # Determine outcome based on status code
            status_code = parsed_log.get('status_code', 0)
            if status_code < 400:
                ecs_log['event.outcome'] = 'success'
            else:
                ecs_log['event.outcome'] = 'failure'
            
            # Add security-related fields for access logs
            url = parsed_log.get('url', '').lower()
            query_params = parsed_log.get('query_params', '').lower()
            user_agent = parsed_log.get('user_agent', '').lower()
            
            # Detect potential security issues
            security_flags = []
            if any(pattern in url or pattern in query_params for pattern in ['../', '..\\', '/etc/', 'system32']):
                security_flags.append('path_traversal')
            if any(pattern in query_params for pattern in ['union select', 'drop table', 'select password', 'or 1=1']):
                security_flags.append('sql_injection')
            if any(pattern in query_params for pattern in ['<script>', 'javascript:', 'alert(']):
                security_flags.append('xss')
            if any(pattern in user_agent for pattern in ['bot', 'crawler', 'spider', 'scanner']):
                security_flags.append('bot_traffic')
            if status_code in [401, 403]:
                security_flags.append('unauthorized_access')
            if status_code in [404, 500]:
                security_flags.append('error_response')
            
            if security_flags:
                ecs_log['security.flags'] = security_flags
                ecs_log['event.category'] = 'security'
                ecs_log['event.type'] = 'threat'
                
        elif log_type == 'linux_syslog' and parsed_log:
            ecs_log['host.name'] = parsed_log.get('host')
            ecs_log['process.name'] = parsed_log.get('process')
            ecs_log['process.pid'] = parsed_log.get('pid')
            ecs_log['event.category'] = 'system'
            ecs_log['event.type'] = 'log'
            
            # Check for authentication events
            message = parsed_log.get('message', '').lower()
            if 'authentication failure' in message or 'failed password' in message:
                ecs_log['event.category'] = 'authentication'
                ecs_log['event.type'] = 'authentication_failure'
                ecs_log['event.outcome'] = 'failure'
                
                # Extract user and source IP from message
                import re
                user_match = re.search(r'user=(\S+)', message)
                if user_match:
                    ecs_log['user.name'] = user_match.group(1)
                    
                rhost_match = re.search(r'rhost=(\S+)', message)
                if rhost_match:
                    ecs_log['source.ip'] = rhost_match.group(1)
                    
            elif 'accepted password' in message:
                ecs_log['event.category'] = 'authentication'
                ecs_log['event.type'] = 'authentication_success'
                ecs_log['event.outcome'] = 'success'
                
        elif log_type == 'nginx' and parsed_log:
            ecs_log['source.ip'] = parsed_log.get('ip_address')
            ecs_log['http.request.method'] = parsed_log.get('http_method')
            ecs_log['url.original'] = parsed_log.get('url')
            ecs_log['http.response.status_code'] = parsed_log.get('status_code')
            ecs_log['http.response.body.bytes'] = parsed_log.get('response_size')
            ecs_log['http.request.referrer'] = parsed_log.get('referrer')
            ecs_log['user_agent.original'] = parsed_log.get('user_agent')
            ecs_log['event.category'] = 'web'
            ecs_log['event.outcome'] = 'success' if ecs_log.get('http.response.status_code', 0) < 400 else 'failure'
            
        elif log_type == 'auth' and parsed_log:
            ecs_log['source.ip'] = parsed_log.get('source_ip')
            ecs_log['user.name'] = parsed_log.get('user')
            ecs_log['event.category'] = 'authentication'
            ecs_log['event.action'] = 'authentication_failure'
            ecs_log['event.outcome'] = parsed_log.get('event_outcome')
        
        # Add raw log for reference
        ecs_log['raw'] = parsed_log.get('raw', '')
        
        return ecs_log
    
    def normalize_logs_to_ecs(self, parsed_logs):
        """Normalize a list of parsed logs to ECS format"""
        ecs_logs = []
        for log in parsed_logs:
            log_type = log.get('log_type', 'unknown')
            ecs_log = self.normalize_to_ecs(log, log_type)
            ecs_logs.append(ecs_log)
        return ecs_logs
    
    def save_processed(self, df: pd.DataFrame, outpath: str):
        """Save processed DataFrame to JSON"""
        df.to_json(outpath, orient="records", lines=True)
    
    def save_ecs_logs(self, ecs_logs, outpath: str):
        """Save ECS normalized logs to JSON"""
        # Ensure the normalized_logs directory exists
        import os
        os.makedirs('normalized_logs', exist_ok=True)
        
        # If outpath doesn't include normalized_logs directory, add it
        if not outpath.startswith('normalized_logs/'):
            filename = os.path.basename(outpath)
            outpath = f'normalized_logs/{filename}'
        
        with open(outpath, 'w') as f:
            for log in ecs_logs:
                f.write(json.dumps(log) + '\n')
