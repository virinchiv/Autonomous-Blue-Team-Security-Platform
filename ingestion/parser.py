import json
import pandas as pd
import re
from datetime import datetime

class LogParser:
    def load_file(self, filepath: str):
        if filepath.endswith('.json'):
            with open(filepath, "r") as f:
                return json.load(f)
        elif filepath.endswith('.csv'):
            df = pd.read_csv(filepath)
            return df.to_dict(orient="records")
        elif filepath.endswith(".log") or filepath.endswith(".txt"):
            with open(filepath, "r") as f:
                lines = f.readlines()
                # Check if this is a Zeek connection log by looking at the header
                if lines and 'id.orig_h' in lines[0] and 'id.resp_h' in lines[0]:
                    return self._parse_zeek_conn_log(lines)
                else:
                    return self._parse_log_lines(lines, filepath)
        else:
            raise ValueError("Unsupported log format")
    
    def _parse_log_lines(self, lines: list[str], filepath: str) -> list[dict]:
        """Parse log lines based on file type and content"""
        parsed_logs = []
        
        for line in lines:
            if not line.strip():
                continue
                
            # Try to detect log type and parse accordingly
            parsed_log = None
            
            # Check for Apache error log format
            if self._is_apache_error_log(line):
                parsed_log = self._parse_apache_error_log(line)
            # Check for Apache access log format (web server logs)
            elif self._is_apache_access_log(line):
                parsed_log = self._parse_apache_access_log(line)
            # Check for Linux syslog format
            elif self._is_linux_syslog(line):
                parsed_log = self._parse_linux_syslog(line)
            # Fallback to generic syslog parsing
            else:
                parsed_log = self._parse_syslog(line)
            
            if parsed_log:
                parsed_log['log_type'] = self._detect_log_type(line, filepath)
                parsed_logs.append(parsed_log)
        
        return parsed_logs
    
    def _parse_zeek_conn_log(self, lines: list[str]) -> list[dict]: 
        """Parses a list of lines from a Zeek conn.log file."""
        header = lines[0].strip().split('\t')
        parsed_logs = []
        for line in lines[1:]:
            if line.startswith("#") or not line.strip(): continue
            values = line.strip().split('\t')
            log_dict = dict(zip(header, values))
            for key in ['id.orig_p', 'id.resp_p', 'duration', 'orig_bytes', 'resp_bytes']:
                if log_dict.get(key) and log_dict[key] != '-':
                    log_dict[key] = float(log_dict[key])
                else:
                    log_dict[key] = 0
            log_dict['ts'] = float(log_dict['ts'])
            parsed_logs.append(log_dict)
        return parsed_logs


    def _is_apache_error_log(self, line: str) -> bool:
        """Check if line matches Apache error log format"""
        return bool(re.match(r'^\[.*?\] \[.*?\]', line))
    
    def _is_linux_syslog(self, line: str) -> bool:
        """Check if line matches Linux syslog format"""
        return bool(re.match(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+', line))
    
    def _is_apache_access_log(self, line: str) -> bool:
        """Check if line matches Apache access log format"""
        return bool(re.match(r'^\S+\s+\S+\s+\S+\s+\[.*?\]\s+"', line))
    
    def _detect_log_type(self, line: str, filepath: str) -> str:
        """Detect log type based on content and filename"""
        if 'apache' in filepath.lower():
            if self._is_apache_error_log(line):
                return 'apache_error'
            elif self._is_apache_access_log(line):
                return 'apache_access'
        elif 'access' in filepath.lower():
            if self._is_apache_access_log(line):
                return 'apache_access'
        elif 'linux' in filepath.lower() or 'auth' in filepath.lower():
            return 'linux_syslog'
        elif 'nginx' in filepath.lower():
            return 'nginx'
        else:
            return 'syslog'
    
    def _parse_apache_error_log(self, line: str) -> dict:
        """Parse Apache error log format: [timestamp] [level] message"""
        pattern = r'^\[(?P<timestamp>.*?)\]\s+\[(?P<level>\w+)\]\s+(?P<message>.*)$'
        match = re.match(pattern, line)
        if match:
            data = match.groupdict()
            try:
                # Parse Apache timestamp format: Thu Jun 09 06:07:04 2005
                timestamp = datetime.strptime(data['timestamp'], "%a %b %d %H:%M:%S %Y")
            except Exception:
                timestamp = None
            
            return {
                "timestamp": timestamp.isoformat() if timestamp else None,
                "level": data.get("level"),
                "message": data.get("message"),
                "raw": line.strip()
            }
        return {"raw": line.strip()}
    
    def _parse_linux_syslog(self, line: str) -> dict:
        """Parse Linux syslog format: timestamp host process[pid]: message"""
        pattern = (
            r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<process>[^\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
        )
        match = re.match(pattern, line)
        if match:
            data = match.groupdict()
            try:
                timestamp_str = f"{data['month']} {data['day']} {datetime.now().year} {data['time']}"
                timestamp = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
            except Exception:
                timestamp = None
            
            return {
                "timestamp": timestamp.isoformat() if timestamp else None,
                "host": data.get("host"),
                "process": data.get("process"),
                "pid": data.get("pid"),
                "message": data.get("message"),
                "raw": line.strip()
            }
        return {"raw": line.strip()}
    
    def _parse_apache_access_log(self, line: str) -> dict:
        """Parse Apache access log format (Combined Log Format)"""
        # Enhanced pattern to handle various Apache access log formats
        pattern = re.compile(
            r'(?P<ip_address>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] '
            r'"(?P<http_method>\S+) (?P<url>\S+) (?P<http_version>\S+)" (?P<status_code>\d{3}) '
            r'(?P<response_size>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
        )
        match = pattern.match(line)
        if match:
            data = match.groupdict()
            try:
                # Parse Apache access log timestamp: 22/Jan/2019:03:56:14 +0330
                timestamp = datetime.strptime(data['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
            except Exception:
                timestamp = None
            
            # Extract additional information from URL
            url = data.get("url", "")
            query_params = ""
            if "?" in url:
                url, query_params = url.split("?", 1)
            
            return {
                "timestamp": timestamp.isoformat() if timestamp else None,
                "ip_address": data.get("ip_address"),
                "http_method": data.get("http_method"),
                "url": url,
                "query_params": query_params,
                "http_version": data.get("http_version"),
                "status_code": int(data.get("status_code", 0)),
                "response_size": int(data.get("response_size", 0)),
                "referrer": data.get("referrer"),
                "user_agent": data.get("user_agent"),
                "raw": line.strip()
            }
        return {"raw": line.strip()}
    
    def _parse_syslog(self, line: str) -> dict:
        """Fallback syslog parser"""
        return {"raw": line.strip()}
    
    def parse_nginx_log(self, line: str) -> dict:
        """Parse Nginx combined log format"""
        pattern = re.compile(
            r'(?P<ip_address>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] '
            r'"(?P<http_method>\S+) (?P<url>\S+) \S+" (?P<status_code>\d{3}) '
            r'(?P<response_size>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
        )
        match = pattern.match(line)
        if match:
            data = match.groupdict()
            try:
                timestamp = datetime.strptime(data['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
            except Exception:
                timestamp = None
            
            return {
                "timestamp": timestamp.isoformat() if timestamp else None,
                "ip_address": data.get("ip_address"),
                "http_method": data.get("http_method"),
                "url": data.get("url"),
                "status_code": int(data.get("status_code", 0)),
                "response_size": int(data.get("response_size", 0)),
                "referrer": data.get("referrer"),
                "user_agent": data.get("user_agent"),
                "raw": line.strip()
            }
        return {"raw": line.strip()}

    def parse_auth_log(self, line: str) -> dict:
        """Parse authentication log format"""
        # SSH failed password pattern
        pattern = re.compile(
            r'.*sshd\[\d+\]: Failed password for (?P<invalid_user>invalid user )?(?P<user>\S+) '
            r'from (?P<source_ip>\S+) port \d+ ssh2'
        )
        match = pattern.match(line)
        if match:
            data = match.groupdict()
            return {
                "user": data.get("user"),
                "source_ip": data.get("source_ip"),
                "event_outcome": "failure",
                "raw": line.strip()
            }
        
        # SSH accepted password pattern
        pattern = re.compile(
            r'.*sshd\[\d+\]: Accepted password for (?P<user>\S+) from (?P<source_ip>\S+) port \d+ ssh2'
        )
        match = pattern.match(line)
        if match:
            data = match.groupdict()
            return {
                "user": data.get("user"),
                "source_ip": data.get("source_ip"),
                "event_outcome": "success",
                "raw": line.strip()
            }
        
        return {"raw": line.strip()}