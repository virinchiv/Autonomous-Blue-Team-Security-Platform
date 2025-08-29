import json
import pandas as pd
import re
from datetime import datetime

class LogParser:
    def load_file(self, filepath:str):
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
                    return [self._parse_syslog(line) for line in lines]
        else:
            raise ValueError("Unsupported log format")
    
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


    def _parse_syslog(self, line: str): 
        syslog_pattern = (
            r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<process>[^\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
        )
        match = re.match(syslog_pattern, line)
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
                "message": data.get("message")
            }
        
        return {"raw": line.strip()}