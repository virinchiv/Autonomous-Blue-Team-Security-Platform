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
                return [self._parse_syslog(line) for line in f.readlines()]
        else:
            raise ValueError("Unsupported log format")

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