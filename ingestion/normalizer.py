import datetime
import pandas as pd 
import json

class LogNormalizer:
    def __init__(self):
        self.fields = [
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "label", "message"
        ]
    def normalize_unsw(self, df: pd.DataFrame):
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
    
    def save_processed(self, df: pd.DataFrame, outpath: str):
        df.to_json(outpath, orient="records", lines=True)
