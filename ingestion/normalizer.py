import datetime

class LogNormalizer:
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