import os
import sys
import json

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ingestion.parser import LogParser

def run_tests():
    parser = LogParser()
    base_path = "data"

    # JSON Test
    json_path = os.path.join(base_path, "sample_logs.json")
    if os.path.exists(json_path):
        logs = parser.load_file(json_path)
        print("\n--- JSON Logs ---")
        print(json.dumps(logs[:3], indent=2))  # show first 3
    else:
        print("[!] sample_logs.json not found in data/")

    # CSV Test
    csv_path = os.path.join(base_path, "sample_logs.csv")
    if os.path.exists(csv_path):
        logs = parser.load_file(csv_path)
        print("\n--- CSV Logs ---")
        print(json.dumps(logs[:3], indent=2))
    else:
        print("[!] sample_logs.csv not found in data/")

    # Syslog Test
    syslog_path = os.path.join(base_path, "sample_syslog.log")
    if os.path.exists(syslog_path):
        logs = parser.load_file(syslog_path)
        print("\n--- Syslog Logs ---")
        print(json.dumps(logs[:3], indent=2))
    else:
        print("[!] sample_syslog.log not found in data/")

if __name__ == "__main__":
    run_tests()
