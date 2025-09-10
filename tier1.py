

# In a new file, e.g., tier1_rules.py
REGEX_RULES = {
    "SSH Brute-Force Failure": r"Failed password for .* from (?P<source_ip>\S+)",
    "SQL Injection Attempt": r"(\'|\%27)\s*(union|select|--|or|and)\s*(\'|\%27|1|true)",
    "XSS Attempt": r"(<|%3C)\s*script\s*(>|%3E)",
    "Directory Traversal": r"\.\.\/|\.\.\\",
    "Common Web Scanner": r"(nmap|nikto|sqlmap|wfuzz)" # Check in user_agent field
}