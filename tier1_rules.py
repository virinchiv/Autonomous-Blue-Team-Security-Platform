# In a new file, e.g., tier1_rules.py
# High-confidence patterns for common, benign events.
# These will be ignored to reduce noise.
BENIGN_RULES = {
    "SSH Accepted Login": r"(?i)Accepted (password|publickey) for",
    "System Startup": r"(?i)systemd\[1\]: Started",
    "Cron Job Execution": r"CRON\[\d+\]: \(",
    "Successful Web Page Access": r"\"\s+200\s+",
    "Benign Bot User-Agent": r"(?i)(googlebot|bingbot|duckduckbot|yandexbot)",
    "System Shutdown/Reboot": r"(?i)systemd-logind.*: Powering Off|reboot: system reboot",
    "Legitimate Search Engine Bots": r"(?i)(googlebot|bingbot|duckduckbot|yandexbot|ahrefsbot|applebot|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot)",
    "Normal Image Requests": r"/image/\d+/product(Model|Type)/\d+x\d+",
    "Normal Product Pages": r"/product/\d+",
    "Normal Filter Requests": r"/filter/[a-zA-Z0-9,|%]+",
}

THREAT_RULES = {
    # --- Web Attack Patterns (to be matched against URL paths, queries, or message bodies) ---
    "SQL Injection Attempt": r"(?i)(\'|\"|\%27|\%22)\s*(union|select|--|or|and)\s*(\'|\"|\%27|\%22|1\s*=\s*1|true)",
    "Cross-Site Scripting (XSS) Attempt": r"(?i)(<|%3C)\s*script\s*(\s*src\s*=.*)?\s*(>|%3E)|onmouseover\s*=",
    "Directory Traversal Attempt": r"(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)",
    "Log4Shell (JNDI) Attempt": r"(?i)\$\{jndi:(ldap|rmi|dns|http)://",
    "Command Injection Attempt": r"(?i)(;|\%3B)\s*(ls|dir|cat|whoami|uname|pwd|wget|curl|nc|netcat)",
    "PHP File Inclusion Attempt": r"(?i)php://(filter|input|memory)",

    # --- Web Server Reconnaissance & Errors ---
    "Common Web Scanner User-Agent": r"(?i)(nmap|nikto|sqlmap|wfuzz|gobuster|dirbuster|feroxbuster|acunetix|nessus)",
    "Server-Side Request Forgery (SSRF) Hint": r"(?i)(url=|uri=|file=|path=|image_url=|template=|page=|redirect=|location=).*(http://|https://|ftp://|file://|gopher://|ldap://|dict://|sftp://|tftp://)",
    "PHP Error Signature": r"(?i)PHP\s+(Parse|Fatal)\s+error:",
    "Client Error (4xx)": r"\"\s+4\d{2}\s+",
    "Server Error (5xx)": r"\"\s+5\d{2}\s+",
    "Directory Index Forbidden": r"(?i)Directory index forbidden by rule",

    # --- Authentication & Brute-Force Patterns (primarily from auth.log) ---
    "SSH Failed Login": r"(?i)Failed (password|publickey) for",
    "SSH Invalid User": r"(?i)Invalid user \S+ from (?P<source_ip>\S+)",
    "SSH Root Login Failure": r"(?i)Failed password for root from",
    "SSH Accepted Login": r"(?i)Accepted (password|publickey) for",
    "Sudo Privilege Escalation": r"(?i)sudo:\s+\S+\s+:\s+USER=\S+\s+;\s+COMMAND=",
    "New User or Group Added": r"(?i)new user:|new group:",
    "Password Changed": r"(?i)password changed for",

    "Suspicious 404 Patterns": r"\"\s+404\s+.*(admin|wp-admin|phpmyadmin|\.env|config|backup)",
    "High-Volume 4xx Errors": r"\"\s+4\d{2}\s+.*(from same IP in short time)",  # Requires correlation
}