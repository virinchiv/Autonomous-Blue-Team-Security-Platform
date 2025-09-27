import os
import json
import re
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv

# Load environment variables from your .env file
load_dotenv()

groq_client = None
try:
    # Initialize the Groq client. It will automatically find the API key.
    groq_client = Groq()
except Exception:
    # Defer hard failure; we will provide a graceful fallback in analyze_log_with_llm
    groq_client = None

# Known legitimate bot patterns
LEGITIMATE_BOTS = [
    'googlebot', 'bingbot', 'duckduckbot', 'yandexbot', 'ahrefsbot', 
    'applebot', 'facebookexternalhit', 'twitterbot', 'linkedinbot', 
    'whatsapp', 'telegrambot', 'uptimerobot', 'semrushbot'
]

# Normal web request patterns
NORMAL_WEB_PATTERNS = [
    r'/image/\d+/product(Model|Type)/\d+x\d+',
    r'/product/\d+',
    r'/filter\?',                             # Filter WITH query params (simplified)
    r'/browse/',                              # Browse pages (simplified)
    r'/static/images/',                       # Static images (simplified)
    r'/settings/logo',
    r'/m/product/\d+',
    r'/m/filter/',
    r'/m/browse/',
    r'/article/\d+/',                         # Article pages
    r'/index',                                # Index pages
    r'/$'                                     # Root requests
]

def is_known_bot(user_agent: str) -> bool:
    """Check if the user agent is a known legitimate bot."""
    if not user_agent:
        return False
    user_agent_lower = user_agent.lower()
    return any(bot in user_agent_lower for bot in LEGITIMATE_BOTS)

def is_normal_web_request(log: dict) -> bool:
    """Check if the request matches normal web patterns."""
    url = log.get('url.original', '')
    status_code = log.get('http.response.status_code')
    
    # Check if it's a successful request (200, 301, 304) to normal endpoints
    if status_code in [200, 301, 302, 304]:
        for pattern in NORMAL_WEB_PATTERNS:
            if re.search(pattern, url):
                return True
    
    # Check for normal image requests with specific patterns
    if '/image/' in url and status_code in [200, 301, 302, 304]:
        return True
        
    return False

def is_normal_linux_syslog(log: dict) -> bool:
    """Check if the Linux syslog entry represents normal system activity."""
    log_source = log.get('log.source', '')
    message = log.get('message', '')
    process_name = log.get('process.name', '')
    
    # Only check Linux syslogs
    if log_source != 'linux_syslog':
        return False
    
    # Normal system sessions (cyrus, news users are system accounts)
    if re.search(r'(?i)session (opened|closed) for user (cyrus|news)', message):
        return True
    
    # Normal system services
    if re.search(r'(?i)(cupsd|syslogd).*(startup|shutdown|restart) succeeded', message):
        return True
    
    # Normal system processes
    if re.search(r'(?i)(logrotate|syslogd).*restart', message):
        return True
    
    # Normal FTP connections (not necessarily threats)
    if re.search(r'(?i)connection from.*at.*\d{4}', message):
        return True
    
    return False

def calculate_confidence_score(log: dict) -> float:
    """Calculate confidence score for whether this log needs LLM analysis."""
    score = 1.0  # Start with high confidence (low priority for LLM)
    log_source = log.get('log.source', '')
    
    # Handle Linux syslog entries
    if log_source == 'linux_syslog':
        # Reduce confidence for normal Linux syslog activity
        if is_normal_linux_syslog(log):
            score -= 0.9  # More aggressive reduction for normal system activity
        
        # Increase confidence for suspicious Linux syslog patterns
        message = log.get('message', '')
        process_name = log.get('process.name', '')
        
        # SSH authentication failures are high priority
        if 'authentication failure' in message.lower():
            score += 0.6
        
        # System alerts and abnormal exits
        if 'alert' in message.lower() and 'exited abnormally' in message.lower():
            score += 0.5
        
        # FTP timeouts and connection issues
        if 'timed out' in message.lower() or 'timeout' in message.lower():
            score += 0.4
        
        # Privilege escalation attempts
        if 'session opened for user' in message.lower() and 'uid=0' in message:
            score += 0.3
        
        # Multiple connection attempts from same source
        source_ip = log.get('source.ip', '')
        if source_ip and source_ip != 'unknown':
            score += 0.2  # Boost for having source IP information
        
        return max(0.0, min(1.0, score))  # Clamp between 0 and 1
    
    # Handle web logs (existing logic)
    # Reduce confidence if it's a known bot
    if is_known_bot(log.get('user_agent.original', '')):
        score -= 0.9  # More aggressive reduction for known bots
    
    # Reduce confidence if it's normal web traffic
    if is_normal_web_request(log):
        score -= 0.8  # More aggressive reduction for normal patterns
    
    # Reduce confidence for successful requests
    if log.get('http.response.status_code') == 200:
        score -= 0.4  # More aggressive reduction for successful requests
    
    # Increase confidence for error responses
    status_code = log.get('http.response.status_code', 0)
    if 400 <= status_code < 500:
        score += 0.2
    elif 500 <= status_code < 600:
        score += 0.4
    
    # Increase confidence for unusual user agents
    user_agent = log.get('user_agent.original', '').lower()
    if not user_agent or user_agent == '-':
        score += 0.3
    elif any(suspicious in user_agent for suspicious in ['scanner', 'crawler', 'bot']):
        if not is_known_bot(user_agent):
            score += 0.4
    
    # Increase confidence for unusual URLs
    url = log.get('url.original', '')
    if any(suspicious in url.lower() for suspicious in ['admin', 'wp-admin', 'phpmyadmin', '.env', 'config', 'backup']):
        score += 0.5
    
    # Special handling for SSRF rule - since it now only scans url.original, it's more reliable
    if any(ssrf_pattern in url.lower() for ssrf_pattern in ['http://', 'https://', 'ftp://', 'file://']):
        score += 0.3  # Boost confidence for SSRF patterns in actual URL
    
    return max(0.0, min(1.0, score))  # Clamp between 0 and 1

def should_escalate_to_llm(log: dict, confidence_threshold: float = 0.3) -> bool:
    """
    Determine if a log should be escalated to LLM analysis.
    Lowered threshold to 0.3 to catch more potential threats and minimize false negatives.
    """
    confidence = calculate_confidence_score(log)
    return confidence >= confidence_threshold

def analyze_log_with_llm(log_context: dict):
    """
    Analyzes an unclassified log document using a Groq LLM to provide a structured threat assessment.

    Args:
        log_context: A dictionary representing the structured (ECS-normalized) log.

    Returns:
        A dictionary containing the LLM's structured analysis with confidence score.
    """
    # Calculate confidence score for this log
    confidence_score = calculate_confidence_score(log_context)
    
    # Pre-filter: Skip LLM analysis for very low-confidence logs
    # Lowered threshold to 0.2 to minimize false negatives
    if confidence_score < 0.2:
        return {
            "classification": "Low Priority (Pre-filtered)",
            "hypothesis": "Log appears to be normal web traffic or legitimate bot activity.",
            "severity": "Informational",
            "recommended_action": "No action required - normal operation.",
            "confidence_score": confidence_score,
            "pre_filtered": True
        }
    
    # Create a clean, readable string from the log context for the prompt
    # This ensures even complex log structures are presented clearly.
    context_str = json.dumps(log_context, indent=2)

    prompt = f"""
    You are a senior security operations center (SOC) analyst.
    A log event, which could not be classified by standard rules, has been escalated to you for expert analysis.
    This log has a confidence score of {confidence_score:.2f}, indicating it may require attention.
    
    Your task is to analyze the log's context and provide a structured threat assessment.

    **Full Log Context (JSON):**
    ```json
    {context_str}
    ```

    **Your Analysis:**
    Based on the context, provide your response ONLY as a single, raw JSON object with the following keys:
    - "classification": A specific threat category (e.g., "Potential Brute-Force", "Web Application Anomaly", "Suspicious User Behavior", "Configuration Error", "Informational").
    - "hypothesis": A brief, one-sentence explanation of what you believe is happening.
    - "severity": Your assessment of the risk ("Low", "Medium", "High", "Informational").
    - "recommended_action": A concrete next step for an analyst (e.g., "Investigate source IP for further suspicious activity", "Verify system configuration", "Monitor user account for privilege escalation").
    - "confidence_assessment": Your confidence in this analysis ("Low", "Medium", "High").
    """

    if groq_client is None:
        # Graceful fallback when no API key/client available
        return {
            "classification": "Unclassified (No LLM)",
            "hypothesis": "LLM unavailable; manual review recommended.",
            "severity": "Informational",
            "recommended_action": "Set GROQ_API_KEY and rerun for deeper analysis.",
            "confidence_score": confidence_score,
            "pre_filtered": False
        }

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
            temperature=0.2,
            max_tokens=350,
            response_format={"type": "json_object"},
        )
        response_text = chat_completion.choices[0].message.content
        analysis = json.loads(response_text)
        # Add confidence score to the analysis
        analysis["confidence_score"] = confidence_score
        analysis["pre_filtered"] = False
        return analysis
    except Exception as e:
        print(f"An unexpected error occurred during Groq LLM analysis: {e}")
        return {
            "classification": "LLM Analysis Error",
            "hypothesis": "The model failed to produce a valid analysis.",
            "severity": "Low",
            "recommended_action": f"Check LLM API status and error logs. Error: {str(e)}",
            "confidence_score": confidence_score,
            "pre_filtered": False
        }

def generate_incident_report(incident_logs: list):
    """
    Generates a comprehensive security incident report for correlated Tier 3 anomalies.
    
    Args:
        incident_logs: A list of related log entries that form a security incident
        
    Returns:
        A dictionary containing the comprehensive incident analysis
    """
    if groq_client is None:
        return {
            "classification": "Incident Analysis Error",
            "executive_summary": "LLM unavailable for incident analysis.",
            "severity": "Informational",
            "recommended_action": "Set GROQ_API_KEY and rerun for comprehensive incident analysis."
        }
    
    # Prepare the log data for analysis
    log_summary = []
    for i, log in enumerate(incident_logs[:20]):  # Limit to first 20 logs to avoid token limits
        log_source = log.get('log.source', '')
        
        if log_source == 'linux_syslog':
            # Linux syslog specific fields
            log_entry = {
                "index": i + 1,
                "timestamp": log.get('@timestamp', 'N/A'),
                "source_ip": log.get('source.ip', 'N/A'),
                "host_name": log.get('host.name', 'N/A'),
                "process_name": log.get('process.name', 'N/A'),
                "process_pid": log.get('process.pid', 'N/A'),
                "event_category": log.get('event.category', 'N/A'),
                "event_type": log.get('event.type', 'N/A'),
                "event_outcome": log.get('event.outcome', 'N/A'),
                "user_name": log.get('user.name', 'N/A'),
                "message": log.get('message', 'N/A'),
                "raw": log.get('raw', 'N/A')
            }
        else:
            # Web log fields (existing logic)
            log_entry = {
                "index": i + 1,
                "timestamp": log.get('@timestamp', 'N/A'),
                "source_ip": log.get('source.ip', 'N/A'),
                "url": log.get('url.original', 'N/A'),
                "method": log.get('http.request.method', 'N/A'),
                "status_code": log.get('http.response.status_code', 'N/A'),
                "user_agent": log.get('user_agent.original', 'N/A'),
                "message": log.get('message', 'N/A')
            }
        log_summary.append(log_entry)
    
    # Create the comprehensive incident analysis prompt
    prompt = f"""
You are a Tier 3 Security Operations Center (SOC) Analyst. I have detected a correlated security incident involving {len(incident_logs)} related log entries. Your task is to analyze this group of related log entries and write a comprehensive security incident report.

The report must be in JSON format with the following structure:
{{
    "classification": "Specific incident type (e.g., 'Coordinated Web Scraping', 'Reconnaissance Activity', 'Automated Attack Campaign')",
    "executive_summary": "A brief, high-level summary of the incident (2-3 sentences)",
    "attacker_information": {{
        "source_ip": "Primary source IP address",
        "user_agent_analysis": "Analysis of the user agent and what it reveals about the attacker",
        "attack_vector": "How the attack was conducted"
    }},
    "attack_timeline": "A chronological summary of the attacker's actions with timestamps (MUST be a single text string, not an object)",
    "hypothesized_attacker_goal": "Based on the observed activity, what was the attacker likely trying to achieve?",
    "impact_assessment": "What is the potential impact of this activity on the business?",
    "severity": "High/Medium/Low based on the overall threat level",
    "recommended_remediation_steps": [
        "List of concrete, actionable steps to take",
        "Each step should be specific and implementable"
    ],
    "confidence_score": 0.85
}}

IMPORTANT: 
- attack_timeline must be a single text string, not an object or array
- recommended_remediation_steps must be an array of strings
- confidence_score must be a number between 0.0 and 1.0

Here are the correlated log entries for the incident:

{json.dumps(log_summary, indent=2)}

Analyze this incident comprehensively and provide a detailed security assessment.
"""

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
            temperature=0.1,  # Lower temperature for more consistent analysis
            max_tokens=800,   # Increased for comprehensive reports
            response_format={"type": "json_object"},
        )
        
        response_text = chat_completion.choices[0].message.content
        incident_analysis = json.loads(response_text)
        
        # Add metadata
        incident_analysis["incident_metadata"] = {
            "total_logs_analyzed": len(incident_logs),
            "analysis_timestamp": datetime.now().isoformat(),
            "source_ips": list(set(log.get('source.ip', 'unknown') for log in incident_logs)),
            "time_span": _calculate_incident_timespan(incident_logs)
        }
        
        return incident_analysis

    except Exception as e:
        print(f"An unexpected error occurred during incident analysis: {e}")
        return {
            "classification": "Incident Analysis Error",
            "executive_summary": "Failed to analyze the correlated incident.",
            "severity": "Low",
            "recommended_action": f"Check LLM API status and error logs. Error: {str(e)}"
        }

def _calculate_incident_timespan(logs):
    """Calculate the time span of an incident from the logs."""
    try:
        timestamps = []
        for log in logs:
            timestamp_str = log.get('@timestamp', '')
            if timestamp_str:
                # Parse timestamp
                if '+' in timestamp_str:
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    dt = datetime.fromisoformat(timestamp_str)
                timestamps.append(dt)
        
        if len(timestamps) >= 2:
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            return f"{time_span:.0f} seconds"
        else:
            return "Unknown"
    except:
        return "Unknown"

