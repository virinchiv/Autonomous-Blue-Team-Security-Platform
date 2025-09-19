import os
import json
import re
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

def calculate_confidence_score(log: dict) -> float:
    """Calculate confidence score for whether this log needs LLM analysis."""
    score = 1.0  # Start with high confidence (low priority for LLM)
    
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

def should_escalate_to_llm(log: dict, confidence_threshold: float = 0.5) -> bool:
    """Determine if a log should be escalated to LLM analysis."""
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
    
    # Pre-filter: Skip LLM analysis for low-confidence logs
    if confidence_score < 0.5:
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

