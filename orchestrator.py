from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import os
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
# --- Import your custom modules ---
from tier1_rules import THREAT_RULES, BENIGN_RULES
from tier3_llm import analyze_log_with_llm, should_escalate_to_llm, calculate_confidence_score, generate_incident_report

# --- Configuration ---
# Elasticsearch Configuration
ELASTICSEARCH_HOST = "http://localhost:9200"
UNIFIED_LOGS_INDEX = "unified-logs"
INCIDENTS_INDEX = "aion-incidents"
BATCH_SIZE = 1000
LOOP_DELAY_SECONDS = 30

# Legacy file-based configuration (for fallback)
LOG_DIRECTORY = "normalized_logs"
FILES_TO_PROCESS = [
    "output_linux-2k.log_ecs.json",
]
REPORT_FILENAME = "security_intelligence_report2.md"

# --- Alert Correlation Configuration ---
TIME_WINDOW_SECONDS = 300  # 5-minute correlation window
CORRELATION_THRESHOLDS = {
    "Client Error (4xx)": 20,  # Alert after 20+ 4xx errors from same IP
    "Server Error (5xx)": 5,   # Alert after 5+ 5xx errors from same IP
    "Directory Traversal Attempt": 3,  # Alert after 3+ attempts
    "SSH Failed Login": 10,    # Alert after 10+ failed SSH attempts
    "Common Web Scanner User-Agent": 5,  # Alert after 5+ scanner requests
    
    # Linux Syslog Correlation Thresholds
    "SSH Authentication Failure": 5,     # Alert after 5+ SSH auth failures from same IP
    "SSH Check Pass User Unknown": 3,    # Alert after 3+ unknown user attempts
    "FTP User Timeout": 2,               # Alert after 2+ FTP timeouts
    "System Alert Abnormal Exit": 1,     # Alert immediately on system alerts
    "Suspicious User Session": 2,        # Alert after 2+ suspicious sessions
    "Multiple SSH Failures": 3,          # Alert after 3+ SSH failures to root
    "FTP Connection Flood": 10,          # Alert after 10+ FTP connections from same IP
    "System Service Failure": 1,         # Alert immediately on service failures
    "Privilege Escalation Attempt": 1,   # Alert immediately on privilege escalation
    "Suspicious Process Activity": 1,    # Alert immediately on suspicious process activity
}

# --- Tier 3 Correlation Configuration ---
TIER3_CORRELATION_THRESHOLD = 5   # Minimum logs to create a Tier 3 incident
TIER3_TIME_WINDOW_SECONDS = 1800  # 30-minute window for Tier 3 correlation

# --- Core Orchestrator Functions ---

def initialize_elasticsearch():
    """Initialize Elasticsearch client and verify connection."""
    try:
        es_client = Elasticsearch([ELASTICSEARCH_HOST], request_timeout=30)
        
        # Test connection
        if es_client.ping():
            print(f"✅ Connected to Elasticsearch at {ELASTICSEARCH_HOST}")
            
            # Check if unified-logs index exists
            if es_client.indices.exists(index=UNIFIED_LOGS_INDEX):
                print(f"✅ Found index: {UNIFIED_LOGS_INDEX}")
            else:
                print(f"⚠️  Index {UNIFIED_LOGS_INDEX} does not exist. Will create it when needed.")
            
            # Ensure incidents index exists
            create_incidents_index(es_client)
            
            return es_client
        else:
            print(f"❌ Failed to connect to Elasticsearch at {ELASTICSEARCH_HOST}")
            return None
    except Exception as e:
        print(f"❌ Error initializing Elasticsearch: {e}")
        return None

def create_incidents_index(es_client):
    """Create the incidents index with proper mapping if it doesn't exist."""
    if not es_client.indices.exists(index=INCIDENTS_INDEX):
        mapping = {
            "mappings": {
                "properties": {
                    "incident_id": {"type": "keyword"},
                    "title": {"type": "text"},
                    "summary": {"type": "text"},
                    "severity": {"type": "keyword"},
                    "classification": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "attacker_information": {"type": "object"},
                    "attack_timeline": {"type": "text"},
                    "hypothesized_attacker_goal": {"type": "text"},
                    "impact_assessment": {"type": "text"},
                    "recommended_remediation_steps": {"type": "text"},
                    "confidence_score": {"type": "float"},
                    "log_ids": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                    "status": {"type": "keyword"}
                }
            }
        }
        
        try:
            es_client.indices.create(index=INCIDENTS_INDEX, body=mapping)
            print(f"✅ Created incidents index: {INCIDENTS_INDEX}")
        except Exception as e:
            print(f"⚠️  Could not create incidents index: {e}")

def fetch_pending_logs_from_elasticsearch(es_client, batch_size=BATCH_SIZE):
    """Fetch logs from Elasticsearch where aion.status is 'pending'."""
    try:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "aion.status"}},
                        {"term": {"aion.status": "pending"}}
                    ]
                }
            },
            "size": batch_size,
            "sort": [{"@timestamp": {"order": "asc"}}]
        }
        
        response = es_client.search(index=UNIFIED_LOGS_INDEX, body=query)
        logs = [hit["_source"] for hit in response["hits"]["hits"]]
        log_ids = [hit["_id"] for hit in response["hits"]["hits"]]
        
        print(f"📥 Fetched {len(logs)} pending logs from Elasticsearch")
        return logs, log_ids
        
    except Exception as e:
        print(f"❌ Error fetching logs from Elasticsearch: {e}")
        return [], []

def update_log_status_in_elasticsearch(es_client, log_ids, status):
    """Update the aion.status field for processed logs."""
    if not log_ids:
        return
    
    try:
        # Use bulk update for efficiency
        bulk_body = []
        for log_id in log_ids:
            bulk_body.extend([
                {"update": {"_index": UNIFIED_LOGS_INDEX, "_id": log_id}},
                {"doc": {"aion.status": status, "aion.processed_at": datetime.now().isoformat()}}
            ])
        
        if bulk_body:
            response = es_client.bulk(body=bulk_body)
            if response.get("errors"):
                print(f"⚠️  Some log status updates failed: {response['errors']}")
            else:
                print(f"✅ Updated status to '{status}' for {len(log_ids)} logs")
                
    except Exception as e:
        print(f"❌ Error updating log status: {e}")

def save_incident_to_elasticsearch(es_client, incident_data):
    """Save incident data to the incidents index."""
    try:
        # Generate unique incident ID
        incident_id = f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(str(incident_data)) % 10000}"
        
        # Prepare document
        doc = {
            "incident_id": incident_id,
            "title": incident_data.get("classification", "Security Incident"),
            "summary": incident_data.get("executive_summary", ""),
            "severity": incident_data.get("severity", "Medium"),
            "classification": incident_data.get("classification", "Unknown"),
            "source_ip": incident_data.get("attacker_information", {}).get("source_ip", "unknown"),
            "attacker_information": incident_data.get("attacker_information", {}),
            "attack_timeline": incident_data.get("attack_timeline", ""),
            "hypothesized_attacker_goal": incident_data.get("hypothesized_attacker_goal", ""),
            "impact_assessment": incident_data.get("impact_assessment", ""),
            "recommended_remediation_steps": incident_data.get("recommended_remediation_steps", []),
            "confidence_score": incident_data.get("confidence_score", 0.0),
            "log_ids": incident_data.get("log_ids", []),
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "status": "active"
        }
        
        # Index the document
        response = es_client.index(index=INCIDENTS_INDEX, body=doc)
        print(f"✅ Saved incident {incident_id} to Elasticsearch")
        return incident_id
        
    except Exception as e:
        print(f"❌ Error saving incident to Elasticsearch: {e}")
        return None

def load_logs_from_files(directory, filenames):
    """Loads all log entries from a list of JSON files in a directory."""
    all_logs = []
    print(f"--- Loading logs from '{directory}' directory ---")
    for filename in filenames:
        filepath = os.path.join(directory, filename)
        if not os.path.exists(filepath):
            print(f"Warning: File not found, skipping: {filepath}")
            continue
        
        print(f"  -> Loading {filepath}...")
        with open(filepath, 'r') as f:
            try:
                # Attempt to parse as a single JSON array first
                logs = json.load(f)
                # If successful, extend and continue
                all_logs.extend(logs)
            except json.JSONDecodeError:
                # Fall back to JSON Lines (one JSON object per line)
                f.seek(0)
                parsed_count = 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        all_logs.append(obj)
                        parsed_count += 1
                    except json.JSONDecodeError:
                        # Skip malformed lines but continue processing
                        continue
                print(f"    Parsed {parsed_count} JSONL lines from {filepath}")
            except Exception as e:
                print(f"An unexpected error occurred reading {filepath}: {e}")

    print(f"\nTotal logs loaded: {len(all_logs)}\n")
    return all_logs

def tier1_triage(log_context: dict):
    """
    Performs Tier 1 triage on a log.
    Returns a tuple: (classification, rule_name or None, confidence_score)
    Classifications: "THREAT", "BENIGN", "UNCLASSIFIED"
    """
    searchable_text = json.dumps(log_context)
    confidence_score = calculate_confidence_score(log_context)
    log_source = log_context.get('log.source', '')

    for rule_name, pattern in THREAT_RULES.items():
        # Special handling for SSRF to avoid false positives from referer logs
        if rule_name == "Server-Side Request Forgery (SSRF) Hint":
            # Only scan the actual URL requested by the user, not the entire log
            scan_target = log_context.get("url.original", "")
        elif log_source == 'linux_syslog':
            # For Linux syslog entries, scan the message field primarily
            scan_target = log_context.get("message", "")
        else:
            # For all other rules, use the full log message
            scan_target = searchable_text
        
        if re.search(pattern, scan_target, re.IGNORECASE):
            return "THREAT", rule_name, confidence_score
    
    for rule_name, pattern in BENIGN_RULES.items():
        if log_source == 'linux_syslog':
            # For Linux syslog entries, scan the message field primarily
            scan_target = log_context.get("message", "")
        else:
            scan_target = searchable_text
            
        if re.search(pattern, scan_target, re.IGNORECASE):
            return "BENIGN", rule_name, confidence_score

    return "UNCLASSIFIED", None, confidence_score

def parse_timestamp(timestamp_str):
    """Parse timestamp string to datetime object."""
    try:
        # Handle different timestamp formats
        if '+' in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            return datetime.fromisoformat(timestamp_str)
    except:
        return datetime.now()

def should_create_correlated_alert(event_tracker, source_ip, rule_name, log_timestamp):
    """
    Check if we should create a correlated alert based on event patterns.
    Returns (should_alert, event_count, time_span)
    """
    if source_ip not in event_tracker:
        return False, 0, 0
    
    events = event_tracker[source_ip]
    if not events['timestamps']:
        return False, 0, 0
    
    # Check if events are within the time window
    time_span = (log_timestamp - events['timestamps'][0]).total_seconds()
    if time_span > TIME_WINDOW_SECONDS:
        # Time window expired, reset tracker
        event_tracker[source_ip] = {"count": 0, "timestamps": [], "logs": []}
        return False, 0, 0
    
    # Check if we've hit the threshold
    threshold = CORRELATION_THRESHOLDS.get(rule_name, 10)  # Default threshold
    if events['count'] >= threshold:
        return True, events['count'], time_span
    
    return False, events['count'], time_span

def update_event_tracker(event_tracker, source_ip, rule_name, log_timestamp, log_context):
    """Update the event tracker with new event information."""
    if source_ip not in event_tracker:
        event_tracker[source_ip] = {"count": 0, "timestamps": [], "logs": []}
    
    events = event_tracker[source_ip]
    
    # Clean old events outside time window
    cutoff_time = log_timestamp - timedelta(seconds=TIME_WINDOW_SECONDS)
    events['timestamps'] = [ts for ts in events['timestamps'] if ts > cutoff_time]
    events['logs'] = events['logs'][-len(events['timestamps']):]  # Keep logs in sync
    
    # Add new event
    events['count'] = len(events['timestamps']) + 1
    events['timestamps'].append(log_timestamp)
    events['logs'].append(log_context)

def create_correlated_alert(source_ip, rule_name, event_count, time_span, sample_logs):
    """Create a correlated alert with enriched context."""
    alert = {
        "alert_type": "CORRELATED_INCIDENT",
        "source_ip": source_ip,
        "rule_name": rule_name,
        "event_count": event_count,
        "time_span_seconds": time_span,
        "severity": "High" if event_count > 50 else "Medium",
        "sample_logs": sample_logs[:5],  # Include up to 5 sample logs
        "timestamp": datetime.now().isoformat(),
        "description": f"High volume of {rule_name} events from {source_ip} ({event_count} events in {time_span:.0f}s)"
    }
    return alert

def group_tier3_logs_by_behavior(unclassified_logs):
    """
    Group unclassified logs by behavioral patterns for Tier 3 correlation.
    Groups by source IP and activity pattern (web or Linux syslog).
    """
    behavior_groups = defaultdict(list)
    
    for log in unclassified_logs:
        source_ip = log.get('source.ip', 'unknown')
        log_source = log.get('log.source', '')
        
        if log_source == 'linux_syslog':
            # Group Linux syslog entries by activity type
            message = log.get('message', '')
            process_name = log.get('process.name', '')
            
            if 'authentication failure' in message.lower():
                pattern = 'ssh_auth_failure'
            elif 'check pass; user unknown' in message.lower():
                pattern = 'ssh_unknown_user'
            elif 'connection from' in message.lower() and 'ftpd' in process_name:
                pattern = 'ftp_connection'
            elif 'timed out' in message.lower():
                pattern = 'ftp_timeout'
            elif 'session opened' in message.lower():
                pattern = 'user_session'
            elif 'alert' in message.lower() and 'exited abnormally' in message.lower():
                pattern = 'system_alert'
            else:
                pattern = 'other_syslog_activity'
        else:
            # Group web logs by URL pattern (existing logic)
            url = log.get('url.original', '')
            
            if '/filter' in url:
                pattern = 'filter_activity'
            elif '/admin' in url or '/wp-admin' in url:
                pattern = 'admin_access'
            elif '/robots.txt' in url:
                pattern = 'reconnaissance'
            elif '/search' in url or '/prepareSearch' in url:
                pattern = 'search_activity'
            else:
                pattern = 'other_web_activity'
        
        group_key = f"{source_ip}_{pattern}"
        behavior_groups[group_key].append(log)
    
    return behavior_groups

def should_create_tier3_incident(logs_group):
    """
    Determine if a group of logs should be escalated to Tier 3 incident analysis.
    """
    if len(logs_group) < TIER3_CORRELATION_THRESHOLD:
        return False
    
    # Check if logs are within time window
    timestamps = []
    for log in logs_group:
        timestamp_str = log.get('@timestamp', '')
        if timestamp_str:
            try:
                if '+' in timestamp_str:
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    dt = datetime.fromisoformat(timestamp_str)
                timestamps.append(dt)
            except:
                continue
    
    if len(timestamps) >= 2:
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        return time_span <= TIER3_TIME_WINDOW_SECONDS
    
    return True  # If we can't parse timestamps, assume it's recent

def generate_security_report(analysis_results, correlated_alerts=None, tier3_incidents=None, filename=None):
    """Generates a markdown security report from the analysis results."""
    report_filename = filename or REPORT_FILENAME
    print(f"--- Generating Security Intelligence Report: {report_filename} ---")
    
    threats = [r for r in analysis_results if r['classification'] == 'THREAT']
    llm_analyzed = [r for r in analysis_results if 'llm_analysis' in r]
    benign = [r for r in analysis_results if r['classification'] == 'BENIGN']
    correlated_alerts = correlated_alerts or []
    tier3_incidents = tier3_incidents or []
    
    # Filter LLM results to only show actual threats or high-severity issues
    critical_llm_alerts = [
        r for r in llm_analyzed 
        if r['llm_analysis'].get('severity') in ['High', 'Medium'] and not r['llm_analysis'].get('pre_filtered', False)
    ]
    
    # Calculate confidence statistics
    high_confidence_threats = [r for r in threats if r.get('confidence_score', 0) > 0.7]
    low_confidence_threats = [r for r in threats if r.get('confidence_score', 0) <= 0.7]

    report_content = f"""
# Security Intelligence Report
**Date Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Logs Analyzed:** {len(analysis_results)}

---
## 🚨 Executive Summary
A total of **{len(correlated_alerts) + len(tier3_incidents)}** high-priority security events were detected.

- **{len(correlated_alerts)}** correlated incidents were identified through behavioral analysis.
- **{len(tier3_incidents)}** sophisticated security incidents were analyzed by the Gen-AI SOC Analyst.
- **{len(threats)}** individual threat events were processed (now grouped into {len(correlated_alerts)} incidents).
- **{len(benign)}** logs were classified as benign and ignored.
- **{len([r for r in analysis_results if r.get('pre_filtered', False)])}** logs were pre-filtered as low-priority by Tier 3.

---
## 🎯 Tier 1: Known Threat Detections
High-confidence threats identified by predefined rules.

| Rule Matched                  | Count |
| ----------------------------- | ----- |
"""
    # Create a summary table for Tier 1 threats with confidence scores
    threat_summary = {}
    for threat in threats:
        rule = threat['rule_name']
        if rule not in threat_summary:
            threat_summary[rule] = {'count': 0, 'high_confidence': 0, 'low_confidence': 0}
        threat_summary[rule]['count'] += 1
        if threat.get('confidence_score', 0) > 0.7:
            threat_summary[rule]['high_confidence'] += 1
        else:
            threat_summary[rule]['low_confidence'] += 1
    
    if not threat_summary:
        report_content += "| No known threats detected. | N/A | N/A | N/A |\n"
    else:
        report_content += "| Rule Matched                  | Total | High Conf | Low Conf |\n"
        report_content += "| ----------------------------- | ----- | --------- | -------- |\n"
        for rule, stats in sorted(threat_summary.items()):
            report_content += f"| {rule:<29} | {stats['count']:<5} | {stats['high_confidence']:<9} | {stats['low_confidence']:<8} |\n"

    # Add correlated alerts section
    if correlated_alerts:
        report_content += """
---
## 🔗 Correlated Security Incidents
High-priority incidents identified through behavioral pattern analysis.

"""
        for alert in correlated_alerts:
            report_content += f"""
### **{alert['rule_name']}** (Severity: {alert['severity']})
- **Source IP:** `{alert['source_ip']}`
- **Event Count:** {alert['event_count']} events in {alert['time_span_seconds']:.0f} seconds
- **Description:** {alert['description']}
- **Sample Logs:** {len(alert['sample_logs'])} representative events
- **Timestamp:** `{alert['timestamp']}`

"""
    else:
        report_content += """
---
## 🔗 Correlated Security Incidents
*No correlated incidents detected above threshold levels.*

"""

    # Add Gen-AI SOC Analyst section
    if tier3_incidents:
        report_content += """
---
## 🤖 Gen-AI SOC Analyst: Comprehensive Incident Analysis
Sophisticated security incidents analyzed by AI-powered behavioral correlation and threat intelligence.

"""
        for incident in tier3_incidents:
            report_content += f"""
### **{incident.get('classification', 'Security Incident')}** (Severity: {incident.get('severity', 'N/A')})
- **Executive Summary:** {incident.get('executive_summary', 'N/A')}

#### **Attacker Information:**
- **Source IP:** `{incident.get('attacker_information', {}).get('source_ip', 'N/A')}`
- **User Agent Analysis:** {incident.get('attacker_information', {}).get('user_agent_analysis', 'N/A')}
- **Attack Vector:** {incident.get('attacker_information', {}).get('attack_vector', 'N/A')}

#### **Attack Timeline:**
{incident.get('attack_timeline', 'N/A')}

#### **Hypothesized Attacker Goal:**
{incident.get('hypothesized_attacker_goal', 'N/A')}

#### **Impact Assessment:**
{incident.get('impact_assessment', 'N/A')}

#### **Recommended Remediation Steps:**
"""
            remediation_steps = incident.get('recommended_remediation_steps', [])
            if isinstance(remediation_steps, list):
                for step in remediation_steps:
                    report_content += f"- {step}\n"
            else:
                report_content += f"- {remediation_steps}\n"
            
            metadata = incident.get('incident_metadata', {})
            report_content += f"""
#### **Incident Metadata:**
- **Total Logs Analyzed:** {metadata.get('total_logs_analyzed', 'N/A')}
- **Time Span:** {metadata.get('time_span', 'N/A')}
- **Analysis Confidence:** {incident.get('confidence_score', 'N/A')}
- **Analysis Timestamp:** `{metadata.get('analysis_timestamp', 'N/A')}`

---
"""
    else:
        report_content += """
---
## 🤖 Gen-AI SOC Analyst: Comprehensive Incident Analysis
*No sophisticated security incidents detected requiring comprehensive analysis.*

"""

    report_content += """
---
## 🧠 Tier 3: LLM Anomaly Analysis (Medium & High Severity)
Logs that did not match known patterns but were flagged as significant by the AI analyst.

"""
    if not critical_llm_alerts:
        report_content += "*No medium or high severity anomalies were identified by the LLM.*\n"
    else:
        for alert in critical_llm_alerts:
            analysis = alert['llm_analysis']
            confidence_score = alert.get('confidence_score', 0)
            report_content += f"""
### **{analysis.get('classification', 'N/A')}** (Severity: {analysis.get('severity', 'N/A')})
- **Confidence Score:** {confidence_score:.2f}
- **Hypothesis:** {analysis.get('hypothesis', 'N/A')}
- **Timestamp:** `{alert['log_context'].get('@timestamp', 'N/A')}`
- **Source IP:** `{alert['log_context'].get('source.ip', 'N/A')}`
- **Original Log:** `{alert['log_context'].get('message', 'N/A')}`
- **Recommended Action:** {analysis.get('recommended_action', 'N/A')}
---
"""

    with open(report_filename, 'w') as f:
        f.write(report_content)
    print(f"\n✅ Report successfully generated: {report_filename}")


# --- Main Orchestration Workflow ---
def process_logs_batch(es_client, logs, log_ids):
    """Process a batch of logs and return analysis results."""
    if not logs:
        return [], [], []
    
    print(f"--- Processing batch of {len(logs)} logs ---")
    
    # Initialize correlation tracking
    event_tracker = defaultdict(lambda: {"count": 0, "timestamps": [], "logs": []})
    correlated_alerts = []
    analysis_results = []
    unclassified_count = 0
    max_tier3 = int(os.getenv("MAX_TIER3_ESCALATIONS", "50"))
    tier3_used = 0
    pre_filtered_count = 0

    # Pass 1: Process logs and build correlation state
    for i, log in enumerate(logs):
        # Provide progress feedback
        if (i + 1) % 100 == 0:
            print(f"  -> Processed {i+1}/{len(logs)} logs...")

        classification, rule_name, confidence_score = tier1_triage(log)
        source_ip = log.get("source.ip", "unknown")
        log_timestamp = parse_timestamp(log.get("@timestamp", ""))
        
        result = {
            "classification": classification,
            "rule_name": rule_name,
            "confidence_score": confidence_score,
            "log_context": log
        }
        
        # Handle THREAT classification with correlation
        if classification == "THREAT" and rule_name in CORRELATION_THRESHOLDS:
            # Update event tracker
            update_event_tracker(event_tracker, source_ip, rule_name, log_timestamp, log)
            
            # Check if we should create a correlated alert
            should_alert, event_count, time_span = should_create_correlated_alert(
                event_tracker, source_ip, rule_name, log_timestamp
            )
            
            if should_alert:
                # Create correlated alert
                alert = create_correlated_alert(
                    source_ip, rule_name, event_count, time_span, 
                    event_tracker[source_ip]['logs']
                )
                correlated_alerts.append(alert)
                print(f"  -> CORRELATED TIER 1 INCIDENT: {rule_name} from {source_ip} ({event_count} events)")
                
                # Reset tracker to avoid duplicate alerts
                event_tracker[source_ip] = {"count": 0, "timestamps": [], "logs": []}
        
        # Handle UNCLASSIFIED logs
        elif classification == "UNCLASSIFIED":
            unclassified_count += 1
            # Use improved escalation logic with confidence scoring
            if should_escalate_to_llm(log) and tier3_used < max_tier3:
                llm_analysis = analyze_log_with_llm(log)
                result['llm_analysis'] = llm_analysis
                tier3_used += 1
                print(f"    -> Escalated log {i+1} to LLM (confidence: {confidence_score:.2f})")
            else:
                # Log was pre-filtered (not escalated to LLM due to low confidence)
                pre_filtered_count += 1
                result['pre_filtered'] = True
        
        analysis_results.append(result)
    
    # Pass 2: Enhanced Tier 3 analysis for correlated incidents
    print("--- Analysis Engine (Pass 2: Correlation & Escalation) ---")
    
    # Collect unclassified logs for Tier 3 correlation
    unclassified_logs = []
    for result in analysis_results:
        if result['classification'] == 'UNCLASSIFIED':
            unclassified_logs.append(result['log_context'])
    
    # Group unclassified logs by behavioral patterns
    behavior_groups = group_tier3_logs_by_behavior(unclassified_logs)
    
    # Analyze each behavior group for potential incidents
    tier3_incidents = []
    for group_key, logs_group in behavior_groups.items():
        if should_create_tier3_incident(logs_group):
            source_ip = logs_group[0].get('source.ip', 'unknown')
            print(f"  -> TIER 3 INCIDENT DETECTED: Analyzing {len(logs_group)} logs from {source_ip}...")
            
            # Generate comprehensive incident report
            try:
                incident_analysis = generate_incident_report(logs_group)
                # Add log IDs to incident data
                incident_analysis['log_ids'] = [log_ids[i] for i, log in enumerate(logs) if log in logs_group]
                tier3_incidents.append(incident_analysis)
                print(f"    -> Generated comprehensive incident report: {incident_analysis.get('classification', 'Unknown')}")
            except Exception as e:
                print(f"    -> Error generating incident report: {e}")
                # Fallback to individual analysis for this group
                for log in logs_group[:5]:  # Limit to first 5 logs
                    if tier3_used < max_tier3:
                        llm_analysis = analyze_log_with_llm(log)
                        # Add to analysis_results
                        for result in analysis_results:
                            if result['log_context'] == log:
                                result['llm_analysis'] = llm_analysis
                                break
                        tier3_used += 1
    
    print(f"\n--- Batch Processing Complete ---")
    print(f"Total Threats (Tier 1): {len([r for r in analysis_results if r['classification'] == 'THREAT'])}")
    print(f"Total Benign (Tier 1): {len([r for r in analysis_results if r['classification'] == 'BENIGN'])}")
    print(f"Total Escalated to LLM (Tier 3): {tier3_used} (of {unclassified_count} unclassified)")
    print(f"Pre-filtered by Tier 3: {pre_filtered_count}")
    print(f"Correlated Incidents: {len(correlated_alerts)}")
    print(f"Gen-AI SOC Incidents: {len(tier3_incidents)}")
    
    return analysis_results, correlated_alerts, tier3_incidents

def main():
    """Main function to orchestrate the entire workflow with Elasticsearch integration."""
    
    # Initialize Elasticsearch connection
    es_client = initialize_elasticsearch()
    if not es_client:
        print("❌ Cannot proceed without Elasticsearch connection. Exiting.")
        return
    
    # 1. Fetch pending logs from Elasticsearch
    logs, log_ids = fetch_pending_logs_from_elasticsearch(es_client)
    
    if not logs:
        print("ℹ️  No pending logs found in Elasticsearch. Exiting.")
        return
    
    # 2. Process the batch of logs
    analysis_results, correlated_alerts, tier3_incidents = process_logs_batch(es_client, logs, log_ids)
    
    # 3. Update log statuses in Elasticsearch
    if analysis_results:
        # Group log IDs by classification for status updates
        threat_log_ids = []
        benign_log_ids = []
        analyzed_log_ids = []
        
        for i, result in enumerate(analysis_results):
            if result['classification'] == 'THREAT':
                threat_log_ids.append(log_ids[i])
            elif result['classification'] == 'BENIGN':
                benign_log_ids.append(log_ids[i])
            else:
                analyzed_log_ids.append(log_ids[i])
        
        # Update statuses
        if threat_log_ids:
            update_log_status_in_elasticsearch(es_client, threat_log_ids, "threat")
        if benign_log_ids:
            update_log_status_in_elasticsearch(es_client, benign_log_ids, "benign")
        if analyzed_log_ids:
            update_log_status_in_elasticsearch(es_client, analyzed_log_ids, "analyzed")
    
    # 4. Save incidents to Elasticsearch
    for incident in tier3_incidents:
        save_incident_to_elasticsearch(es_client, incident)
    
    # 5. Generate the final report with correlated alerts and Gen-AI incidents
    generate_security_report(analysis_results, correlated_alerts, tier3_incidents)

def run_real_time_service():
    """Run the orchestrator as a continuous real-time service."""
    import time
    
    print("🚀 Starting AION Real-Time Security Orchestrator Service")
    print(f"⏰ Processing interval: {LOOP_DELAY_SECONDS} seconds")
    print("🔄 Service will run continuously. Press Ctrl+C to stop.")
    print("-" * 60)
    
    # Initialize Elasticsearch connection
    es_client = initialize_elasticsearch()
    if not es_client:
        print("❌ Cannot start service without Elasticsearch connection. Exiting.")
        return
    
    cycle_count = 0
    
    try:
        while True:
            cycle_count += 1
            print(f"\n🔄 Processing Cycle #{cycle_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Fetch pending logs from Elasticsearch
            logs, log_ids = fetch_pending_logs_from_elasticsearch(es_client)
            
            if logs:
                # Process the batch
                analysis_results, correlated_alerts, tier3_incidents = process_logs_batch(es_client, logs, log_ids)
                
                # Update log statuses in Elasticsearch
                if analysis_results:
                    # Group log IDs by classification for status updates
                    threat_log_ids = []
                    benign_log_ids = []
                    analyzed_log_ids = []
                    
                    for i, result in enumerate(analysis_results):
                        if result['classification'] == 'THREAT':
                            threat_log_ids.append(log_ids[i])
                        elif result['classification'] == 'BENIGN':
                            benign_log_ids.append(log_ids[i])
                        else:
                            analyzed_log_ids.append(log_ids[i])
                    
                    # Update statuses
                    if threat_log_ids:
                        update_log_status_in_elasticsearch(es_client, threat_log_ids, "threat")
                    if benign_log_ids:
                        update_log_status_in_elasticsearch(es_client, benign_log_ids, "benign")
                    if analyzed_log_ids:
                        update_log_status_in_elasticsearch(es_client, analyzed_log_ids, "analyzed")
                
                # Save incidents to Elasticsearch
                for incident in tier3_incidents:
                    save_incident_to_elasticsearch(es_client, incident)
                
                # Generate report for this cycle
                report_filename = f"security_intelligence_report_cycle_{cycle_count}.md"
                generate_security_report(analysis_results, correlated_alerts, tier3_incidents, report_filename)
                
                print(f"✅ Cycle #{cycle_count} completed successfully")
            else:
                print(f"ℹ️  No pending logs found in cycle #{cycle_count}")
            
            # Wait before next cycle
            print(f"⏳ Waiting {LOOP_DELAY_SECONDS} seconds before next cycle...")
            time.sleep(LOOP_DELAY_SECONDS)
            
    except KeyboardInterrupt:
        print(f"\n🛑 Service stopped by user after {cycle_count} cycles")
    except Exception as e:
        print(f"\n❌ Service error: {e}")
        print("🔄 Service will continue after error...")
        time.sleep(LOOP_DELAY_SECONDS)

if __name__ == "__main__":
    import sys
    
    # Check command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--service":
        run_real_time_service()
    else:
        # Run in batch mode (legacy behavior)
        main()