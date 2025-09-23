from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan


# # --- Configuration ---
# ELASTICSEARCH_HOST = "http://localhost:9200"
# INDEX_NAME = "unified-logs"
# BATCH_SIZE = 1000
# LOOP_DELAY_SECONDS = 1

# # --- Initialize connections and models ---
# try:
#     es_client = Elasticsearch([ELASTICSEARCH_HOST], request_timeout=30, api_key=None, basic_auth=None)
#     anomaly_detector = BertAnomalyDetector(model_path="hdbscan_model.joblib")  # Use trained model
#     print("Orchestrator initialized successfully.")
# except Exception as e:
#     print(f"Error during initialization: {e}")
#     exit()

# --- Tier Processing Functions ---

import os
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict

# --- Import your custom modules ---
from tier1_rules import THREAT_RULES, BENIGN_RULES
from tier3_llm import analyze_log_with_llm, should_escalate_to_llm, calculate_confidence_score, generate_incident_report

# --- Configuration ---
LOG_DIRECTORY = "normalized_logs"
# Specify the files from the directory you want to process
# Modified for testing - only processing access logs
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

def generate_security_report(analysis_results, correlated_alerts=None, tier3_incidents=None):
    """Generates a markdown security report from the analysis results."""
    print(f"--- Generating Security Intelligence Report ---")
    
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

    with open(REPORT_FILENAME, 'w') as f:
        f.write(report_content)
    print(f"\n✅ Report successfully generated: {REPORT_FILENAME}")


# --- Main Orchestration Workflow ---
def main():
    """Main function to orchestrate the entire workflow with alert correlation."""
    
    # 1. Load all logs from the specified files
    all_logs = load_logs_from_files(LOG_DIRECTORY, FILES_TO_PROCESS)
    
    # 2. Initialize correlation tracking
    print("--- Starting Triage and Analysis Engine (Pass 1: Grouping) ---")
    event_tracker = defaultdict(lambda: {"count": 0, "timestamps": [], "logs": []})
    correlated_alerts = []
    analysis_results = []
    unclassified_count = 0
    max_tier3 = int(os.getenv("MAX_TIER3_ESCALATIONS", "50"))
    tier3_used = 0
    pre_filtered_count = 0

    # Pass 1: Process logs and build correlation state
    for i, log in enumerate(all_logs):
        # Provide progress feedback
        if (i + 1) % 1000 == 0:
            print(f"  -> Processed {i+1}/{len(all_logs)} logs...")

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
    
    print(f"\n--- Triage Complete ---")
    print(f"Total Threats (Tier 1): {len([r for r in analysis_results if r['classification'] == 'THREAT'])}")
    print(f"  - High Confidence: {len([r for r in analysis_results if r['classification'] == 'THREAT' and r.get('confidence_score', 0) > 0.7])}")
    print(f"  - Low Confidence: {len([r for r in analysis_results if r['classification'] == 'THREAT' and r.get('confidence_score', 0) <= 0.7])}")
    print(f"Total Benign (Tier 1): {len([r for r in analysis_results if r['classification'] == 'BENIGN'])}")
    print(f"Total Escalated to LLM (Tier 3): {tier3_used} (of {unclassified_count} unclassified)")
    print(f"Pre-filtered by Tier 3: {pre_filtered_count}")
    print(f"Correlated Incidents: {len(correlated_alerts)}")
    print(f"Gen-AI SOC Incidents: {len(tier3_incidents)}")

    # 3. Generate the final report with correlated alerts and Gen-AI incidents
    generate_security_report(analysis_results, correlated_alerts, tier3_incidents)

if __name__ == "__main__":
    main()