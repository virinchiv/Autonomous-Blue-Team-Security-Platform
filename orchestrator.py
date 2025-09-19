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
from datetime import datetime

# --- Import your custom modules ---
from tier1_rules import THREAT_RULES, BENIGN_RULES
from tier3_llm import analyze_log_with_llm, should_escalate_to_llm, calculate_confidence_score

# --- Configuration ---
LOG_DIRECTORY = "normalized_logs"
# Specify the files from the directory you want to process
# Modified for testing - only processing access logs
FILES_TO_PROCESS = [
    "output_access-10k.log_ecs.json",
]
REPORT_FILENAME = "security_intelligence_report.md"

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

    for rule_name, pattern in THREAT_RULES.items():
        # Special handling for SSRF to avoid false positives from referer logs
        if rule_name == "Server-Side Request Forgery (SSRF) Hint":
            # Only scan the actual URL requested by the user, not the entire log
            scan_target = log_context.get("url.original", "")
        else:
            # For all other rules, use the full log message
            scan_target = searchable_text
        
        if re.search(pattern, scan_target, re.IGNORECASE):
            return "THREAT", rule_name, confidence_score
    
    for rule_name, pattern in BENIGN_RULES.items():
        if re.search(pattern, searchable_text, re.IGNORECASE):
            return "BENIGN", rule_name, confidence_score

    return "UNCLASSIFIED", None, confidence_score

def generate_security_report(analysis_results):
    """Generates a markdown security report from the analysis results."""
    print(f"--- Generating Security Intelligence Report ---")
    
    threats = [r for r in analysis_results if r['classification'] == 'THREAT']
    llm_analyzed = [r for r in analysis_results if 'llm_analysis' in r]
    benign = [r for r in analysis_results if r['classification'] == 'BENIGN']
    
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
A total of **{len(threats) + len(critical_llm_alerts)}** high-priority security events were detected.

- **{len(threats)}** known threats were identified by Tier 1 rules.
  - **{len(high_confidence_threats)}** high-confidence threats (confidence > 0.7)
  - **{len(low_confidence_threats)}** low-confidence threats (confidence ≤ 0.7)
- **{len(critical_llm_alerts)}** previously unknown anomalies were classified as Medium or High severity by Tier 3 LLM analysis.
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
    """Main function to orchestrate the entire workflow."""
    
    # 1. Load all logs from the specified files
    all_logs = load_logs_from_files(LOG_DIRECTORY, FILES_TO_PROCESS)
    
    # 2. Process logs through the triage engine
    print("--- Starting Triage and Analysis Engine ---")
    analysis_results = []
    unclassified_count = 0
    max_tier3 = int(os.getenv("MAX_TIER3_ESCALATIONS", "50"))
    tier3_used = 0
    pre_filtered_count = 0

    for i, log in enumerate(all_logs):
        # Provide progress feedback
        if (i + 1) % 1000 == 0:
            print(f"  -> Processed {i+1}/{len(all_logs)} logs...")

        classification, rule_name, confidence_score = tier1_triage(log)
        
        result = {
            "classification": classification,
            "rule_name": rule_name,
            "confidence_score": confidence_score,
            "log_context": log
        }
        
        if classification == "UNCLASSIFIED":
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
    
    print(f"\n--- Triage Complete ---")
    print(f"Total Threats (Tier 1): {len([r for r in analysis_results if r['classification'] == 'THREAT'])}")
    print(f"  - High Confidence: {len([r for r in analysis_results if r['classification'] == 'THREAT' and r.get('confidence_score', 0) > 0.7])}")
    print(f"  - Low Confidence: {len([r for r in analysis_results if r['classification'] == 'THREAT' and r.get('confidence_score', 0) <= 0.7])}")
    print(f"Total Benign (Tier 1): {len([r for r in analysis_results if r['classification'] == 'BENIGN'])}")
    print(f"Total Escalated to LLM (Tier 3): {tier3_used} (of {unclassified_count} unclassified)")
    print(f"Pre-filtered by Tier 3: {pre_filtered_count}")

    # 3. Generate the final report
    generate_security_report(analysis_results)

if __name__ == "__main__":
    main()