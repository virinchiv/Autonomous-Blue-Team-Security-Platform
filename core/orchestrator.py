from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import os
import json
import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- Import your custom modules ---
from .tier1_rules import THREAT_RULES, BENIGN_RULES
from .tier3_llm import analyze_log_with_llm, should_escalate_to_llm, calculate_confidence_score, generate_incident_report

# --- Configuration from Environment Variables ---
# Elasticsearch Configuration
ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "")
ELASTICSEARCH_SSL_VERIFY = os.getenv("ELASTICSEARCH_SSL_VERIFY", "true").lower() == "true"

UNIFIED_LOGS_INDEX = os.getenv("UNIFIED_LOGS_INDEX", "unified-logs")
INCIDENTS_INDEX = os.getenv("INCIDENTS_INDEX", "aion-incidents")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "1000"))
LOOP_DELAY_SECONDS = int(os.getenv("LOOP_DELAY_SECONDS", "30"))
MAX_DEMO_LOGS = int(os.getenv("MAX_DEMO_LOGS", "2000"))
CORRELATION_TIME_WINDOW = int(os.getenv("CORRELATION_TIME_WINDOW", "300"))

# --- Alert Correlation Configuration ---
TIME_WINDOW_SECONDS = CORRELATION_TIME_WINDOW  # Use environment variable
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

# --- Environment Validation ---
def validate_environment():
    """Validate required environment variables and configuration."""
    print("🔍 Validating environment configuration...")
    
    # Check for required environment variables
    required_vars = []
    optional_vars = {
        "GROQ_API_KEY": "AI-powered threat analysis (optional but recommended)",
        "ELASTICSEARCH_HOST": "Elasticsearch connection (defaults to localhost:9200)",
        "UNIFIED_LOGS_INDEX": "Log storage index (defaults to unified-logs)",
        "INCIDENTS_INDEX": "Incident storage index (defaults to aion-incidents)"
    }
    
    # Check optional variables
    for var, description in optional_vars.items():
        value = os.getenv(var)
        if value:
            print(f"✅ {var}: {description}")
        else:
            print(f"ℹ️  {var}: Not set, using default value")
    
    # Validate numeric values
    try:
        int(os.getenv("BATCH_SIZE", "1000"))
        int(os.getenv("LOOP_DELAY_SECONDS", "30"))
        int(os.getenv("MAX_DEMO_LOGS", "2000"))
        int(os.getenv("CORRELATION_TIME_WINDOW", "300"))
        print("✅ Numeric configuration values are valid")
    except ValueError as e:
        print(f"❌ Invalid numeric configuration: {e}")
        return False
    
    # Check if .env file exists
    if os.path.exists(".env"):
        print("✅ Found .env file")
    else:
        print("⚠️  No .env file found. Using default values.")
        print("   Copy .env.example to .env and configure your settings.")
    
    print("✅ Environment validation completed")
    return True

# --- Core Orchestrator Functions ---
def initialize_elasticsearch():
    """Initialize Elasticsearch client and verify connection."""
    try:
        # Build Elasticsearch connection parameters
        es_config = {
            "hosts": [ELASTICSEARCH_HOST],
            "request_timeout": 30,
            "verify_certs": ELASTICSEARCH_SSL_VERIFY
        }
        
        # Add authentication if provided
        if ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD:
            es_config["basic_auth"] = (ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD)
            print(f"🔐 Using Elasticsearch authentication")
        
        es_client = Elasticsearch(**es_config)
        
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
    """Create the incidents index with proper mapping for the new incident structure."""
    if not es_client.indices.exists(index=INCIDENTS_INDEX):
        mapping = {
            "mappings": {
                "properties": {
                    "incident_id": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "first_event_at": {"type": "date"},
                    "last_event_at": {"type": "date"},
                    "source_ip": {"type": "ip", "null_value": None},
                    "involved_hosts": {"type": "keyword"},
                    "threat_rules_triggered": {"type": "keyword"},
                    "event_count": {"type": "integer"},
                    "classification": {"type": "text"},
                    "severity": {"type": "keyword"},
                    "executive_summary": {"type": "text"},
                    "attack_timeline": {"type": "text"},
                    "recommended_actions": {"type": "text"},
                    "evidence_logs": {"type": "object"},
                    "confidence_score": {"type": "float"},
                    "updated_at": {"type": "date"}
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

def tier1_triage(log_context: dict):
    """
    Performs Tier 1 triage on a log.
    Returns a tuple: (classification, rule_name or None, confidence_score)
    Classifications: "THREAT", "BENIGN", "UNCLASSIFIED"
    """
    try:
        # Clean the log_context to remove None values that can't be serialized
        clean_log_context = {}
        for key, value in log_context.items():
            if value is not None:
                clean_log_context[key] = value
            else:
                clean_log_context[key] = ""
        
        searchable_text = json.dumps(clean_log_context)
        confidence_score = calculate_confidence_score(log_context)
        log_source = log_context.get('log.source', '')

        for rule_name, pattern in THREAT_RULES.items():
            try:
                # Special handling for SSRF to avoid false positives from referer logs
                if rule_name == "Server-Side Request Forgery (SSRF) Hint":
                    # Only scan the actual URL requested by the user, not the entire log
                    scan_target = log_context.get("url.original", "") or ""
                elif log_source == 'linux_syslog':
                    # For Linux syslog entries, scan the message field primarily
                    scan_target = log_context.get("message", "") or ""
                else:
                    # For all other rules, use the full log message
                    scan_target = searchable_text
                
                if scan_target and re.search(pattern, scan_target, re.IGNORECASE):
                    return "THREAT", rule_name, confidence_score
            except Exception as e:
                print(f"⚠️  Error in THREAT_RULES processing for {rule_name}: {e}")
                continue
        for rule_name, pattern in BENIGN_RULES.items():
            try:
                if log_source == 'linux_syslog':
                    # For Linux syslog entries, scan the message field primarily
                    scan_target = log_context.get("message", "") or ""
                else:
                    scan_target = searchable_text
                    
                if scan_target and re.search(pattern, scan_target, re.IGNORECASE):
                    return "BENIGN", rule_name, confidence_score
            except Exception as e:
                print(f"⚠️  Error in BENIGN_RULES processing for {rule_name}: {e}")
                continue

        return "UNCLASSIFIED", None, confidence_score
        
    except Exception as e:
        print(f"⚠️  Error in tier1_triage: {e}")
        print(f"   Log context keys: {list(log_context.keys()) if log_context else 'None'}")
        return "UNCLASSIFIED", None, 0.5

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

def correlate_alerts(threat_logs):
    """
    Group related threat logs into distinct incident dictionaries.
    This is the core correlation logic that creates incidents from individual threat logs.
    """
    incidents = []
    
    # Group threats by source IP and rule type
    ip_rule_groups = defaultdict(list)
    
    for log in threat_logs:
        source_ip = log.get('source.ip', 'unknown')
        rule_name = log.get('rule_name', 'Unknown')
        group_key = f"{source_ip}_{rule_name}"
        ip_rule_groups[group_key].append(log)
    
    # Create incidents from groups that meet correlation thresholds
    for group_key, logs in ip_rule_groups.items():
        source_ip, rule_name = group_key.split('_', 1)
        
        # Check if this group meets the correlation threshold
        threshold = CORRELATION_THRESHOLDS.get(rule_name, 1)  # Default to 1 for immediate alerts
        
        if len(logs) >= threshold:
            # Create incident from this group
            incident = create_incident_from_threats(source_ip, rule_name, logs)
            incidents.append(incident)
            print(f"  -> Created incident: {incident['incident_id']} - {rule_name} from {source_ip} ({len(logs)} events)")
    
    return incidents

def create_incident_from_threats(source_ip, rule_name, threat_logs):
    """
    Create a basic incident structure from a group of related threat logs.
    This creates the initial incident that will later be enriched by Tier 3 LLM.
    """
    # Sort logs by timestamp
    threat_logs.sort(key=lambda x: x.get('@timestamp', ''))
    
    # Extract timestamps
    timestamps = []
    for log in threat_logs:
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
    
    # Calculate time span
    if len(timestamps) >= 2:
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        first_event_at = min(timestamps).isoformat()
        last_event_at = max(timestamps).isoformat()
    else:
        time_span = 0
        first_event_at = timestamps[0].isoformat() if timestamps else datetime.now().isoformat()
        last_event_at = first_event_at
    
    # Extract involved hosts
    involved_hosts = list(set(log.get('host.name', 'unknown') for log in threat_logs if log.get('host.name')))
    
    # Clean and validate source IP
    if source_ip in ['unknown', 'None', None, '']:
        source_ip = 'unknown'
        incident_id = f"INC-{int(datetime.now().timestamp())}-unknown"
    else:
        # Clean IP address for incident ID
        clean_ip = source_ip.replace('.', '-').replace(':', '-')
        incident_id = f"INC-{int(datetime.now().timestamp())}-{clean_ip}"
    
    # Create basic incident structure
    incident = {
        "incident_id": incident_id,
        "status": "New",
        "created_at": datetime.now().isoformat(),
        "first_event_at": first_event_at,
        "last_event_at": last_event_at,
        "source_ip": source_ip if source_ip != 'unknown' else None,  # Use None for unknown IPs
        "involved_hosts": involved_hosts,
        "threat_rules_triggered": [rule_name],
        "event_count": len(threat_logs),
        "evidence_logs": threat_logs[:50],  # Limit to first 50 logs to avoid size issues
        "confidence_score": 0.0,  # Will be updated by LLM analysis
        "updated_at": datetime.now().isoformat()
    }
    
    return incident

def enrich_incident_with_llm(incident):
    """
    Send incident to Tier 3 LLM for enrichment and analysis.
    This adds the comprehensive analysis fields to the incident.
    """
    try:
        # Use the existing generate_incident_report function
        llm_analysis = generate_incident_report(incident['evidence_logs'])
        
        # Validate and clean the LLM response
        attack_timeline = llm_analysis.get("attack_timeline", "")
        if isinstance(attack_timeline, dict):
            # Convert dict to string if LLM returned object
            attack_timeline = str(attack_timeline)
        elif not isinstance(attack_timeline, str):
            attack_timeline = str(attack_timeline) if attack_timeline else ""
        
        recommended_actions = llm_analysis.get("recommended_remediation_steps", [])
        if not isinstance(recommended_actions, list):
            recommended_actions = [str(recommended_actions)] if recommended_actions else []
        
        # Ensure confidence score is a float
        confidence_score = llm_analysis.get("confidence_score", 0.0)
        try:
            confidence_score = float(confidence_score)
        except (ValueError, TypeError):
            confidence_score = 0.0
        
        # Merge LLM analysis into incident
        incident.update({
            "classification": llm_analysis.get("classification", "Security Incident"),
            "severity": llm_analysis.get("severity", "Medium"),
            "executive_summary": llm_analysis.get("executive_summary", ""),
            "attack_timeline": attack_timeline,
            "recommended_actions": recommended_actions,
            "confidence_score": confidence_score,
            "updated_at": datetime.now().isoformat()
        })
        
        print(f"    -> Enriched incident {incident['incident_id']} with LLM analysis")
        return incident
        
    except Exception as e:
        print(f"    -> Error enriching incident {incident['incident_id']}: {e}")
        # Return incident with basic analysis
        incident.update({
            "classification": "Security Incident (Analysis Error)",
            "severity": "Medium",
            "executive_summary": f"Security incident detected but analysis failed: {str(e)}",
            "attack_timeline": "Analysis unavailable",
            "recommended_actions": ["Manual investigation required"],
            "confidence_score": 0.5,
            "updated_at": datetime.now().isoformat()
        })
        return incident

def save_incident_to_elasticsearch(es_client, incident):
    """Save enriched incident data to the incidents index."""
    try:
        # Clean the incident data before saving
        cleaned_incident = clean_incident_for_elasticsearch(incident)
        
        # Index the document
        response = es_client.index(index=INCIDENTS_INDEX, body=cleaned_incident)
        print(f"✅ Saved incident {incident['incident_id']} to Elasticsearch")
        return incident['incident_id']
        
    except Exception as e:
        print(f"❌ Error saving incident to Elasticsearch: {e}")
        print(f"   Incident ID: {incident.get('incident_id', 'Unknown')}")
        print(f"   Source IP: {incident.get('source_ip', 'Unknown')}")
        return None

def clean_incident_for_elasticsearch(incident):
    """Clean incident data to ensure it's compatible with Elasticsearch mapping."""
    cleaned = incident.copy()
    
    # Handle source_ip field
    if 'source_ip' in cleaned:
        source_ip = cleaned['source_ip']
        if source_ip in ['unknown', 'None', None, '']:
            cleaned['source_ip'] = None
        elif not isinstance(source_ip, str) or not source_ip.replace('.', '').replace(':', '').isdigit():
            # Invalid IP format, set to None
            cleaned['source_ip'] = None
    
    # Ensure all required fields are present
    required_fields = {
        'incident_id': 'unknown',
        'status': 'New',
        'created_at': datetime.now().isoformat(),
        'first_event_at': datetime.now().isoformat(),
        'last_event_at': datetime.now().isoformat(),
        'event_count': 0,
        'confidence_score': 0.0,
        'updated_at': datetime.now().isoformat()
    }
    
    for field, default_value in required_fields.items():
        if field not in cleaned or cleaned[field] is None:
            cleaned[field] = default_value
    
    # Ensure list fields are lists
    list_fields = ['involved_hosts', 'threat_rules_triggered']
    for field in list_fields:
        if field not in cleaned or not isinstance(cleaned[field], list):
            cleaned[field] = []
    
    return cleaned

def process_logs_batch(es_client, logs, log_ids):
    """
    Process a batch of logs using the complete incident-centric workflow:
    1. Triage: Process logs through Tier 1
    2. Collect Threats: Gather all THREAT logs
    3. Process Unclassified: Send UNCLASSIFIED logs to Tier 3 LLM for threat detection
    4. Correlate: Group related threats into incidents (both Tier 1 and LLM-detected)
    5. Enrich: Send incidents to Tier 3 LLM for comprehensive analysis
    6. Store: Save enriched incidents to Elasticsearch
    """
    if not logs:
        return [], []
    
    print(f"--- Processing batch of {len(logs)} logs ---")
    
    # Step 1: Triage - Process all logs through Tier 1
    print("Step 1: Tier 1 Triage")
    threat_logs = []
    benign_log_ids = []
    unclassified_logs = []
    unclassified_log_ids = []
    
    for i, log in enumerate(logs):
        # Provide progress feedback
        if (i + 1) % 100 == 0:
            print(f"  -> Processed {i+1}/{len(logs)} logs...")

        classification, rule_name, confidence_score = tier1_triage(log)
        
        if classification == "THREAT":
            # Add rule information to the log for correlation
            log['rule_name'] = rule_name
            log['confidence_score'] = confidence_score
            threat_logs.append(log)
        elif classification == "BENIGN":
            benign_log_ids.append(log_ids[i])
        else:  # UNCLASSIFIED
            log['confidence_score'] = confidence_score
            unclassified_logs.append(log)
            unclassified_log_ids.append(log_ids[i])
    
    print(f"  -> Found {len(threat_logs)} threats, {len(benign_log_ids)} benign, {len(unclassified_logs)} unclassified")
    
    # Step 2: Process Unclassified Logs with Tier 3 LLM
    print("Step 2: Tier 3 Analysis of Unclassified Logs")
    llm_threat_logs = []
    llm_benign_log_ids = []
    max_tier3 = int(os.getenv("MAX_TIER3_ESCALATIONS", "50"))
    tier3_used = 0
    
    for i, log in enumerate(unclassified_logs):
        if tier3_used >= max_tier3:
            print(f"  -> Reached max Tier 3 escalations ({max_tier3}), marking remaining as analyzed")
            break
            
        # Check if log should be escalated to LLM
        if should_escalate_to_llm(log):
            try:
                llm_analysis = analyze_log_with_llm(log)
                log['llm_analysis'] = llm_analysis
                
                # Check if LLM identified this as a threat
                if (llm_analysis.get('severity') in ['High', 'Medium'] and 
                    not llm_analysis.get('pre_filtered', False) and
                    llm_analysis.get('classification') not in ['Informational', 'Low Priority (Pre-filtered)']):
                    
                    # LLM identified this as a threat - add to threat logs
                    log['rule_name'] = f"LLM-{llm_analysis.get('classification', 'Threat')}"
                    llm_threat_logs.append(log)
                    print(f"    -> LLM THREAT: {llm_analysis.get('classification')} (severity: {llm_analysis.get('severity')})")
                else:
                    # LLM classified as benign or low priority
                    llm_benign_log_ids.append(unclassified_log_ids[i])
                    print(f"    -> LLM BENIGN: {llm_analysis.get('classification')} (severity: {llm_analysis.get('severity')})")
                
                tier3_used += 1
                
            except Exception as e:
                print(f"    -> Error analyzing log with LLM: {e}")
                # Mark as analyzed on error
                llm_benign_log_ids.append(unclassified_log_ids[i])
        else:
            # Low confidence - mark as benign without LLM analysis
            llm_benign_log_ids.append(unclassified_log_ids[i])
    
    # Add remaining unclassified logs to benign (if we hit the limit)
    remaining_count = len(unclassified_logs) - tier3_used
    if remaining_count > 0:
        llm_benign_log_ids.extend(unclassified_log_ids[tier3_used:])
        print(f"  -> Marked {remaining_count} low-confidence logs as benign")
    
    print(f"  -> LLM analyzed {tier3_used} unclassified logs")
    print(f"  -> LLM identified {len(llm_threat_logs)} additional threats")
    print(f"  -> LLM classified {len(llm_benign_log_ids)} as benign")
    
    # Step 3: Combine all threat logs (Tier 1 + LLM-detected)
    all_threat_logs = threat_logs + llm_threat_logs
    print(f"Step 3: Total Threats (Tier 1 + LLM): {len(all_threat_logs)}")
    
    # Step 4: Correlate - Group related threats into incidents
    print("Step 4: Correlating All Threats into Incidents")
    incidents = correlate_alerts(all_threat_logs)
    print(f"  -> Created {len(incidents)} incidents from {len(all_threat_logs)} threat logs")
    
    # Step 5: Enrich & Summarize - Send incidents to Tier 3 LLM
    print("Step 5: Enriching Incidents with LLM Analysis")
    enriched_incidents = []
    for incident in incidents:
        enriched_incident = enrich_incident_with_llm(incident)
        enriched_incidents.append(enriched_incident)
    
    # Step 6: Store Incidents - Save to Elasticsearch
    print("Step 6: Storing Incidents")
    stored_incident_ids = []
    failed_incidents = []
    
    for incident in enriched_incidents:
        incident_id = save_incident_to_elasticsearch(es_client, incident)
        if incident_id:
            stored_incident_ids.append(incident_id)
        else:
            failed_incidents.append(incident)
            print(f"⚠️  Failed to store incident: {incident.get('incident_id', 'Unknown')}")
    
    # Report storage results
    if failed_incidents:
        print(f"⚠️  {len(failed_incidents)} incidents failed to store")
    else:
        print(f"✅ All {len(enriched_incidents)} incidents stored successfully")
    
    # Update log statuses
    if all_threat_logs:
        all_threat_log_ids = [log_ids[i] for i, log in enumerate(logs) if log in all_threat_logs]
        update_log_status_in_elasticsearch(es_client, all_threat_log_ids, "threat")
    
    all_benign_log_ids = benign_log_ids + llm_benign_log_ids
    if all_benign_log_ids:
        update_log_status_in_elasticsearch(es_client, all_benign_log_ids, "benign")
    
    print(f"\n--- Batch Processing Complete ---")
    print(f"Tier 1 Threats: {len(threat_logs)}")
    print(f"LLM-Detected Threats: {len(llm_threat_logs)}")
    print(f"Total Threats: {len(all_threat_logs)}")
    print(f"Incidents Created: {len(incidents)}")
    print(f"Incidents Stored: {len(stored_incident_ids)}")
    print(f"Total Benign Logs: {len(all_benign_log_ids)}")
    print(f"Tier 3 Escalations: {tier3_used}")
    
    # Return detailed statistics for demo mode
    processing_stats = {
        'tier1_threats': len(threat_logs),
        'llm_threats': len(llm_threat_logs),
        'total_threats': len(all_threat_logs),
        'benign_logs': len(all_benign_log_ids),
        'tier3_escalations': tier3_used,
        'incidents_created': len(incidents),
        'incidents_stored': len(stored_incident_ids)
    }
    
    return enriched_incidents, stored_incident_ids, processing_stats

def fetch_all_logs_for_demo(es_client, max_logs=None):
    """Fetch all available logs from Elasticsearch for demo purposes."""
    if max_logs is None:
        max_logs = MAX_DEMO_LOGS
    
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
            "size": max_logs,
            "sort": [{"@timestamp": {"order": "asc"}}]
        }
        
        response = es_client.search(index=UNIFIED_LOGS_INDEX, body=query)
        logs = [hit["_source"] for hit in response["hits"]["hits"]]
        log_ids = [hit["_id"] for hit in response["hits"]["hits"]]
        
        print(f"📥 Fetched {len(logs)} pending logs from Elasticsearch for demo")
        return logs, log_ids
        
    except Exception as e:
        print(f"❌ Error fetching logs from Elasticsearch: {e}")
        return [], []

def generate_demo_report(incidents, total_logs_processed, demo_stats):
    """Generate a comprehensive markdown report for the demo."""
    report_filename = f"security_intelligence_demo_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    
    print(f"--- Generating Demo Security Intelligence Report: {report_filename} ---")
    
    # Calculate statistics
    total_incidents = len(incidents)
    high_severity = len([i for i in incidents if i.get('severity') == 'High'])
    medium_severity = len([i for i in incidents if i.get('severity') == 'Medium'])
    low_severity = len([i for i in incidents if i.get('severity') == 'Low'])
    
    # Group incidents by classification
    classifications = {}
    for incident in incidents:
        classification = incident.get('classification', 'Unknown')
        if classification not in classifications:
            classifications[classification] = []
        classifications[classification].append(incident)
    
    report_content = f"""
# AION Security Intelligence Demo Report
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Demo Mode:** Processing existing logs from Elasticsearch

---

## 🎯 Executive Summary

This demo processed **{total_logs_processed}** logs from the Elasticsearch `{UNIFIED_LOGS_INDEX}` index and identified **{total_incidents}** security incidents requiring attention.

### 📊 Incident Statistics
- **Total Incidents:** {total_incidents}
- **High Severity:** {high_severity}
- **Medium Severity:** {medium_severity}
- **Low Severity:** {low_severity}

### 🔍 Processing Statistics
- **Tier 1 Threats Detected:** {demo_stats.get('tier1_threats', 0)}
- **LLM-Detected Threats:** {demo_stats.get('llm_threats', 0)}
- **Total Threats Processed:** {demo_stats.get('total_threats', 0)}
- **Benign Logs:** {demo_stats.get('benign_logs', 0)}
- **Tier 3 Escalations:** {demo_stats.get('tier3_escalations', 0)}

---

## 🚨 Security Incidents by Classification

"""
    
    # Add incidents grouped by classification
    for classification, incident_list in classifications.items():
        report_content += f"""
### {classification} ({len(incident_list)} incidents)

"""
        for incident in incident_list:
            report_content += f"""
#### **{incident['incident_id']}** (Severity: {incident.get('severity', 'N/A')})
- **Source IP:** `{incident['source_ip']}`
- **Event Count:** {incident['event_count']} events
- **Time Span:** {incident['first_event_at']} to {incident['last_event_at']}
- **Involved Hosts:** {', '.join(incident.get('involved_hosts', []))}
- **Threat Rules:** {', '.join(incident.get('threat_rules_triggered', []))}
- **Confidence Score:** {incident.get('confidence_score', 0.0):.2f}

**Executive Summary:**
{incident.get('executive_summary', 'N/A')}

**Attack Timeline:**
{incident.get('attack_timeline', 'N/A')}

**Recommended Actions:**
"""
            actions = incident.get('recommended_actions', [])
            if isinstance(actions, list):
                for i, action in enumerate(actions, 1):
                    report_content += f"{i}. {action}\n"
            else:
                report_content += f"- {actions}\n"
            
            report_content += "\n---\n"
    
    # Add methodology section
    report_content += f"""
## 🔧 Methodology

This demo utilized the AION incident-centric security orchestration workflow:

### 1. **Tier 1 Triage**
- Processed all logs through predefined threat detection rules
- Classified logs as THREAT, BENIGN, or UNCLASSIFIED
- Identified {demo_stats.get('tier1_threats', 0)} known threat patterns

### 2. **Tier 3 LLM Analysis**
- Escalated {demo_stats.get('tier3_escalations', 0)} unclassified logs to AI analysis
- LLM identified {demo_stats.get('llm_threats', 0)} additional threats
- Applied confidence scoring to minimize false positives

### 3. **Incident Correlation**
- Grouped related threats by source IP and attack pattern
- Applied correlation thresholds to create coherent incidents
- Generated {total_incidents} distinct security incidents

### 4. **Comprehensive Analysis**
- Each incident enriched with AI-powered analysis
- Generated executive summaries and attack timelines
- Provided actionable remediation recommendations

---

## 📈 Key Findings

"""
    
    if total_incidents > 0:
        # Find most common attack types
        attack_types = {}
        for incident in incidents:
            classification = incident.get('classification', 'Unknown')
            attack_types[classification] = attack_types.get(classification, 0) + 1
        
        most_common = max(attack_types.items(), key=lambda x: x[1])
        report_content += f"""
- **Most Common Attack Type:** {most_common[0]} ({most_common[1]} incidents)
- **Average Events per Incident:** {sum(i['event_count'] for i in incidents) / len(incidents):.1f}
- **Highest Confidence Score:** {max(i.get('confidence_score', 0) for i in incidents):.2f}
- **Time Range Analyzed:** {min(i['first_event_at'] for i in incidents)} to {max(i['last_event_at'] for i in incidents)}
"""
    else:
        report_content += """
- **No security incidents detected** in the analyzed log set
- All processed logs were classified as benign or normal activity
- System is operating within normal security parameters
"""
    
    report_content += f"""

---

## 🎯 Recommendations

Based on the analysis of {total_logs_processed} logs and {total_incidents} identified incidents:

1. **Immediate Actions:**
   - Review all High and Medium severity incidents
   - Implement recommended remediation steps
   - Monitor identified source IPs for continued activity

2. **System Improvements:**
   - Consider adjusting correlation thresholds based on findings
   - Review Tier 1 rules for potential enhancements
   - Monitor LLM analysis accuracy and adjust confidence thresholds

3. **Ongoing Monitoring:**
   - Deploy the real-time service for continuous monitoring
   - Set up alerts for new incidents in the `{INCIDENTS_INDEX}` index
   - Regular review of incident trends and patterns

---

## 📋 Technical Details

- **Elasticsearch Index:** `{UNIFIED_LOGS_INDEX}`
- **Incidents Index:** `{INCIDENTS_INDEX}`
- **Processing Mode:** Demo (Batch)
- **Max Logs Processed:** {total_logs_processed}
- **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

*This report was generated by the AION Autonomous Blue Team Agent incident-centric security orchestration system.*
"""
    
    # Write the report
    with open(report_filename, 'w') as f:
        f.write(report_content)
    
    print(f"✅ Demo report generated: {report_filename}")
    return report_filename

def run_demo_mode():
    """Run the orchestrator in demo mode - process existing logs and generate report."""
    print("🎬 Starting AION Security Orchestrator Demo Mode")
    print("=" * 60)
    print("This demo will:")
    print("1. Validate environment configuration")
    print("2. Fetch existing logs from Elasticsearch")
    print("3. Process them through the complete incident workflow")
    print("4. Generate a comprehensive security intelligence report")
    print("5. Store incidents in the backend")
    print("=" * 60)
    
    # Validate environment configuration
    if not validate_environment():
        print("❌ Environment validation failed. Please check your configuration.")
        return
    
    # Initialize Elasticsearch connection
    es_client = initialize_elasticsearch()
    if not es_client:
        print("❌ Cannot run demo without Elasticsearch connection. Exiting.")
        return
    
    # Fetch all available logs for demo
    print("\n📥 Fetching logs from Elasticsearch...")
    logs, log_ids = fetch_all_logs_for_demo(es_client, max_logs=MAX_DEMO_LOGS)
    
    if not logs:
        print("❌ No logs found in Elasticsearch. Please ensure logs are available in the unified-logs index.")
        return
    
    print(f"✅ Found {len(logs)} logs to process")
    
    # Process logs through the complete workflow
    print("\n🔄 Processing logs through incident-centric workflow...")
    incidents, incident_ids, processing_stats = process_logs_batch(es_client, logs, log_ids)
    
    # Generate comprehensive report
    print("\n📊 Generating comprehensive security intelligence report...")
    report_filename = generate_demo_report(incidents, len(logs), processing_stats)
    
    # Summary
    print(f"\n🎉 Demo completed successfully!")
    print(f"   -> Processed {len(logs)} logs")
    print(f"   -> Created {len(incidents)} incidents")
    print(f"   -> Stored {len(incident_ids)} incidents in Elasticsearch")
    print(f"   -> Generated report: {report_filename}")
    
    return incidents, report_filename

def run_real_time_service():
    """Run the orchestrator as a continuous real-time service."""
    import time
    
    print("🚀 Starting AION Real-Time Security Orchestrator Service")
    print(f"⏰ Processing interval: {LOOP_DELAY_SECONDS} seconds")
    print("🔄 Service will run continuously. Press Ctrl+C to stop.")
    print("-" * 60)
    
    # Validate environment configuration
    if not validate_environment():
        print("❌ Environment validation failed. Please check your configuration.")
        return
    
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
                # Process the batch using incident-centric workflow
                incidents, incident_ids, stats = process_logs_batch(es_client, logs, log_ids)
                
                print(f"✅ Cycle #{cycle_count} completed successfully")
                print(f"   -> Created {len(incidents)} incidents")
                print(f"   -> Stored {len(incident_ids)} incidents in Elasticsearch")
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
    if len(sys.argv) > 1:
        if sys.argv[1] == "--service":
            run_real_time_service()
        elif sys.argv[1] == "--demo":
            run_demo_mode()
        else:
            print("Usage:")
            print("  python orchestrator.py --demo     # Run demo mode (process existing logs)")
            print("  python orchestrator.py --service  # Run real-time service")
    else:
        print("AION Security Orchestrator")
        print("=" * 40)
        print("Usage:")
        print("  python orchestrator.py --demo     # Run demo mode (process existing logs)")
        print("  python orchestrator.py --service  # Run real-time service")
        print("")
        print("Demo Mode:")
        print(f"  - Processes up to {MAX_DEMO_LOGS} existing logs from Elasticsearch")
        print("  - Generates comprehensive security intelligence report")
        print("  - Creates incidents in the backend")
        print("")
        print("Service Mode:")
        print("  - Runs continuously, processing new logs every 30 seconds")
        print("  - Real-time incident detection and response")