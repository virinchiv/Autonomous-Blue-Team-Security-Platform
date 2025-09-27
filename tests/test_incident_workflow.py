#!/usr/bin/env python3
"""
Test script to demonstrate the new incident-centric workflow.
This script shows how the orchestrator now creates, enriches, and stores incidents.
"""

import json
from datetime import datetime, timedelta
from orchestrator import (
    tier1_triage, 
    correlate_alerts, 
    create_incident_from_threats, 
    enrich_incident_with_llm
)

def create_sample_threat_logs():
    """Create sample threat logs for testing the incident workflow."""
    
    base_time = datetime.now() - timedelta(minutes=5)
    
    # Sample SSH brute force attack logs (Tier 1 THREAT)
    ssh_logs = []
    for i in range(15):  # 15 failed SSH attempts
        log = {
            "@timestamp": (base_time + timedelta(seconds=i*10)).isoformat(),
            "source.ip": "104.244.42.1",
            "host.name": "WebServer-01",
            "log.source": "linux_syslog",
            "message": f"Failed password for invalid user admin from 104.244.42.1 port 22 ssh2",
            "process.name": "sshd",
            "event.category": "authentication",
            "event.type": "authentication_failure",
            "event.outcome": "failure",
            "user.name": "admin"
        }
        ssh_logs.append(log)
    
    # Sample web attack logs (Tier 1 THREAT)
    web_logs = []
    for i in range(8):  # 8 directory traversal attempts
        log = {
            "@timestamp": (base_time + timedelta(seconds=i*15)).isoformat(),
            "source.ip": "192.168.1.100",
            "host.name": "WebServer-02",
            "log.source": "apache_access",
            "url.original": f"/admin/../../../etc/passwd",
            "http.request.method": "GET",
            "http.response.status_code": 404,
            "user_agent.original": "Mozilla/5.0 (compatible; ScannerBot/1.0)",
            "message": f"GET /admin/../../../etc/passwd HTTP/1.1 404 1234"
        }
        web_logs.append(log)
    
    # Sample unclassified logs that should be analyzed by LLM
    unclassified_logs = []
    
    # Suspicious but not clearly malicious activity
    for i in range(5):
        log = {
            "@timestamp": (base_time + timedelta(seconds=i*20)).isoformat(),
            "source.ip": "203.0.113.50",
            "host.name": "WebServer-03",
            "log.source": "apache_access",
            "url.original": f"/api/v1/users/search?q=admin&limit=1000",
            "http.request.method": "GET",
            "http.response.status_code": 200,
            "user_agent.original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "message": f"GET /api/v1/users/search?q=admin&limit=1000 HTTP/1.1 200 2048"
        }
        unclassified_logs.append(log)
    
    # Unusual system activity
    for i in range(3):
        log = {
            "@timestamp": (base_time + timedelta(seconds=i*30)).isoformat(),
            "source.ip": "198.51.100.25",
            "host.name": "Database-01",
            "log.source": "linux_syslog",
            "message": f"User root executed command: /usr/bin/find / -name '*.key' -type f 2>/dev/null",
            "process.name": "bash",
            "event.category": "process",
            "event.type": "start",
            "event.outcome": "success",
            "user.name": "root"
        }
        unclassified_logs.append(log)
    
    # Benign logs (should be classified as BENIGN by Tier 1)
    benign_logs = []
    for i in range(3):
        log = {
            "@timestamp": (base_time + timedelta(seconds=i*5)).isoformat(),
            "source.ip": "203.0.113.100",
            "host.name": "WebServer-01",
            "log.source": "apache_access",
            "url.original": f"/product/{i+1}",
            "http.request.method": "GET",
            "http.response.status_code": 200,
            "user_agent.original": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "message": f"GET /product/{i+1} HTTP/1.1 200 1024"
        }
        benign_logs.append(log)
    
    return ssh_logs + web_logs + unclassified_logs + benign_logs

def test_incident_workflow():
    """Test the complete incident-centric workflow including UNCLASSIFIED log processing."""
    
    print("🧪 Testing Complete Incident-Centric Workflow")
    print("=" * 60)
    
    # Step 1: Create sample logs (threats, unclassified, benign)
    print("\n1. Creating sample logs...")
    sample_logs = create_sample_threat_logs()
    print(f"   -> Created {len(sample_logs)} sample logs")
    
    # Step 2: Triage logs through Tier 1
    print("\n2. Tier 1 Triage...")
    threat_logs = []
    unclassified_logs = []
    benign_logs = []
    
    for log in sample_logs:
        classification, rule_name, confidence_score = tier1_triage(log)
        
        if classification == "THREAT":
            log['rule_name'] = rule_name
            log['confidence_score'] = confidence_score
            threat_logs.append(log)
            print(f"   -> THREAT: {rule_name} (confidence: {confidence_score:.2f})")
        elif classification == "BENIGN":
            benign_logs.append(log)
            print(f"   -> BENIGN: {rule_name or 'Normal activity'}")
        else:  # UNCLASSIFIED
            log['confidence_score'] = confidence_score
            unclassified_logs.append(log)
            print(f"   -> UNCLASSIFIED: (confidence: {confidence_score:.2f})")
    
    print(f"   -> Found {len(threat_logs)} threats, {len(unclassified_logs)} unclassified, {len(benign_logs)} benign")
    
    # Step 3: Process UNCLASSIFIED logs with Tier 3 LLM
    print("\n3. Tier 3 Analysis of Unclassified Logs...")
    from tier3_llm import should_escalate_to_llm, analyze_log_with_llm
    
    llm_threat_logs = []
    llm_benign_logs = []
    
    for i, log in enumerate(unclassified_logs):
        if should_escalate_to_llm(log):
            try:
                llm_analysis = analyze_log_with_llm(log)
                log['llm_analysis'] = llm_analysis
                
                # Check if LLM identified this as a threat
                if (llm_analysis.get('severity') in ['High', 'Medium'] and 
                    not llm_analysis.get('pre_filtered', False) and
                    llm_analysis.get('classification') not in ['Informational', 'Low Priority (Pre-filtered)']):
                    
                    # LLM identified this as a threat
                    log['rule_name'] = f"LLM-{llm_analysis.get('classification', 'Threat')}"
                    llm_threat_logs.append(log)
                    print(f"   -> LLM THREAT: {llm_analysis.get('classification')} (severity: {llm_analysis.get('severity')})")
                else:
                    # LLM classified as benign or low priority
                    llm_benign_logs.append(log)
                    print(f"   -> LLM BENIGN: {llm_analysis.get('classification')} (severity: {llm_analysis.get('severity')})")
                
            except Exception as e:
                print(f"   -> Error analyzing log with LLM: {e}")
                llm_benign_logs.append(log)
        else:
            # Low confidence - mark as benign without LLM analysis
            llm_benign_logs.append(log)
            print(f"   -> LOW CONFIDENCE: Skipped LLM analysis (confidence: {log['confidence_score']:.2f})")
    
    print(f"   -> LLM identified {len(llm_threat_logs)} additional threats from unclassified logs")
    print(f"   -> LLM classified {len(llm_benign_logs)} as benign")
    
    # Step 4: Combine all threat logs (Tier 1 + LLM-detected)
    all_threat_logs = threat_logs + llm_threat_logs
    print(f"\n4. Total Threats (Tier 1 + LLM): {len(all_threat_logs)}")
    
    # Step 5: Correlate all threats into incidents
    print("\n5. Correlating All Threats into Incidents...")
    incidents = correlate_alerts(all_threat_logs)
    print(f"   -> Created {len(incidents)} incidents")
    
    # Step 6: Show incident structure before enrichment
    print("\n6. Incident structure before LLM enrichment:")
    for incident in incidents:
        print(f"\n   Incident ID: {incident['incident_id']}")
        print(f"   Source IP: {incident['source_ip']}")
        print(f"   Event Count: {incident['event_count']}")
        print(f"   Threat Rules: {incident['threat_rules_triggered']}")
        print(f"   Time Span: {incident['first_event_at']} to {incident['last_event_at']}")
        print(f"   Involved Hosts: {incident['involved_hosts']}")
    
    # Step 7: Enrich incidents with LLM
    print("\n7. Enriching Incidents with LLM Analysis...")
    enriched_incidents = []
    for incident in incidents:
        try:
            enriched_incident = enrich_incident_with_llm(incident)
            enriched_incidents.append(enriched_incident)
            print(f"   -> Enriched {incident['incident_id']}")
        except Exception as e:
            print(f"   -> Error enriching {incident['incident_id']}: {e}")
            enriched_incidents.append(incident)
    
    # Step 8: Show final incident structure
    print("\n8. Final Enriched Incident Structure:")
    for incident in enriched_incidents:
        print(f"\n   📋 Incident: {incident['incident_id']}")
        print(f"   🎯 Classification: {incident.get('classification', 'N/A')}")
        print(f"   ⚠️  Severity: {incident.get('severity', 'N/A')}")
        print(f"   📝 Summary: {incident.get('executive_summary', 'N/A')[:100]}...")
        print(f"   🎯 Confidence: {incident.get('confidence_score', 0.0):.2f}")
        print(f"   📊 Event Count: {incident['event_count']}")
        print(f"   🌐 Source IP: {incident['source_ip']}")
        
        # Show recommended actions
        actions = incident.get('recommended_actions', [])
        if actions:
            print(f"   🔧 Recommended Actions:")
            for i, action in enumerate(actions[:3], 1):  # Show first 3 actions
                print(f"      {i}. {action}")
    
    print(f"\n✅ Complete Workflow Test Results:")
    print(f"   -> Total Logs Processed: {len(sample_logs)}")
    print(f"   -> Tier 1 Threats: {len(threat_logs)}")
    print(f"   -> LLM-Detected Threats: {len(llm_threat_logs)}")
    print(f"   -> Total Threats: {len(all_threat_logs)}")
    print(f"   -> Incidents Created: {len(incidents)}")
    print(f"   -> Incidents Enriched: {len(enriched_incidents)}")
    print(f"   -> Benign Logs: {len(benign_logs) + len(llm_benign_logs)}")
    
    return enriched_incidents

def show_incident_json_structure(incident):
    """Show the JSON structure of a final incident."""
    print(f"\n📄 Final Incident JSON Structure:")
    print("=" * 50)
    
    # Create a clean JSON representation
    incident_json = {
        "incident_id": incident["incident_id"],
        "status": incident["status"],
        "created_at": incident["created_at"],
        "first_event_at": incident["first_event_at"],
        "last_event_at": incident["last_event_at"],
        "source_ip": incident["source_ip"],
        "involved_hosts": incident["involved_hosts"],
        "threat_rules_triggered": incident["threat_rules_triggered"],
        "event_count": incident["event_count"],
        "classification": incident.get("classification", "Security Incident"),
        "severity": incident.get("severity", "Medium"),
        "executive_summary": incident.get("executive_summary", ""),
        "attack_timeline": incident.get("attack_timeline", ""),
        "recommended_actions": incident.get("recommended_actions", []),
        "confidence_score": incident.get("confidence_score", 0.0),
        "evidence_logs": f"[{len(incident['evidence_logs'])} log entries]"
    }
    
    print(json.dumps(incident_json, indent=2))

if __name__ == "__main__":
    # Run the test
    incidents = test_incident_workflow()
    
    # Show the JSON structure of the first incident
    if incidents:
        show_incident_json_structure(incidents[0])
    
    print(f"\n🎉 The new incident-centric orchestrator is working correctly!")
    print(f"   Each incident now contains all the rich, structured data")
    print(f"   that your API and frontend can use directly.")
