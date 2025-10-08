"""
Analysis Mode CLI
Handles log file analysis workflow.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import (
    validate_environment, 
    initialize_elasticsearch, 
    process_logs_batch,
    generate_demo_report
)
from utils.log_processor import LogProcessor


def run_analysis(logfile_path: Path, args) -> bool:
    """
    Run the complete analysis workflow for a log file.
    
    Args:
        logfile_path: Path to the log file to analyze
        args: Command line arguments
        
    Returns:
        True if analysis completed successfully, False otherwise
    """
    try:
        # Step 1: Validate environment
        print("🔍 Validating environment configuration...")
        if not validate_environment():
            print("❌ Environment validation failed. Please check your configuration.")
            return False
        
        # Step 2: Initialize Elasticsearch
        print("🔌 Connecting to Elasticsearch...")
        es_client = initialize_elasticsearch()
        if not es_client:
            print("❌ Cannot connect to Elasticsearch. Please ensure it's running.")
            return False
        
        # Step 3: Process log file
        print("📁 Processing log file...")
        processor = LogProcessor(es_client)
        processing_stats = processor.process_log_file(logfile_path)
        
        if not processing_stats['success']:
            print(f"❌ Failed to process log file: {processing_stats.get('error', 'Unknown error')}")
            return False
        
        print(f"✅ Successfully processed {processing_stats['uploaded_count']} log entries")
        
        # Step 4: Run threat analysis
        print("🛡️  Running threat analysis...")
        analysis_results = run_threat_analysis(es_client, processing_stats)
        
        if not analysis_results['success']:
            print(f"❌ Threat analysis failed: {analysis_results.get('error', 'Unknown error')}")
            return False
        
        # Step 5: Generate report
        print("📊 Generating security report...")
        report_path = generate_analysis_report(
            analysis_results, 
            processing_stats, 
            logfile_path,
            args
        )
        
        if not report_path:
            print("❌ Failed to generate report")
            return False
        
        # Step 6: Cleanup (if requested)
        if args.cleanup:
            print("🧹 Cleaning up processed data...")
            cleanup_processed_data(es_client, processing_stats)
        
        # Step 7: Display summary
        display_analysis_summary(analysis_results, processing_stats, report_path, args)
        
        return True
        
    except Exception as e:
        print(f"❌ Analysis failed with error: {e}")
        return False


def run_threat_analysis(es_client, processing_stats: dict) -> dict:
    """
    Run threat analysis on the processed logs.
    
    Args:
        es_client: Elasticsearch client
        processing_stats: Statistics from log processing
        
    Returns:
        Dictionary with analysis results
    """
    try:
        # Fetch the logs we just uploaded
        # Limit the query size to avoid Elasticsearch limits
        max_size = min(processing_stats['uploaded_count'], 10000)
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "aion"}},
                        {"term": {"aion.status.keyword": "pending"}},
                        {"term": {"aion.source_file.keyword": processing_stats['file_path']}}
                    ]
                }
            },
            "size": max_size,
            "sort": [{"@timestamp": {"order": "desc"}}]  # Get most recent logs first
        }
        
        response = es_client.search(index="unified-logs", body=query)
        logs = [hit['_source'] for hit in response['hits']['hits']]
        log_ids = [hit['_id'] for hit in response['hits']['hits']]
        
        # Inform user about analysis scope
        total_logs = processing_stats['uploaded_count']
        analyzed_logs = len(logs)
        if total_logs > 10000:
            print(f"ℹ️  Analyzing {analyzed_logs:,} logs (limited from {total_logs:,} total due to Elasticsearch limits)")
        else:
            print(f"ℹ️  Analyzing {analyzed_logs:,} logs")
        
        if not logs:
            return {
                'success': False,
                'error': 'No logs found for analysis',
                'incidents': [],
                'processing_stats': {}
            }
        
        print(f"🔍 Analyzing {len(logs)} log entries...")
        
        # Process logs through the threat detection pipeline
        incidents, incident_ids, processing_stats = process_logs_batch(es_client, logs, log_ids)
        
        return {
            'success': True,
            'incidents': incidents,
            'incident_ids': incident_ids,
            'processing_stats': processing_stats,
            'total_logs_analyzed': len(logs)
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'incidents': [],
            'processing_stats': {}
        }


def generate_analysis_report(analysis_results: dict, processing_stats: dict, 
                           logfile_path: Path, args) -> Optional[Path]:
    """
    Generate a comprehensive security analysis report.
    
    Args:
        analysis_results: Results from threat analysis
        processing_stats: Statistics from log processing
        logfile_path: Original log file path
        args: Command line arguments
        
    Returns:
        Path to generated report file, or None if failed
    """
    try:
        # Determine output directory
        output_dir = Path(args.output) if args.output else Path.cwd()
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate report filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"aion_analysis_report_{timestamp}.{args.format}"
        report_path = output_dir / filename
        
        # Generate report content based on format
        if args.format == 'markdown':
            content = generate_markdown_report(analysis_results, processing_stats, logfile_path)
        elif args.format == 'json':
            content = generate_json_report(analysis_results, processing_stats, logfile_path)
        elif args.format == 'html':
            content = generate_html_report(analysis_results, processing_stats, logfile_path)
        else:
            raise ValueError(f"Unsupported report format: {args.format}")
        
        # Write report to file
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Report generated: {report_path}")
        return report_path
        
    except Exception as e:
        print(f"❌ Failed to generate report: {e}")
        return None


def generate_markdown_report(analysis_results: dict, processing_stats: dict, logfile_path: Path) -> str:
    """Generate markdown format report matching the detailed demo report format."""
    incidents = analysis_results.get('incidents', [])
    processing_stats_analysis = analysis_results.get('processing_stats', {})
    total_logs = processing_stats.get('uploaded_count', 0)
    
    # Calculate statistics
    tier1_threats = processing_stats_analysis.get('tier1_threats', 0)
    llm_threats = processing_stats_analysis.get('llm_threats', 0)
    total_threats = tier1_threats + llm_threats
    benign_logs = total_logs - total_threats
    tier3_escalations = processing_stats_analysis.get('tier3_escalations', 0)
    
    # Group incidents by classification
    incident_classifications = {}
    for incident in incidents:
        classification = incident.get('classification', 'Unknown Threat')
        if classification not in incident_classifications:
            incident_classifications[classification] = []
        incident_classifications[classification].append(incident)
    
    # Calculate severity statistics
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for incident in incidents:
        severity = incident.get('severity', 'Low')
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    report = f"""# AION Security Intelligence Analysis Report
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Analysis Mode:** File-based log analysis

---

## 🎯 Executive Summary

This analysis processed **{total_logs}** logs from the file `{logfile_path}` and identified **{len(incidents)}** security incidents requiring attention.

### 📊 Incident Statistics
- **Total Incidents:** {len(incidents)}
- **High Severity:** {severity_counts['High']}
- **Medium Severity:** {severity_counts['Medium']}
- **Low Severity:** {severity_counts['Low']}

### 🔍 Processing Statistics
- **Tier 1 Threats Detected:** {tier1_threats}
- **LLM-Detected Threats:** {llm_threats}
- **Total Threats Processed:** {total_threats}
- **Benign Logs:** {benign_logs}
- **Tier 3 Escalations:** {tier3_escalations}

---

## 🚨 Security Incidents by Classification

"""
    
    if incidents:
        for classification, classification_incidents in incident_classifications.items():
            report += f"### {classification} ({len(classification_incidents)} incidents)\n\n"
            
            for incident in classification_incidents:
                incident_id = incident.get('incident_id', 'Unknown')
                severity = incident.get('severity', 'Unknown')
                source_ips = incident.get('incident_metadata', {}).get('source_ips', [])
                event_count = incident.get('incident_metadata', {}).get('event_count', 0)
                time_span = incident.get('incident_metadata', {}).get('time_span', 'N/A')
                involved_hosts = incident.get('incident_metadata', {}).get('involved_hosts', [])
                threat_rules = incident.get('incident_metadata', {}).get('threat_rules', [])
                confidence_score = incident.get('confidence_score', 0.0)
                
                # Format source IPs
                source_ip_str = ', '.join(source_ips) if source_ips else 'Unknown'
                
                # Format involved hosts
                hosts_str = ', '.join(involved_hosts) if involved_hosts else 'None'
                
                # Format threat rules
                rules_str = ', '.join(threat_rules) if threat_rules else 'Unknown'
                
                report += f"#### **{incident_id}** (Severity: {severity})\n"
                report += f"- **Source IP:** `{source_ip_str}`\n"
                report += f"- **Event Count:** {event_count} events\n"
                report += f"- **Time Span:** {time_span}\n"
                report += f"- **Involved Hosts:** {hosts_str}\n"
                report += f"- **Threat Rules:** {rules_str}\n"
                report += f"- **Confidence Score:** {confidence_score:.2f}\n\n"
                
                # Executive Summary
                executive_summary = incident.get('executive_summary', '')
                if executive_summary:
                    report += f"**Executive Summary:**\n{executive_summary}\n\n"
                else:
                    report += f"**Executive Summary:**\nNo executive summary available.\n\n"
                
                # Attack Timeline
                attack_timeline = incident.get('attack_timeline', '')
                if attack_timeline:
                    report += f"**Attack Timeline:**\n{attack_timeline}\n\n"
                else:
                    report += f"**Attack Timeline:**\nNo timeline information available.\n\n"
                
                # Recommended Actions
                recommended_actions = incident.get('recommended_actions', '')
                if recommended_actions:
                    report += f"**Recommended Actions:**\n{recommended_actions}\n\n"
                else:
                    report += f"**Recommended Actions:**\nNo specific recommendations available.\n\n"
                
                report += "---\n\n"
    else:
        report += "✅ **No security incidents detected**\n\n"
        report += "The analyzed logs did not contain any detectable security threats.\n\n"
    
    # Add methodology section
    report += """## 🔧 Methodology

This analysis utilized the AION incident-centric security orchestration workflow:

### 1. **Tier 1 Triage**
- Processed all logs through predefined threat detection rules
- Classified logs as THREAT, BENIGN, or UNCLASSIFIED
- Identified known threat patterns using regex-based rules

### 2. **Tier 3 LLM Analysis**
- Escalated unclassified logs to AI analysis
- LLM identified additional threats using natural language processing
- Applied confidence scoring to minimize false positives

### 3. **Incident Correlation**
- Grouped related threats by source IP and attack pattern
- Applied correlation thresholds to create coherent incidents
- Generated distinct security incidents

### 4. **Comprehensive Analysis**
- Each incident enriched with AI-powered analysis
- Generated executive summaries and attack timelines
- Provided actionable remediation recommendations

---

## 📈 Key Findings

"""
    
    if incidents:
        # Calculate key findings
        total_events = sum(incident.get('incident_metadata', {}).get('event_count', 0) for incident in incidents)
        avg_events = total_events / len(incidents) if incidents else 0
        max_confidence = max(incident.get('confidence_score', 0) for incident in incidents) if incidents else 0
        
        # Find most common attack type
        attack_types = {}
        for incident in incidents:
            classification = incident.get('classification', 'Unknown')
            attack_types[classification] = attack_types.get(classification, 0) + 1
        
        most_common = max(attack_types.items(), key=lambda x: x[1]) if attack_types else ('None', 0)
        
        # Get time range
        time_ranges = []
        for incident in incidents:
            time_span = incident.get('incident_metadata', {}).get('time_span', '')
            if time_span and ' to ' in time_span:
                time_ranges.append(time_span)
        
        time_range_str = time_ranges[0] if time_ranges else 'N/A'
        
        report += f"""- **Most Common Attack Type:** {most_common[0]} ({most_common[1]} incidents)
- **Average Events per Incident:** {avg_events:.1f}
- **Highest Confidence Score:** {max_confidence:.2f}
- **Time Range Analyzed:** {time_range_str}

"""
    else:
        report += "- **No threats detected in the analyzed logs**\n\n"
    
    # Add recommendations section
    report += """## 🎯 Recommendations

Based on the analysis of the log file:

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
   - Set up alerts for new incidents in the `aion-incidents` index
   - Regular review of incident trends and patterns

---

## 📋 Technical Details

"""
    
    report += f"""- **Log File:** `{logfile_path}`
- **Elasticsearch Index:** `unified-logs`
- **Incidents Index:** `aion-incidents`
- **Processing Mode:** File-based Analysis
- **Logs Processed:** {total_logs}
- **Log Type:** {processing_stats.get('log_type', 'Unknown')}
- **File Size:** {processing_stats.get('file_size', 0)} bytes
- **Report Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

*This report was generated by the AION Autonomous Blue Team Agent incident-centric security orchestration system.*
"""
    
    return report


def generate_json_report(analysis_results: dict, processing_stats: dict, logfile_path: Path) -> str:
    """Generate JSON format report."""
    report_data = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "log_file": str(logfile_path),
            "aion_version": "1.0.0"
        },
        "analysis_summary": {
            "total_logs_processed": processing_stats.get('uploaded_count', 0),
            "total_incidents": len(analysis_results.get('incidents', [])),
            "processing_stats": processing_stats,
            "analysis_stats": analysis_results.get('processing_stats', {})
        },
        "incidents": analysis_results.get('incidents', []),
        "processing_details": processing_stats
    }
    
    return json.dumps(report_data, indent=2, default=str)


def generate_html_report(analysis_results: dict, processing_stats: dict, logfile_path: Path) -> str:
    """Generate HTML format report."""
    incidents = analysis_results.get('incidents', [])
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AION Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #e8f4fd; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .incident {{ background: #fff3cd; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ffc107; }}
        .critical {{ border-left-color: #dc3545; background: #f8d7da; }}
        .high {{ border-left-color: #fd7e14; background: #fff3cd; }}
        .medium {{ border-left-color: #ffc107; background: #fff3cd; }}
        .low {{ border-left-color: #28a745; background: #d4edda; }}
        .stats {{ background: #f8f9fa; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AION Security Analysis Report</h1>
        <p><strong>Log File:</strong> {logfile_path}</p>
        <p><strong>Analysis Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Analysis Summary</h2>
        <ul>
            <li><strong>Total Logs Processed:</strong> {processing_stats.get('uploaded_count', 0)}</li>
            <li><strong>Total Incidents Detected:</strong> {len(incidents)}</li>
            <li><strong>Log Type:</strong> {processing_stats.get('log_type', 'Unknown')}</li>
        </ul>
    </div>
"""
    
    if incidents:
        html += "<h2>🚨 Security Incidents</h2>\n"
        for i, incident in enumerate(incidents, 1):
            severity = incident.get('severity', 'Unknown').lower()
            html += f"""
    <div class="incident {severity}">
        <h3>Incident #{i}: {incident.get('classification', 'Unknown Threat')}</h3>
        <p><strong>Severity:</strong> {incident.get('severity', 'Unknown')}</p>
        <p><strong>Confidence:</strong> {incident.get('confidence_score', 'N/A')}</p>
        <p><strong>Description:</strong> {incident.get('hypothesis', 'No description available')}</p>
        <p><strong>Recommended Action:</strong> {incident.get('recommended_action', 'No action specified')}</p>
    </div>
"""
    else:
        html += """
    <div class="summary">
        <h2>✅ No Security Incidents Detected</h2>
        <p>The analyzed logs did not contain any detectable security threats.</p>
    </div>
"""
    
    html += f"""
    <div class="stats">
        <h2>📈 Processing Statistics</h2>
        <ul>
            <li><strong>Logs Parsed:</strong> {processing_stats.get('parsed_count', 0)}</li>
            <li><strong>Logs Normalized:</strong> {processing_stats.get('normalized_count', 0)}</li>
            <li><strong>Logs Uploaded:</strong> {processing_stats.get('uploaded_count', 0)}</li>
            <li><strong>Processing Errors:</strong> {processing_stats.get('error_count', 0)}</li>
        </ul>
    </div>
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; color: #666;">
        <p><em>Report generated by AION - Autonomous Blue Team Security Platform</em></p>
    </footer>
</body>
</html>
"""
    
    return html


def cleanup_processed_data(es_client, processing_stats: dict):
    """Clean up processed data from Elasticsearch."""
    try:
        # Delete logs from the specific file
        query = {
            "query": {
                "term": {
                    "aion.source_file": processing_stats['file_path']
                }
            }
        }
        
        response = es_client.delete_by_query(
            index="unified-logs",
            body=query,
            wait_for_completion=True
        )
        
        deleted_count = response.get('deleted', 0)
        print(f"✅ Cleaned up {deleted_count} log entries from Elasticsearch")
        
    except Exception as e:
        print(f"⚠️  Cleanup failed: {e}")


def display_analysis_summary(analysis_results: dict, processing_stats: dict, 
                           report_path: Path, args):
    """Display analysis summary to the user."""
    incidents = analysis_results.get('incidents', [])
    
    print("\n" + "="*60)
    print("🎉 ANALYSIS COMPLETED SUCCESSFULLY!")
    print("="*60)
    print(f"📁 Log File: {processing_stats['file_path']}")
    print(f"📊 Logs Processed: {processing_stats['uploaded_count']}")
    print(f"🚨 Incidents Detected: {len(incidents)}")
    print(f"📄 Report Generated: {report_path}")
    
    if incidents:
        print(f"\n🚨 Security Incidents Found:")
        severity_counts = {}
        for incident in incidents:
            severity = incident.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items(), key=lambda x: ['Critical', 'High', 'Medium', 'Low'].index(x[0]) if x[0] in ['Critical', 'High', 'Medium', 'Low'] else 999):
            print(f"   - {severity}: {count} incidents")
    else:
        print(f"\n✅ No security threats detected in the analyzed logs")
    
    print(f"\n📋 Next Steps:")
    print(f"   1. Review the detailed report: {report_path}")
    if not args.cleanup:
        print(f"   2. Data retained in Elasticsearch for further analysis")
        print(f"   3. Access Kibana at http://localhost:5601 to explore the data")
    else:
        print(f"   2. Processed data has been cleaned up from Elasticsearch")
    
    print("="*60)
