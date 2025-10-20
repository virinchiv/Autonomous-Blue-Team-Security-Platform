"""
Monitor Mode CLI
Handles real-time monitoring workflow.
"""

import os
import sys
import time
from datetime import datetime
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import (
    validate_environment, 
    initialize_elasticsearch, 
    process_logs_batch,
    fetch_pending_logs_from_elasticsearch,
    UNIFIED_LOGS_INDEX,
    INCIDENTS_INDEX
)


def run_monitoring(args):
    """
    Run the real-time monitoring service.
    
    Args:
        args: Command line arguments
    """
    try:
        # Step 1: Validate environment
        print("🔍 Validating environment configuration...")
        if not validate_environment():
            print("❌ Environment validation failed. Please check your configuration.")
            return
        
        # Step 2: Initialize Elasticsearch
        print("🔌 Connecting to Elasticsearch...")
        es_client = initialize_elasticsearch()
        if not es_client:
            print("❌ Cannot connect to Elasticsearch. Please ensure it's running.")
            return
        
        # Step 3: Display monitoring configuration
        display_monitoring_info(args)
        
        # Step 4: Start monitoring loop
        start_monitoring_loop(es_client, args)
        
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user")
    except Exception as e:
        print(f"\n❌ Monitoring failed with error: {e}")


def display_monitoring_info(args):
    """Display monitoring configuration and instructions."""
    print("\n" + "="*60)
    print("🚀 AION REAL-TIME MONITORING MODE")
    print("="*60)
    print(f"⏰ Processing Interval: {args.interval} seconds")
    print(f"📦 Batch Size: {args.batch_size} logs per cycle")
    print(f"🔄 Mode: Continuous monitoring")
    print("="*60)
    
    print("\n📋 How Real-Time Monitoring Works:")
    print("1. 🔍 Continuously scans Elasticsearch for new logs")
    print("2. 🛡️  Processes logs through threat detection pipeline")
    print("3. 📊 Creates incidents for detected threats")
    print("4. 💾 Stores incidents in Elasticsearch")
    print("5. 🔄 Repeats every specified interval")
    
    print("\n📥 Log Ingestion Options:")
    print("• Use Filebeat to send logs to Elasticsearch")
    print("• Use Logstash to process and forward logs")
    print("• Use custom scripts to write logs to Elasticsearch")
    print("• Use the 'analyze' command to process log files")
    
    print("\n🎯 Monitoring Targets:")
    print("• Index: unified-logs")
    print("• Status: pending (logs awaiting analysis)")
    print("• Output: aion-incidents (detected security incidents)")
    
    print("\n🛑 To stop monitoring: Press Ctrl+C")
    print("="*60)


def start_monitoring_loop(es_client, args):
    """Start the main monitoring loop."""
    cycle_count = 0
    total_incidents = 0
    total_logs_processed = 0
    
    print(f"\n🔄 Starting monitoring loop...")
    print(f"📅 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    try:
        while True:
            cycle_count += 1
            cycle_start_time = datetime.now()
            
            print(f"\n🔄 Processing Cycle #{cycle_count} - {cycle_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Fetch pending logs from Elasticsearch
            logs, log_ids = fetch_pending_logs_from_elasticsearch(es_client, args.batch_size)
            
            if logs:
                print(f"📥 Found {len(logs)} pending logs to process")
                
                # Process the batch using incident-centric workflow
                incidents, incident_ids, stats = process_logs_batch(es_client, logs, log_ids)
                
                # Update totals
                total_incidents += len(incidents)
                total_logs_processed += len(logs)
                
                # Calculate cycle duration
                cycle_duration = (datetime.now() - cycle_start_time).total_seconds()
                
                # Display cycle results
                display_cycle_results(cycle_count, len(logs), len(incidents), cycle_duration, stats)
                
            else:
                print(f"ℹ️  No pending logs found in cycle #{cycle_count}")
            
            # Display cumulative statistics
            if cycle_count % 10 == 0:  # Every 10 cycles
                display_cumulative_stats(cycle_count, total_logs_processed, total_incidents)
            
            # Wait before next cycle
            print(f"⏳ Waiting {args.interval} seconds before next cycle...")
            time.sleep(args.interval)
            
    except KeyboardInterrupt:
        print(f"\n🛑 Monitoring stopped by user after {cycle_count} cycles")
        display_final_stats(cycle_count, total_logs_processed, total_incidents)
    except Exception as e:
        print(f"\n❌ Monitoring error in cycle #{cycle_count}: {e}")
        print("🔄 Continuing monitoring...")
        time.sleep(args.interval)


def display_cycle_results(cycle_count: int, logs_processed: int, incidents_created: int, 
                         cycle_duration: float, stats: dict):
    """Display results for a single monitoring cycle."""
    print(f"✅ Cycle #{cycle_count} completed in {cycle_duration:.2f} seconds")
    print(f"   📊 Logs Processed: {logs_processed}")
    print(f"   🚨 Incidents Created: {incidents_created}")
    
    if incidents_created > 0:
        # Show incident breakdown by severity
        severity_counts = {}
        for incident in stats.get('incidents', []):
            severity = incident.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            print(f"   📈 Incident Breakdown:")
            for severity, count in sorted(severity_counts.items(), 
                                        key=lambda x: ['Critical', 'High', 'Medium', 'Low'].index(x[0]) 
                                        if x[0] in ['Critical', 'High', 'Medium', 'Low'] else 999):
                print(f"      - {severity}: {count}")


def display_cumulative_stats(cycle_count: int, total_logs: int, total_incidents: int):
    """Display cumulative statistics every 10 cycles."""
    print(f"\n📊 CUMULATIVE STATISTICS (After {cycle_count} cycles)")
    print("-" * 50)
    print(f"📥 Total Logs Processed: {total_logs}")
    print(f"🚨 Total Incidents Created: {total_incidents}")
    print(f"📈 Average Logs per Cycle: {total_logs / cycle_count:.1f}")
    print(f"📈 Average Incidents per Cycle: {total_incidents / cycle_count:.1f}")
    print(f"📈 Incident Rate: {(total_incidents / total_logs * 100):.2f}%" if total_logs > 0 else "📈 Incident Rate: 0.00%")
    print("-" * 50)


def display_final_stats(cycle_count: int, total_logs: int, total_incidents: int):
    """Display final statistics when monitoring stops."""
    print(f"\n📊 FINAL MONITORING STATISTICS")
    print("=" * 50)
    print(f"🔄 Total Cycles: {cycle_count}")
    print(f"📥 Total Logs Processed: {total_logs}")
    print(f"🚨 Total Incidents Created: {total_incidents}")
    print(f"📈 Average Logs per Cycle: {total_logs / cycle_count:.1f}" if cycle_count > 0 else "📈 Average Logs per Cycle: 0")
    print(f"📈 Average Incidents per Cycle: {total_incidents / cycle_count:.1f}" if cycle_count > 0 else "📈 Average Incidents per Cycle: 0")
    print(f"📈 Overall Incident Rate: {(total_incidents / total_logs * 100):.2f}%" if total_logs > 0 else "📈 Overall Incident Rate: 0.00%")
    print("=" * 50)
    
    print(f"\n📋 Next Steps:")
    print(f"   1. Review incidents in Elasticsearch index: aion-incidents")
    print(f"   2. Access Kibana at http://localhost:5601 for visualization")
    print(f"   3. Run 'python main.py analyze' to process additional log files")
    print(f"   4. Configure log ingestion pipeline for continuous monitoring")


def get_monitoring_status(es_client) -> dict:
    """
    Get current monitoring status and statistics.
    
    Args:
        es_client: Elasticsearch client
        
    Returns:
        Dictionary with monitoring status
    """
    try:
        # Get pending logs count
        pending_query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "aion.status"}},
                        {"term": {"aion.status": "pending"}}
                    ]
                }
            }
        }
        
        pending_response = es_client.count(index=UNIFIED_LOGS_INDEX, body=pending_query)
        pending_count = pending_response['count']
        
        # Get total logs count
        total_response = es_client.count(index=UNIFIED_LOGS_INDEX)
        total_logs = total_response['count']
        
        # Get incidents count
        incidents_response = es_client.count(index=INCIDENTS_INDEX)
        total_incidents = incidents_response['count']
        
        return {
            'pending_logs': pending_count,
            'total_logs': total_logs,
            'total_incidents': total_incidents,
            'processed_logs': total_logs - pending_count,
            'processing_rate': ((total_logs - pending_count) / total_logs * 100) if total_logs > 0 else 0
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'pending_logs': 0,
            'total_logs': 0,
            'total_incidents': 0,
            'processed_logs': 0,
            'processing_rate': 0
        }
