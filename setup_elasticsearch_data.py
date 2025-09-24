#!/usr/bin/env python3
"""
Setup script to populate Elasticsearch with test data from normalized logs.
This script reads the existing normalized log files and uploads them to Elasticsearch
with the proper aion.status field set to "pending" for processing.
"""

import os
import json
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Configuration
ELASTICSEARCH_HOST = "http://localhost:9200"
UNIFIED_LOGS_INDEX = "unified-logs"
LOG_DIRECTORY = "normalized_logs"

def initialize_elasticsearch():
    """Initialize Elasticsearch client and verify connection."""
    try:
        es_client = Elasticsearch([ELASTICSEARCH_HOST], request_timeout=30)
        
        if es_client.ping():
            print(f"✅ Connected to Elasticsearch at {ELASTICSEARCH_HOST}")
            return es_client
        else:
            print(f"❌ Failed to connect to Elasticsearch at {ELASTICSEARCH_HOST}")
            return None
    except Exception as e:
        print(f"❌ Error initializing Elasticsearch: {e}")
        return None

def create_unified_logs_index(es_client):
    """Create the unified-logs index with proper mapping if it doesn't exist."""
    if not es_client.indices.exists(index=UNIFIED_LOGS_INDEX):
        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "message": {"type": "text"},
                    "log.source": {"type": "keyword"},
                    "source.ip": {"type": "ip"},
                    "url.original": {"type": "text"},
                    "http.response.status_code": {"type": "integer"},
                    "user_agent.original": {"type": "text"},
                    "process.name": {"type": "keyword"},
                    "aion.status": {"type": "keyword"},
                    "aion.processed_at": {"type": "date"}
                }
            }
        }
        
        try:
            es_client.indices.create(index=UNIFIED_LOGS_INDEX, body=mapping)
            print(f"✅ Created index: {UNIFIED_LOGS_INDEX}")
        except Exception as e:
            print(f"⚠️  Could not create index: {e}")
    else:
        print(f"ℹ️  Index {UNIFIED_LOGS_INDEX} already exists")

def load_logs_from_files(directory):
    """Load only access log entries from JSON files in the directory."""
    all_logs = []
    print(f"--- Loading ACCESS LOGS ONLY from '{directory}' directory ---")
    
    if not os.path.exists(directory):
        print(f"❌ Directory not found: {directory}")
        return []
    
    # Only process access log files (exclude Linux syslog)
    access_log_files = [
        "output_access-10k.log_ecs.json",
    ]
    
    for filename in access_log_files:
        filepath = os.path.join(directory, filename)
        if not os.path.exists(filepath):
            print(f"⚠️  Access log file not found: {filepath}")
            continue
            
        print(f"  -> Loading {filepath}...")
        
        with open(filepath, 'r') as f:
            try:
                # Attempt to parse as a single JSON array first
                logs = json.load(f)
                if isinstance(logs, list):
                    # Filter to only include access logs (not Linux syslog)
                    access_logs = [log for log in logs if log.get('log.source') != 'linux_syslog']
                    all_logs.extend(access_logs)
                    print(f"    Added {len(access_logs)} access logs (filtered out {len(logs) - len(access_logs)} non-access logs)")
                else:
                    # Single log entry
                    if logs.get('log.source') != 'linux_syslog':
                        all_logs.append(logs)
                        print(f"    Added 1 access log")
            except json.JSONDecodeError:
                # Fall back to JSON Lines (one JSON object per line)
                f.seek(0)
                parsed_count = 0
                access_count = 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        parsed_count += 1
                        # Only add if it's not a Linux syslog entry
                        if obj.get('log.source') != 'linux_syslog':
                            all_logs.append(obj)
                            access_count += 1
                    except json.JSONDecodeError:
                        continue
                print(f"    Parsed {parsed_count} total lines, added {access_count} access logs")
            except Exception as e:
                print(f"    Error reading {filepath}: {e}")

    print(f"\nTotal ACCESS logs loaded: {len(all_logs)}")
    return all_logs

def prepare_logs_for_elasticsearch(logs):
    """Prepare logs for Elasticsearch indexing by adding aion.status field."""
    prepared_logs = []
    
    for log in logs:
        # Add AION processing fields
        log['aion.status'] = 'pending'
        log['aion.uploaded_at'] = datetime.now().isoformat()
        
        # Ensure @timestamp exists
        if '@timestamp' not in log:
            log['@timestamp'] = datetime.now().isoformat()
        
        prepared_logs.append({
            '_index': UNIFIED_LOGS_INDEX,
            '_source': log
        })
    
    return prepared_logs

def clear_existing_data(es_client):
    """Clear existing data from the unified-logs index."""
    try:
        if es_client.indices.exists(index=UNIFIED_LOGS_INDEX):
            print(f"🗑️  Clearing existing data from {UNIFIED_LOGS_INDEX}...")
            es_client.delete_by_query(
                index=UNIFIED_LOGS_INDEX,
                body={"query": {"match_all": {}}}
            )
            print(f"✅ Cleared existing data from {UNIFIED_LOGS_INDEX}")
        else:
            print(f"ℹ️  Index {UNIFIED_LOGS_INDEX} doesn't exist yet")
    except Exception as e:
        print(f"⚠️  Error clearing existing data: {e}")

def upload_logs_to_elasticsearch(es_client, prepared_logs):
    """Upload logs to Elasticsearch using bulk indexing."""
    if not prepared_logs:
        print("ℹ️  No logs to upload")
        return
    
    print(f"--- Uploading {len(prepared_logs)} ACCESS logs to Elasticsearch ---")
    
    try:
        # Use bulk indexing for efficiency
        success_count, failed_items = bulk(es_client, prepared_logs, chunk_size=1000)
        
        print(f"✅ Successfully uploaded {success_count} access logs")
        
        if failed_items:
            print(f"⚠️  {len(failed_items)} logs failed to upload")
            for item in failed_items[:5]:  # Show first 5 failures
                print(f"    Failed: {item}")
    
    except Exception as e:
        print(f"❌ Error uploading logs: {e}")

def main():
    """Main function to set up Elasticsearch with ACCESS LOG data only."""
    print("🚀 Setting up Elasticsearch with ACCESS LOGS ONLY")
    print("=" * 60)
    print("📋 This will upload ONLY access logs (Apache/Nginx)")
    print("🚫 Linux syslog entries will be excluded")
    print("=" * 60)
    
    # Initialize Elasticsearch
    es_client = initialize_elasticsearch()
    if not es_client:
        return
    
    # Clear existing data
    clear_existing_data(es_client)
    
    # Create index
    create_unified_logs_index(es_client)
    
    # Load ACCESS logs from files
    logs = load_logs_from_files(LOG_DIRECTORY)
    if not logs:
        print("❌ No access logs found to upload")
        return
    
    # Prepare logs for Elasticsearch
    prepared_logs = prepare_logs_for_elasticsearch(logs)
    
    # Upload to Elasticsearch
    upload_logs_to_elasticsearch(es_client, prepared_logs)
    
    print("\n✅ Setup complete!")
    print(f"📊 You can now view your ACCESS LOG data in Kibana at: http://localhost:5601")
    print(f"🔍 Search for index: {UNIFIED_LOGS_INDEX}")
    print(f"🚀 Run the orchestrator with: python orchestrator.py --service")
    print(f"📈 Expected: Only web access logs with aion.status='pending'")

if __name__ == "__main__":
    main()
