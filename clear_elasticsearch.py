#!/usr/bin/env python3
"""
AION Elasticsearch Data Cleanup Script
Clears all logs and incidents from Elasticsearch for testing purposes.
"""

import os
import sys
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration from environment variables
ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "")
ELASTICSEARCH_SSL_VERIFY = os.getenv("ELASTICSEARCH_SSL_VERIFY", "true").lower() == "true"

UNIFIED_LOGS_INDEX = os.getenv("UNIFIED_LOGS_INDEX", "unified-logs")
INCIDENTS_INDEX = os.getenv("INCIDENTS_INDEX", "aion-incidents")

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
            return es_client
        else:
            print(f"❌ Failed to connect to Elasticsearch at {ELASTICSEARCH_HOST}")
            return None
    except Exception as e:
        print(f"❌ Error initializing Elasticsearch: {e}")
        return None

def get_index_stats(es_client, index_name):
    """Get statistics for an index."""
    try:
        if es_client.indices.exists(index=index_name):
            stats = es_client.count(index=index_name)
            return stats['count']
        else:
            return 0
    except Exception as e:
        print(f"⚠️  Error getting stats for {index_name}: {e}")
        return 0

def clear_index(es_client, index_name, index_description):
    """Clear all documents from an index."""
    try:
        if not es_client.indices.exists(index=index_name):
            print(f"ℹ️  Index {index_name} does not exist - nothing to clear")
            return True
        
        # Get count before deletion
        count_before = get_index_stats(es_client, index_name)
        
        if count_before == 0:
            print(f"ℹ️  Index {index_name} is already empty")
            return True
        
        print(f"🗑️  Clearing {count_before:,} {index_description} from {index_name}...")
        
        # Delete all documents using delete_by_query
        response = es_client.delete_by_query(
            index=index_name,
            body={"query": {"match_all": {}}},
            wait_for_completion=True,
            refresh=True
        )
        
        deleted_count = response.get('deleted', 0)
        print(f"✅ Successfully deleted {deleted_count:,} {index_description}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error clearing {index_name}: {e}")
        return False

def clear_all_indices(es_client):
    """Clear all AION-related indices."""
    print("🧹 Starting Elasticsearch cleanup...")
    print("=" * 50)
    
    # List of indices to clear
    indices_to_clear = [
        (UNIFIED_LOGS_INDEX, "log entries"),
        (INCIDENTS_INDEX, "incidents")
    ]
    
    success_count = 0
    total_indices = len(indices_to_clear)
    
    for index_name, description in indices_to_clear:
        if clear_index(es_client, index_name, description):
            success_count += 1
        print()  # Add spacing between indices
    
    print("=" * 50)
    if success_count == total_indices:
        print("🎉 All indices cleared successfully!")
        return True
    else:
        print(f"⚠️  {success_count}/{total_indices} indices cleared successfully")
        return False

def show_final_stats(es_client):
    """Show final statistics after cleanup."""
    print("📊 Final Statistics:")
    print("-" * 30)
    
    for index_name, description in [(UNIFIED_LOGS_INDEX, "Log entries"), (INCIDENTS_INDEX, "Incidents")]:
        count = get_index_stats(es_client, index_name)
        status = "✅ Empty" if count == 0 else f"⚠️  {count:,} remaining"
        print(f"  {index_name}: {status}")

def main():
    """Main cleanup function."""
    print("🧹 AION Elasticsearch Data Cleanup")
    print("=" * 50)
    print("This script will clear ALL logs and incidents from Elasticsearch.")
    print("Use this for testing purposes only!")
    print("=" * 50)
    
    # Confirm before proceeding
    if len(sys.argv) > 1 and sys.argv[1] == "--force":
        print("🚀 Force mode enabled - proceeding without confirmation")
    else:
        response = input("\n⚠️  Are you sure you want to clear all data? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Operation cancelled")
            return
    
    # Initialize Elasticsearch
    es_client = initialize_elasticsearch()
    if not es_client:
        print("❌ Cannot proceed without Elasticsearch connection")
        sys.exit(1)
    
    # Show initial statistics
    print("\n📊 Current Statistics:")
    print("-" * 30)
    for index_name, description in [(UNIFIED_LOGS_INDEX, "Log entries"), (INCIDENTS_INDEX, "Incidents")]:
        count = get_index_stats(es_client, index_name)
        print(f"  {index_name}: {count:,} {description}")
    
    print()
    
    # Clear all indices
    success = clear_all_indices(es_client)
    
    # Show final statistics
    print()
    show_final_stats(es_client)
    
    if success:
        print("\n✅ Cleanup completed successfully!")
        print("🚀 Ready for fresh testing!")
    else:
        print("\n⚠️  Cleanup completed with some issues")
        print("Check the output above for details")
        sys.exit(1)

if __name__ == "__main__":
    main()
