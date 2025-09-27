#!/usr/bin/env python3
"""
Reset some logs to pending status for demo purposes.
"""

from elasticsearch import Elasticsearch
import json

def reset_logs_for_demo():
    """Reset up to 2000 logs to pending status for demo."""
    es_client = Elasticsearch([{"host": "localhost", "port": 9200}])
    
    # First, get some logs that are currently benign
    query = {
        "query": {
            "term": {"aion.status": "benign"}
        },
        "size": 2000
    }
    
    response = es_client.search(index="unified-logs", body=query)
    logs = response["hits"]["hits"]
    
    print(f"Found {len(logs)} benign logs to reset")
    
    # Reset them to pending status
    bulk_body = []
    for log in logs:
        bulk_body.extend([
            {"update": {"_index": "unified-logs", "_id": log["_id"]}},
            {"doc": {"aion.status": "pending"}}
        ])
    
    if bulk_body:
        response = es_client.bulk(body=bulk_body)
        if response.get("errors"):
            print(f"Some updates failed: {response['errors']}")
        else:
            print(f"✅ Reset {len(logs)} logs to pending status")
    
    # Verify the reset
    verify_query = {
        "query": {
            "term": {"aion.status": "pending"}
        },
        "size": 5
    }
    
    verify_response = es_client.search(index="unified-logs", body=verify_query)
    pending_count = verify_response["hits"]["total"]["value"]
    print(f"📊 Total pending logs now: {pending_count}")

if __name__ == "__main__":
    reset_logs_for_demo()
