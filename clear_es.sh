#!/bin/bash
# AION Elasticsearch Cleanup Script
# Quick wrapper for clearing Elasticsearch data

echo "🧹 AION Elasticsearch Cleanup"
echo "=============================="

# Check if Python script exists
if [ ! -f "clear_elasticsearch.py" ]; then
    echo "❌ clear_elasticsearch.py not found!"
    exit 1
fi

# Run the Python script with any passed arguments
python3 clear_elasticsearch.py "$@"
