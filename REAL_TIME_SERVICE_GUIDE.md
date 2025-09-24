# AION Real-Time Security Orchestrator Service

## Overview

Your orchestrator has been successfully transformed from a batch processing script into a **real-time, incident-centric security service** that integrates with Elasticsearch. This guide explains how to use the new functionality.

## 🚀 What's New

### ✅ Task 1: Elasticsearch Integration
- **Direct Elasticsearch Integration**: Fetches logs from `unified-logs` index instead of local files
- **Status Tracking**: Updates log status (`pending` → `threat`/`benign`/`analyzed`) after processing
- **Structured Data**: All logs now have `aion.status` and `aion.processed_at` fields

### ✅ Task 2: Dedicated Incidents Index
- **New Index**: `aion-incidents` stores structured incident data
- **Rich Metadata**: Each incident includes title, summary, severity, timeline, and log references
- **Searchable**: Full-text search and filtering capabilities in Kibana

### ✅ Task 3: Real-Time Service
- **Continuous Processing**: Runs as a persistent service with configurable intervals
- **Batch Processing**: Processes logs in configurable batches (default: 1000 logs)
- **Error Handling**: Graceful error handling with service continuation
- **Cycle Reports**: Generates reports for each processing cycle

## 🛠️ Setup Instructions

### 1. Start Elasticsearch and Kibana

```bash
# Start the services using Docker Compose
docker-compose up -d

# Verify services are running
curl http://localhost:9200
curl http://localhost:5601
```

### 2. Populate Elasticsearch with Test Data

```bash
# Run the setup script to upload your normalized logs
python setup_elasticsearch_data.py
```

This script will:
- Create the `unified-logs` index with proper mapping
- Load all JSON files from `normalized_logs/` directory
- Add `aion.status: "pending"` to all logs
- Upload logs to Elasticsearch using bulk indexing

### 3. Run the Real-Time Service

```bash
# Start the real-time service (processes every 30 seconds)
python orchestrator.py --service

# Or run in batch mode (legacy behavior)
python orchestrator.py
```

## 📊 How to View Your Backend

### Elasticsearch API
```bash
# Check if indices exist
curl -X GET "localhost:9200/_cat/indices?v"

# View pending logs
curl -X GET "localhost:9200/unified-logs/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "term": {
      "aion.status": "pending"
    }
  },
  "size": 5
}'

# View incidents
curl -X GET "localhost:9200/aion-incidents/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match_all": {}
  },
  "size": 10
}'
```

### Kibana Dashboard
1. **Access Kibana**: http://localhost:5601
2. **Create Index Patterns**:
   - Go to Stack Management → Index Patterns
   - Create pattern for `unified-logs*`
   - Create pattern for `aion-incidents*`
3. **Explore Data**:
   - Go to Discover to view raw logs
   - Use filters to find `aion.status: pending`
   - View incidents in the `aion-incidents` index

### Service Monitoring
The real-time service provides detailed console output:
```
🚀 Starting AION Real-Time Security Orchestrator Service
⏰ Processing interval: 30 seconds
🔄 Service will run continuously. Press Ctrl+C to stop.

🔄 Processing Cycle #1 - 2024-01-15 10:30:00
📥 Fetched 150 pending logs from Elasticsearch
--- Processing batch of 150 logs ---
  -> Processed 100/150 logs...
  -> CORRELATED TIER 1 INCIDENT: SSH Authentication Failure from 192.168.1.100 (5 events)
  -> TIER 3 INCIDENT DETECTED: Analyzing 8 logs from 192.168.1.200...
✅ Updated status to 'threat' for 12 logs
✅ Updated status to 'benign' for 120 logs
✅ Updated status to 'analyzed' for 18 logs
✅ Saved incident incident_20240115_103000_1234 to Elasticsearch
✅ Report successfully generated: security_intelligence_report_cycle_1.md
✅ Cycle #1 completed successfully
⏳ Waiting 30 seconds before next cycle...
```

## 🔧 Configuration

### Environment Variables
```bash
# Maximum LLM escalations per batch (default: 50)
export MAX_TIER3_ESCALATIONS=100

# Processing interval (default: 30 seconds)
export LOOP_DELAY_SECONDS=60
```

### Configuration in orchestrator.py
```python
# Elasticsearch Configuration
ELASTICSEARCH_HOST = "http://localhost:9200"
UNIFIED_LOGS_INDEX = "unified-logs"
INCIDENTS_INDEX = "aion-incidents"
BATCH_SIZE = 1000
LOOP_DELAY_SECONDS = 30
```

## 📈 Data Flow

### 1. Log Ingestion
```
Normalized Logs → setup_elasticsearch_data.py → unified-logs index (status: pending)
```

### 2. Real-Time Processing
```
unified-logs (pending) → orchestrator.py --service → Analysis → Status Updates
```

### 3. Incident Creation
```
Tier 3 Analysis → generate_incident_report() → aion-incidents index
```

### 4. Status Lifecycle
```
pending → threat/benign/analyzed (with processed_at timestamp)
```

## 🎯 Key Features

### Elasticsearch Integration
- **Efficient Queries**: Uses Elasticsearch's powerful query DSL
- **Bulk Operations**: Updates multiple logs simultaneously
- **Index Management**: Automatic index creation with proper mappings
- **Status Tracking**: Complete audit trail of log processing

### Real-Time Processing
- **Continuous Monitoring**: Never stops checking for new logs
- **Batch Processing**: Configurable batch sizes for optimal performance
- **Error Recovery**: Continues running even if individual cycles fail
- **Resource Management**: Configurable processing limits

### Incident Management
- **Structured Storage**: Rich incident metadata in dedicated index
- **Log Correlation**: Links incidents back to original log entries
- **Searchable**: Full-text search across all incident data
- **Timeline Tracking**: Complete audit trail of incident creation

## 🚨 Troubleshooting

### Common Issues

1. **Elasticsearch Connection Failed**
   ```bash
   # Check if Elasticsearch is running
   docker ps | grep elasticsearch
   
   # Restart if needed
   docker-compose restart elasticsearch
   ```

2. **No Pending Logs Found**
   ```bash
   # Check if data was uploaded
   curl "localhost:9200/unified-logs/_count?q=aion.status:pending"
   
   # Re-run setup if needed
   python setup_elasticsearch_data.py
   ```

3. **Service Stops Unexpectedly**
   - Check console output for error messages
   - Verify all dependencies are installed
   - Check Elasticsearch connectivity

### Monitoring Commands
```bash
# Check service status
ps aux | grep orchestrator

# Monitor Elasticsearch indices
curl "localhost:9200/_cat/indices?v"

# Check pending logs count
curl "localhost:9200/unified-logs/_count?q=aion.status:pending"

# View recent incidents
curl "localhost:9200/aion-incidents/_search?sort=created_at:desc&size=5"
```

## 🎉 Next Steps

Your AION MVP backend is now ready! The real-time service provides:

1. **Continuous Log Processing**: Never misses new security events
2. **Structured Incident Storage**: Rich, searchable incident database
3. **Status Tracking**: Complete audit trail of all processing
4. **Scalable Architecture**: Ready for production deployment

You can now build frontend dashboards, APIs, and alerting systems on top of this solid foundation!
