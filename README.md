# LogShield AI - Intelligent Log Analysis & Threat Detection

An intelligent cybersecurity platform that automatically analyzes log files and detects threats using a hybrid rules + ML + LLM pipeline, generating human-readable incident reports with AI-powered analysis.

## 🚀 Quick Start

### Analyze Your Log Files
The fastest way to see the system in action is to analyze your own log files:

```bash
# Try the sample logs
python aion.py analyze example_data/sample_logs/apache_access_sample.log
```

### Real-Time Monitoring
For continuous monitoring of new logs:

```bash
# Start real-time monitoring
python aion.py monitor
```

## 📋 What LogShield AI Does

### Log Analysis Mode
1. **Ingests Log Files** - Automatically detects and parses various log formats
2. **Normalizes Data** - Converts logs to standardized ECS format
3. **Detects Threats** - Applies multi-tier analysis (rules + AI)
4. **Generates Reports** - Creates comprehensive security intelligence reports
5. **Stores Results** - Keeps data in Elasticsearch for further analysis

### Real-Time Monitoring Mode
1. **Continuous Scanning** - Monitors Elasticsearch for new logs
2. **Real-Time Analysis** - Processes logs as they arrive
3. **Incident Creation** - Automatically creates security incidents
4. **Live Updates** - Provides real-time threat detection

## 🏗️ Architecture Overview

Currently uses a **2-tier detection pipeline**:

### Tier 1: Rule-Based Detection
- **Fast pattern matching** for known attack signatures
- **Correlation rules** to detect multi-step attacks
- **Threshold-based alerts** for suspicious behavior patterns

### Tier 2 (Under Development): ML-Powered Detection
- **Machine learning** for anomaly detection

### Tier 3: LLM-Powered Intelligence
- **Contextual analysis** of complex attack scenarios
- **Natural language explanations** of security incidents
- **Executive summaries** and actionable recommendations

## 🎯 MVP Features

### ✅ What's Included
- **Log File Analysis**: Process any log file format (Apache, syslog, JSON, CSV)
- **AI-Powered Detection**: Groq LLM integration for intelligent threat analysis
- **Real-Time Monitoring**: Continuous monitoring of Elasticsearch for new logs
- **Multiple Report Formats**: Markdown, JSON, and HTML reports
- **Easy Setup**: One-command setup with Docker
- **Sample Data**: Ready-to-use sample log files for testing

### 🚀 Ready for Production
- **Environment Management**: Secure API key handling
- **Error Handling**: Graceful error recovery and logging
- **Scalable Architecture**: Modular design for easy extension
- **Professional CLI**: Clean command-line interface
- **Comprehensive Documentation**: Detailed setup and usage guides

## 🛠️ Configuration

### Environment Variables
- **GROQ_API_KEY**: AI-powered analysis
- **ELASTICSEARCH_HOST**: Elasticsearch connection (default: localhost:9200)
- **BATCH_SIZE**: Processing batch size (default: 1000)
- **MAX_DEMO_LOGS**: Maximum logs per analysis (default: 2000)

### Detection Settings
- **Correlation Window**: 5 minutes for related events
- **Alert Thresholds**: Configurable per attack type
- **Processing Limits**: Configurable via environment variables

## 🔧 Prerequisites

### Required Services
- **Elasticsearch 8.9.0** - For log storage and search
- **Python 3.8+** - Runtime environment
- **Docker & Docker Compose** - For easy service deployment

### Environment Configuration

Uses environment variables for configuration. Follow these steps to set up your environment:

#### 1. Copy Environment Template
```bash
# Copy the example environment file
cp .env.example .env
```

#### 2. Configure Your Settings
Edit the `.env` file with your specific configuration:

```bash
# Required: Groq API Key for AI-powered analysis
GROQ_API_KEY=your_groq_api_key_here

# Optional: Elasticsearch configuration (defaults work for local setup)
ELASTICSEARCH_HOST=http://localhost:9200
UNIFIED_LOGS_INDEX=unified-logs
INCIDENTS_INDEX=aion-incidents

# Optional: Processing configuration
BATCH_SIZE=1000
MAX_DEMO_LOGS=2000
```

#### 3. Get Your Groq API Key
1. Visit [Groq Console](https://console.groq.com/keys)
2. Create an account or sign in
3. Generate a new API key
4. Copy the key to your `.env` file

**Note**: The Groq API key is optional but highly recommended.
### Quick Setup

#### Option 1: Automated Setup (Recommended)
```bash
# Run the automated setup script
python aion.py setup
```

#### Option 2: Manual Setup
```bash
# 1. Start Elasticsearch and Kibana
docker-compose up -d

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Configure environment variables (see above)
cp .env.example .env
# Edit .env with your settings

# 4. Verify Elasticsearch is running
curl http://localhost:9200

# 5. Analyze your first log file
python aion.py analyze examples/sample_logs/apache_access_sample.log
```

## 📊 What LogShield AI Detects

### 1. **Web Application Attacks**
- **SQL Injection**: `' OR '1'='1`, UNION SELECT patterns
- **Cross-Site Scripting (XSS)**: `<script>` tags, event handlers
- **Directory Traversal**: `../../../etc/passwd` attempts
- **Command Injection**: System command execution attempts
- **SSRF**: Server-side request forgery patterns

### 2. **System Compromises**
- **SSH Brute Force**: Multiple failed login attempts
- **Privilege Escalation**: Sudo usage patterns
- **Service Failures**: System service crashes and errors
- **Authentication Bypass**: Invalid user attempts

### 3. **Network Intrusions**
- **Port Scanning**: Reconnaissance activities
- **DDoS Patterns**: High-volume traffic anomalies
- **Bot Traffic**: Automated scanner signatures
- **Lateral Movement**: Internal network reconnaissance

### 4. **Anomalous Behavior**
- **Unusual Traffic Patterns**: Statistical anomalies
- **Suspicious User Activity**: Abnormal access patterns
- **Data Exfiltration**: Unusual data transfer patterns
- **Policy Violations**: Security policy breaches

## 🎯 Key Features

### Real-Time Processing
- **Continuous monitoring** of log streams
- **Sub-second detection** for critical threats
- **Automatic escalation** based on severity

### Multi-Source Support
- **Web Server Logs**: Apache, Nginx access logs
- **System Logs**: Linux syslog, authentication logs
- **Network Logs**: Netflow, firewall logs
- **Application Logs**: Custom application events

### Intelligent Analysis
- **False Positive Reduction**: ML models trained on real attack data
- **Context Awareness**: LLM understands attack patterns and intent
- **Adaptive Learning**: System improves with more data

### Enterprise Integration
- **Elasticsearch Storage**: Scalable log and incident storage
- **REST API**: Easy integration with existing security tools
- **Kibana Dashboards**: Visual threat monitoring and analysis

## 📈 Demo Output

After running the demo, you'll get:

1. **Console Output**: Real-time processing status and incident counts
2. **Security Report**: Detailed markdown report with findings and recommendations
3. **Elasticsearch Data**: Structured incidents stored in `aion-incidents` index
4. **Kibana Visualization**: Interactive dashboards for threat analysis

## 🔍 Understanding the Results

### Incident Classifications
- **Critical**: Active attacks requiring immediate response
- **High**: Significant security events needing prompt attention
- **Medium**: Suspicious activity warranting investigation
- **Low**: Potential threats for monitoring

### Confidence Scores
- **90-100%**: Very high confidence in threat classification
- **70-89%**: High confidence with some uncertainty
- **50-69%**: Moderate confidence, requires human review
- **Below 50%**: Low confidence, likely false positive

## 🚀 Usage Examples

### Analyze Log Files
```bash
# Basic analysis
python aion.py analyze /var/log/apache2/access.log

# Generate HTML report
python aion.py analyze /var/log/auth.log --format html

# Keep data in Elasticsearch for further analysis
python aion.py analyze /var/log/nginx/access.log --keep-data

# Clean up after analysis
python aion.py analyze /var/log/syslog --cleanup
```

### Real-Time Monitoring
```bash
# Start monitoring with default settings
python aion.py monitor

# Custom monitoring interval and batch size
python aion.py monitor --interval 60 --batch-size 500
```

### Next Steps
1. **Review Reports**: Check generated security intelligence reports
2. **Explore Kibana**: Visualize incidents at http://localhost:5601
3. **Customize Rules**: Modify detection rules in `core/tier1_rules.py`
4. **Process More Logs**: Analyze additional log files
5. **Set Up Monitoring**: Configure log ingestion for real-time monitoring

## 🔧 Troubleshooting

### Common Issues

#### Environment Configuration
- **"GROQ_API_KEY not found"**: Copy `.env.example` to `.env` and add your Groq API key
- **"Environment validation failed"**: Check that all numeric values in `.env` are valid integers
- **"No .env file found"**: Run `cp .env.example .env` and configure your settings

#### Elasticsearch Connection
- **"Failed to connect to Elasticsearch"**: 
  - Ensure Docker containers are running: `docker-compose ps`
  - Check Elasticsearch is accessible: `curl http://localhost:9200`
  - Verify no other service is using port 9200

#### Groq API Issues
- **"Failed to initialize Groq client"**: 
  - Verify your API key is correct in `.env`
  - Check your Groq account has available credits
  - Ensure you're not hitting rate limits

#### No Logs Found
- **"No logs found in Elasticsearch"**: 
  - Run `python setup_elasticsearch_data.py` to populate sample data
  - Check the `unified-logs` index exists: `curl http://localhost:9200/unified-logs/_count`

### Getting Help
- Check the console output for detailed error messages
- Verify all prerequisites are installed and running
- Ensure your `.env` file is properly configured

## 📁 Project Structure

```
aion/
├── aion.py                    # Main CLI interface
├── core/                      # Core security analysis components
│   ├── orchestrator.py        # Main orchestration logic
│   ├── tier1_rules.py         # Rule-based detection
│   ├── tier3_llm.py          # AI-powered analysis
│   └── ingestion/            # Log parsing and normalization
├── cli/                       # Command-line interface modules
│   ├── analyze.py            # Log analysis mode
│   └── monitor.py            # Real-time monitoring mode
├── utils/                     # Utility functions
│   └── log_processor.py      # Enhanced log processing
├── examples/                  # Sample data and examples
│   └── sample_logs/          # Sample log files for testing
├── .env.example              # Environment configuration template
├── docker-compose.yml        # Elasticsearch and Kibana setup
└── requirements.txt          # Python dependencies
```

## 🤝 Contributing

This is an autonomous security platform designed to demonstrate AI-powered threat detection. The system is built with modularity in mind, allowing easy extension of detection rules, ML models, and analysis capabilities.

## 📄 License

See [LICENSE](LICENSE) file for details.


## 📦 Filebeat Usage (Log Shipping)

Use the sample Filebeat configuration to ship Apache, Nginx, and System logs into Elasticsearch with `aion.status=pending` so AION can process them in real time.

```
# 1) Edit paths and credentials in filebeat/filebeat.yml

# 2) Set environment variables (optional if using secure ES)
export ELASTICSEARCH_HOSTS=http://localhost:9200
export ELASTICSEARCH_USERNAME=elastic
export ELASTICSEARCH_PASSWORD=changeme

# 3) Start Filebeat (installation varies by OS)
sudo filebeat modules enable apache nginx system
sudo filebeat -e -c filebeat/filebeat.yml

# 4) Verify data in Elasticsearch
curl "$ELASTICSEARCH_HOSTS/unified-logs/_count?pretty"
```

Notes:
- Events are tagged with `aion.status=pending` so `monitor` mode can pick them up.
- All logs land in the `unified-logs` index by default.

## 🗂️ Index Templates & ILM (Optional)

To add guardrails around mappings and retention, apply the included index templates and optional ILM policies.

```
# Create ILM policies (optional)
curl -X PUT "$ELASTICSEARCH_HOSTS/_ilm/policy/aion-unified-logs-policy" \
  -H 'Content-Type: application/json' \
  -d @elasticsearch/ilm/aion-unified-logs-policy.json

curl -X PUT "$ELASTICSEARCH_HOSTS/_ilm/policy/aion-incidents-policy" \
  -H 'Content-Type: application/json' \
  -d @elasticsearch/ilm/aion-incidents-policy.json

# Create index templates
curl -X PUT "$ELASTICSEARCH_HOSTS/_index_template/unified-logs-template" \
  -H 'Content-Type: application/json' \
  -d @elasticsearch/templates/unified-logs-template.json

curl -X PUT "$ELASTICSEARCH_HOSTS/_index_template/aion-incidents-template" \
  -H 'Content-Type: application/json' \
  -d @elasticsearch/templates/aion-incidents-template.json
```

Files:
- `elasticsearch/templates/unified-logs-template.json`
- `elasticsearch/templates/aion-incidents-template.json`
- `elasticsearch/ilm/aion-unified-logs-policy.json` (optional)
- `elasticsearch/ilm/aion-incidents-policy.json` (optional)

## 📊 Kibana Dashboards (Optional)

Import the starter data view and dashboard for quick visualization.

```
# Import saved objects
curl -X POST "$ELASTICSEARCH_HOSTS/_security/user/_has_privileges" -H 'kbn-xsrf: true' || true
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -H 'kbn-xsrf: true' \
  --form file=@kibana/saved_objects.ndjson
```

Files:
- `kibana/saved_objects.ndjson`