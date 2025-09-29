# AION - Autonomous Blue Team Security Platform

An intelligent cybersecurity platform that automatically ingests system and network logs, detects threats using a hybrid ML + rules pipeline, and generates human-readable incident reports with AI-powered analysis.

## 🚀 Quick Start Demo

The fastest way to see AION in action is to run the demo:

```bash
python run_demo.py
```

This demo will:
1. **Connect to Elasticsearch** - Verify the backend is running
2. **Fetch existing logs** - Process up to 2000 logs from your `unified-logs` index
3. **Run threat detection** - Apply multi-tier analysis (rules + ML + LLM)
4. **Generate incidents** - Create structured security incidents
5. **Produce intelligence report** - Generate a comprehensive security report

## 🏗️ Architecture Overview

AION currently uses a **2-tier detection pipeline**:

### Tier 1: Rule-Based Detection
- **Fast pattern matching** for known attack signatures
- **Correlation rules** to detect multi-step attacks
- **Threshold-based alerts** for suspicious behavior patterns

### Tier 3: LLM-Powered Intelligence
- **Contextual analysis** of complex attack scenarios
- **Natural language explanations** of security incidents
- **Executive summaries** and actionable recommendations

## 🔧 Prerequisites

### Required Services
- **Elasticsearch 8.9.0** - For log storage and search
- **Python 3.8+** - Runtime environment
- **Docker & Docker Compose** - For easy service deployment

### Environment Configuration

AION uses environment variables for configuration. Follow these steps to set up your environment:

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

**Note**: The Groq API key is optional but highly recommended. Without it, AION will only use rule-based detection (Tier 1) and skip AI-powered analysis (Tier 3).

### Quick Setup

#### Option 1: Automated Setup (Recommended)
```bash
# Run the automated setup script
python setup.py
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

# 5. Run the demo
python run_demo.py
```

## 📊 What the Demo Shows

When you run `python run_demo.py`, you'll see:

### 1. **Log Processing**
- Ingests logs from multiple sources (Apache, Linux syslog, network flows)
- Normalizes data into ECS (Elastic Common Schema) format
- Applies real-time threat detection rules

### 2. **Threat Detection**
- **Web Attacks**: SQL injection, directory traversal, XSS attempts
- **Network Intrusions**: Port scans, DDoS patterns, bot traffic
- **System Compromises**: SSH brute force, privilege escalation, service failures
- **Anomalous Behavior**: Unusual traffic patterns, suspicious user activity

### 3. **Incident Generation**
- **Correlated Events**: Groups related attacks into coherent incidents
- **Severity Assessment**: Critical, High, Medium, Low classifications
- **Timeline Analysis**: Shows attack progression over time
- **Evidence Collection**: Preserves original logs for forensic analysis

### 4. **Intelligence Reporting**
- **Executive Summary**: High-level overview for management
- **Technical Details**: Deep dive for security analysts
- **Actionable Recommendations**: Specific steps to remediate threats
- **Confidence Scoring**: AI confidence in threat classification

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

## 🚀 Next Steps

After the demo:

1. **Review the Report**: Check the generated security intelligence report
2. **Explore Kibana**: Visualize incidents and trends in the web interface
3. **Run Real-Time Mode**: Start continuous monitoring with `python orchestrator.py --service`
4. **Customize Rules**: Modify detection rules in `tier1_rules.py`
5. **Train Models**: Improve ML detection with your own data

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

## 🛠️ Configuration

### Elasticsearch Settings
- **Host**: `http://localhost:9200` (configurable in `orchestrator.py`)
- **Indices**: `unified-logs` (input), `aion-incidents` (output)
- **Batch Size**: 1000 logs per processing cycle

### Detection Thresholds
- **Correlation Window**: 5 minutes for related events
- **Alert Thresholds**: Configurable per attack type
- **Processing Limit**: 2000 logs per demo run (for performance)

## 📚 Technical Details

### Detection Pipeline
```
Raw Logs → Normalization → Tier 1 Rules → Tier 2 ML → Tier 3 LLM → Incidents
```

### Supported Attack Types
- **Web Application Attacks**: OWASP Top 10 patterns
- **Network Intrusions**: Port scans, DDoS, botnets
- **System Compromises**: Privilege escalation, service abuse
- **Data Exfiltration**: Unusual data transfer patterns
- **Lateral Movement**: Internal network reconnaissance

### ML Models
- **Random Forest**: Anomaly detection in network flows
- **XGBoost**: Classification of suspicious activities
- **LSTM**: Sequence analysis for attack patterns

## 🤝 Contributing

This is an autonomous security platform designed to demonstrate AI-powered threat detection. The system is built with modularity in mind, allowing easy extension of detection rules, ML models, and analysis capabilities.

## 📄 License

See [LICENSE](LICENSE) file for details.

---

**Ready to see AION in action? Run `python run_demo.py` and watch your autonomous blue team agent detect threats in real-time!** 🛡️