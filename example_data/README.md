# AION Examples

This directory contains example log files and usage examples for the AION Security Platform.

## 📁 Sample Log Files

### Small Sample Files (Quick Testing)
### `sample_logs/apache_access_sample.log`
- **Format**: Apache access log
- **Content**: Web server access logs with various attack patterns
- **Threats**: Directory traversal, SQL injection, XSS attempts
- **Usage**: `python aion.py analyze example_data/sample_logs/apache_access_sample.log`

### `sample_logs/syslog_sample.log`
- **Format**: Linux syslog
- **Content**: System authentication and service logs
- **Threats**: SSH brute force, privilege escalation attempts
- **Usage**: `python aion.py analyze example_data/sample_logs/syslog_sample.log`

### Large Test Files (Comprehensive Analysis)
### `sample_logs/linux-2k.log`
- **Format**: Linux syslog
- **Size**: ~216 KB, 2,000 log entries
- **Content**: Comprehensive system logs with multiple attack patterns
- **Threats**: SSH brute force, system alerts, authentication failures
- **Usage**: `python aion.py analyze example_data/sample_logs/linux-2k.log`

### `sample_logs/apache-10k.log`
- **Format**: Apache server log
- **Size**: ~5.1 MB, 10,000+ log entries
- **Content**: Large web server access logs
- **Threats**: Various web attacks, reconnaissance, exploitation attempts
- **Usage**: `python aion.py analyze example_data/sample_logs/apache-10k.log`

### `sample_logs/access-10k.log`
- **Format**: Apache access log
- **Size**: ~4.9 MB, 10,000+ log entries
- **Content**: Web server access logs with attack patterns
- **Threats**: Directory traversal, SQL injection, XSS attempts
- **Usage**: `python aion.py analyze example_data/sample_logs/access-10k.log`

## 🚀 Quick Start Examples

### 1. Analyze Sample Logs
```bash
# Quick test with small samples
python aion.py analyze example_data/sample_logs/apache_access_sample.log
python aion.py analyze example_data/sample_logs/syslog_sample.log

# Comprehensive analysis with large files
python aion.py analyze example_data/sample_logs/linux-2k.log
python aion.py analyze example_data/sample_logs/apache-10k.log
python aion.py analyze example_data/sample_logs/access-10k.log

# Generate HTML report
python aion.py analyze example_data/sample_logs/apache_access_sample.log --format html
```

### 2. Real-Time Monitoring
```bash
# Start monitoring with default settings
python aion.py monitor

# Custom monitoring interval
python aion.py monitor --interval 60 --batch-size 500
```

### 3. Setup and Configuration
```bash
# Run initial setup
python aion.py setup

# Check system status
curl http://localhost:9200
```

## 📊 Expected Results

When analyzing the sample logs, you should see:

### Apache Access Log Analysis
- **Directory Traversal**: `../../../etc/passwd` attempts
- **SQL Injection**: `' OR '1'='1` patterns
- **XSS Attempts**: `<script>` tags in URLs
- **Reconnaissance**: Admin panel and WordPress scans

### Syslog Analysis
- **SSH Brute Force**: Multiple failed login attempts
- **Privilege Escalation**: Sudo usage patterns
- **System Alerts**: Out of memory conditions
- **Invalid Users**: Attempts with non-existent accounts

## 🔧 Custom Log Formats

AION supports various log formats:

- **Apache/Nginx Access Logs**: Standard web server logs
- **Linux Syslog**: System authentication and service logs
- **JSON Logs**: Structured log data
- **CSV Logs**: Comma-separated log data
- **Custom Formats**: Line-by-line parsing with fallback

## 📈 Performance Tips

- **Large Files**: AION processes files in chunks for memory efficiency
- **Multiple Files**: Use batch processing for multiple log files
- **Real-Time**: Configure appropriate batch sizes for your log volume
- **Storage**: Use `--cleanup` flag to remove processed data after analysis

## 🛠️ Troubleshooting

### Common Issues
1. **File Not Found**: Ensure the log file path is correct
2. **Permission Denied**: Check file read permissions
3. **Elasticsearch Connection**: Ensure Elasticsearch is running
4. **Memory Issues**: Process large files in smaller batches

### Getting Help
- Check the main README.md for detailed setup instructions
- Review console output for specific error messages
- Ensure all dependencies are installed correctly
