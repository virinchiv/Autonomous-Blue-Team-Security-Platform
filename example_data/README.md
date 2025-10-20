# LogShield AI Examples

This directory contains example log files for testing and demonstration purposes.

## 📁 Sample Log Files

### Small Sample Files (Quick Testing)
- **`apache_access_sample.log`** - Apache access logs with attack patterns
- **`nginx_access_sample.log`** - Nginx access logs 
- **`syslog_sample.log`** - Linux system logs with authentication events
- **`zeek_conn_sample.log`** - Network connection logs

### Large Test Files (Comprehensive Analysis)
- **`linux-2k.log`** - 2,000 Linux system log entries (~216 KB)
- **`apache-10k.log`** - 10,000+ Apache server log entries (~5.1 MB)
- **`access-10k.log`** - 10,000+ access log entries (~3.1 MB)

## 🚀 Quick Start Examples

```bash
# Quick test with small samples
python main.py analyze example_data/sample_logs/apache_access_sample.log

# Comprehensive analysis with large files
python main.py analyze example_data/sample_logs/linux-2k.log

# Generate HTML report
python main.py analyze example_data/sample_logs/apache_access_sample.log --format html
```

## 📊 Expected Results

These sample files contain various security threats and attack patterns that LogShield AI will detect and analyze, including:

- SQL injection attempts
- Cross-site scripting (XSS)
- Directory traversal attacks
- SSH brute force attempts
- System authentication failures
- Network anomalies
