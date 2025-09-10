#!/usr/bin/env python3
"""
Test script for access log parsing and normalization
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ingestion.parser import LogParser
from ingestion.normalizer import LogNormalizer
import json

def test_access_logs():
    """Test access log parsing and normalization"""
    
    # Initialize parser and normalizer
    parser = LogParser()
    normalizer = LogNormalizer()
    
    # Test access log file
    access_log_file = "logs/access-10k.log"
    
    print(f"{'='*60}")
    print(f"Testing Access Log: {access_log_file}")
    print(f"{'='*60}")
    
    try:
        # Parse logs
        print("Parsing access logs...")
        parsed_logs = parser.load_file(access_log_file)
        print(f"Parsed {len(parsed_logs)} log entries")
        
        # Show first few parsed logs
        print(f"\nFirst 5 parsed access logs:")
        for i, log in enumerate(parsed_logs[:5]):
            print(f"\nLog {i+1}:")
            print(f"  Type: {log.get('log_type', 'unknown')}")
            print(f"  Timestamp: {log.get('timestamp', 'N/A')}")
            print(f"  IP: {log.get('ip_address', 'N/A')}")
            print(f"  Method: {log.get('http_method', 'N/A')}")
            print(f"  URL: {log.get('url', 'N/A')}")
            print(f"  Status: {log.get('status_code', 'N/A')}")
            print(f"  User Agent: {log.get('user_agent', 'N/A')[:50]}...")
        
        # Normalize to ECS format
        print(f"\nNormalizing to ECS format...")
        ecs_logs = normalizer.normalize_logs_to_ecs(parsed_logs)
        print(f"Normalized {len(ecs_logs)} logs to ECS format")
        
        # Show first few ECS logs
        print(f"\nFirst 5 ECS normalized logs:")
        for i, log in enumerate(ecs_logs[:5]):
            print(f"\nECS Log {i+1}:")
            print(f"  @timestamp: {log.get('@timestamp', 'N/A')}")
            print(f"  log.source: {log.get('log.source', 'N/A')}")
            print(f"  event.category: {log.get('event.category', 'N/A')}")
            print(f"  event.type: {log.get('event.type', 'N/A')}")
            print(f"  event.outcome: {log.get('event.outcome', 'N/A')}")
            print(f"  source.ip: {log.get('source.ip', 'N/A')}")
            print(f"  http.request.method: {log.get('http.request.method', 'N/A')}")
            print(f"  url.original: {log.get('url.original', 'N/A')}")
            print(f"  http.response.status_code: {log.get('http.response.status_code', 'N/A')}")
            if log.get('security.flags'):
                print(f"  security.flags: {log.get('security.flags')}")
        
        # Count security flags
        security_logs = [log for log in ecs_logs if log.get('security.flags')]
        print(f"\nSecurity Analysis:")
        print(f"  Total logs: {len(ecs_logs)}")
        print(f"  Logs with security flags: {len(security_logs)}")
        
        # Count by security flag type
        flag_counts = {}
        for log in security_logs:
            for flag in log.get('security.flags', []):
                flag_counts[flag] = flag_counts.get(flag, 0) + 1
        
        if flag_counts:
            print(f"  Security flag breakdown:")
            for flag, count in sorted(flag_counts.items()):
                print(f"    {flag}: {count}")
        
        # Save ECS logs to file
        output_file = f"output_{os.path.basename(access_log_file)}_ecs.json"
        normalizer.save_ecs_logs(ecs_logs, output_file)
        print(f"\nSaved ECS logs to: normalized_logs/{output_file}")
        
    except Exception as e:
        print(f"Error processing {access_log_file}: {e}")
        import traceback
        traceback.print_exc()

def test_individual_access_parsing():
    """Test individual access log parsing"""
    print(f"\n{'='*60}")
    print("Testing Individual Access Log Parsing")
    print(f"{'='*60}")
    
    parser = LogParser()
    
    # Test access log parsing
    access_line = '54.36.149.41 - - [22/Jan/2019:03:56:14 +0330] "GET /filter/27|13%20%D9%85%DA%AF%D8%A7%D9%BE%DB%8C%DA%A9%D8%B3%D9%84,27|%DA%A9%D9%85%D8%AA%D8%B1%20%D8%A7%D8%B2%205%20%D9%85%DA%AF%D8%A7%D9%BE%DB%8C%DA%A9%D8%B3%D9%84,p53 HTTP/1.1" 200 30577 "-" "Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)" "-"'
    print(f"\nAccess Log Test:")
    print(f"Input: {access_line[:100]}...")
    result = parser._parse_apache_access_log(access_line)
    print(f"Parsed: {json.dumps(result, indent=2)}")
    
    # Test with a potential security issue
    security_line = '192.168.1.100 - - [22/Jan/2019:03:56:14 +0330] "GET /login.php?user=admin&pass=admin HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "-"'
    print(f"\nSecurity Test:")
    print(f"Input: {security_line}")
    result = parser._parse_apache_access_log(security_line)
    print(f"Parsed: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    print("Testing Access Log Parser and Normalizer")
    print("=" * 60)
    
    # Test individual parsing first
    test_individual_access_parsing()
    
    # Test full pipeline
    test_access_logs()
    
    print(f"\n{'='*60}")
    print("Access Log Testing Complete!")
    print(f"{'='*60}")
