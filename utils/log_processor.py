"""
Enhanced Log Processing Utilities
Handles parsing, normalization, and ingestion of various log formats.
"""

import os
import json
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Import our existing components
from core.ingestion.parser import LogParser
from core.ingestion.normalizer import LogNormalizer


class LogProcessor:
    """Enhanced log processor for various log formats."""
    
    def __init__(self, es_client: Elasticsearch, index_name: str = "unified-logs"):
        self.es_client = es_client
        self.index_name = index_name
        self.parser = LogParser()
        self.normalizer = LogNormalizer()
        self.processed_count = 0
        self.error_count = 0
    
    def detect_log_format(self, file_path: Path) -> str:
        """Detect the log format based on file extension and content."""
        file_ext = file_path.suffix.lower()
        
        # Check file extension first
        if file_ext == '.json':
            return 'json'
        elif file_ext == '.csv':
            return 'csv'
        elif file_ext in ['.log', '.txt']:
            # Read first few lines to detect format
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    first_lines = [f.readline().strip() for _ in range(3)]
                
                # Check for common log formats
                for line in first_lines:
                    if not line:
                        continue
                    
                    # Apache access log pattern
                    if self._is_apache_access_log(line):
                        return 'apache_access'
                    # Apache error log pattern
                    elif self._is_apache_error_log(line):
                        return 'apache_error'
                    # Linux syslog pattern
                    elif self._is_linux_syslog(line):
                        return 'linux_syslog'
                    # Zeek connection log pattern
                    elif 'id.orig_h' in line and 'id.resp_h' in line:
                        return 'zeek_conn'
                
                return 'generic_syslog'
            except Exception:
                return 'generic_syslog'
        else:
            return 'unknown'
    
    def _is_apache_access_log(self, line: str) -> bool:
        """Check if line matches Apache access log format."""
        # Basic Apache access log pattern: IP - - [timestamp] "method path protocol" status size
        import re
        pattern = r'^\d+\.\d+\.\d+\.\d+.*\[.*\].*".*".*\d{3}'
        return bool(re.match(pattern, line))
    
    def _is_apache_error_log(self, line: str) -> bool:
        """Check if line matches Apache error log format."""
        # Apache error log pattern: [timestamp] [level] [pid] message
        import re
        pattern = r'^\[.*\].*\[.*\].*\[.*\]'
        return bool(re.match(pattern, line))
    
    def _is_linux_syslog(self, line: str) -> bool:
        """Check if line matches Linux syslog format."""
        # Linux syslog pattern: timestamp hostname service: message
        import re
        pattern = r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
        return bool(re.match(pattern, line))
    
    def process_log_file(self, file_path: Path, log_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Process a single log file and return processing statistics.
        
        Args:
            file_path: Path to the log file
            log_type: Optional log type override
            
        Returns:
            Dictionary with processing statistics
        """
        print(f"📁 Processing log file: {file_path}")
        
        # Detect log format if not specified
        if not log_type:
            log_type = self.detect_log_format(file_path)
            print(f"🔍 Detected log format: {log_type}")
        
        # Validate file exists and is readable
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")
        
        # Get file size for progress tracking
        file_size = file_path.stat().st_size
        print(f"📊 File size: {self._format_file_size(file_size)}")
        
        # Process the file
        try:
            parsed_logs = self._parse_log_file(file_path, log_type)
            print(f"✅ Parsed {len(parsed_logs)} log entries")
            
            # Normalize logs to ECS format
            normalized_logs = self._normalize_logs(parsed_logs, log_type)
            print(f"✅ Normalized {len(normalized_logs)} log entries")
            
            # Upload to Elasticsearch
            uploaded_count = self._upload_to_elasticsearch(normalized_logs)
            print(f"✅ Uploaded {uploaded_count} log entries to Elasticsearch")
            
            return {
                'file_path': str(file_path),
                'log_type': log_type,
                'file_size': file_size,
                'parsed_count': len(parsed_logs),
                'normalized_count': len(normalized_logs),
                'uploaded_count': uploaded_count,
                'error_count': self.error_count,
                'success': True
            }
            
        except Exception as e:
            print(f"❌ Error processing file: {e}")
            return {
                'file_path': str(file_path),
                'log_type': log_type,
                'file_size': file_size,
                'parsed_count': 0,
                'normalized_count': 0,
                'uploaded_count': 0,
                'error_count': self.error_count + 1,
                'success': False,
                'error': str(e)
            }
    
    def _parse_log_file(self, file_path: Path, log_type: str) -> List[Dict[str, Any]]:
        """Parse log file based on detected type."""
        try:
            # Use existing parser
            parsed_data = self.parser.load_file(str(file_path))
            
            # Convert to list if it's a single record
            if isinstance(parsed_data, dict):
                parsed_data = [parsed_data]
            
            # Add log type to each entry
            for entry in parsed_data:
                entry['log_type'] = log_type
                entry['source_file'] = str(file_path)
                entry['processed_at'] = datetime.now().isoformat()
            
            return parsed_data
            
        except Exception as e:
            print(f"⚠️  Parser error: {e}")
            # Fallback to line-by-line parsing
            return self._fallback_parse(file_path, log_type)
    
    def _fallback_parse(self, file_path: Path, log_type: str) -> List[Dict[str, Any]]:
        """Fallback parsing for unsupported formats."""
        parsed_logs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Create a basic log entry
                    log_entry = {
                        'raw_message': line,
                        'log_type': log_type,
                        'source_file': str(file_path),
                        'line_number': line_num,
                        'processed_at': datetime.now().isoformat(),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    parsed_logs.append(log_entry)
                    
                    # Progress indicator for large files
                    if line_num % 1000 == 0:
                        print(f"  📝 Processed {line_num} lines...")
        
        except Exception as e:
            print(f"❌ Fallback parsing failed: {e}")
            self.error_count += 1
        
        return parsed_logs
    
    def _normalize_logs(self, parsed_logs: List[Dict[str, Any]], log_type: str) -> List[Dict[str, Any]]:
        """Normalize parsed logs to ECS format."""
        normalized_logs = []
        
        for log_entry in parsed_logs:
            try:
                # Use existing normalizer
                normalized = self.normalizer.normalize_to_ecs(log_entry, log_type)
                
                # Add AION-specific fields as top-level fields
                normalized['aion.status'] = 'pending'
                normalized['aion.processed_at'] = datetime.now().isoformat()
                normalized['aion.source_file'] = log_entry.get('source_file', '')
                normalized['aion.log_type'] = log_type
                
                normalized_logs.append(normalized)
                
            except Exception as e:
                print(f"⚠️  Normalization error: {e}")
                self.error_count += 1
                continue
        
        return normalized_logs
    
    def _upload_to_elasticsearch(self, normalized_logs: List[Dict[str, Any]]) -> int:
        """Upload normalized logs to Elasticsearch."""
        if not normalized_logs:
            return 0
        
        try:
            # Create index if it doesn't exist
            if not self.es_client.indices.exists(index=self.index_name):
                self._create_index()
            
            # Prepare bulk actions
            actions = []
            for log_entry in normalized_logs:
                actions.append({
                    "_index": self.index_name,
                    "_source": log_entry
                })
            
            # Bulk upload
            success_count, failed_items = bulk(
                self.es_client,
                actions,
                chunk_size=1000,
                request_timeout=60
            )
            
            if failed_items:
                print(f"⚠️  {len(failed_items)} items failed to upload")
                self.error_count += len(failed_items)
            
            return success_count
            
        except Exception as e:
            print(f"❌ Upload error: {e}")
            self.error_count += len(normalized_logs)
            return 0
    
    def _create_index(self):
        """Create Elasticsearch index with proper mapping."""
        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "log.source": {"type": "keyword"},
                    "message": {"type": "text"},
                    "source.ip": {"type": "ip"},
                    "destination.ip": {"type": "ip"},
                    "http.request.method": {"type": "keyword"},
                    "url.original": {"type": "text"},
                    "http.response.status_code": {"type": "integer"},
                    "user_agent.original": {"type": "text"},
                    "event.category": {"type": "keyword"},
                    "event.type": {"type": "keyword"},
                    "event.outcome": {"type": "keyword"},
                    "aion.status": {"type": "keyword"},
                    "aion.processed_at": {"type": "date"},
                    "aion.source_file": {"type": "keyword"},
                    "aion.log_type": {"type": "keyword"}
                }
            }
        }
        
        self.es_client.indices.create(index=self.index_name, body=mapping)
        print(f"✅ Created Elasticsearch index: {self.index_name}")
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get overall processing statistics."""
        return {
            'processed_count': self.processed_count,
            'error_count': self.error_count,
            'success_rate': (self.processed_count / (self.processed_count + self.error_count) * 100) 
                           if (self.processed_count + self.error_count) > 0 else 0
        }
