import os
import json
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# --- Configuration ---
ELASTICSEARCH_HOST = "http://localhost:9200"
INDEX_NAME = "unified-logs"
# List of your normalized JSON files to upload (from normalized_logs directory)
FILES_TO_UPLOAD = [
    "normalized_logs/output_access-10k.log_ecs.json",
    "normalized_logs/output_apache-10k.log_ecs.json",
    "normalized_logs/output_linux-2k.log_ecs.json"
]


# --- Main Script ---
def generate_actions(files):
    """
    Reads line-delimited JSON files and yields documents in the format required for bulk upload.
    """
    total_docs = 0
    for file_path in files:
        if not os.path.exists(file_path):
            print(f"Warning: File not found, skipping: {file_path}")
            continue
            
        print(f"Reading documents from {file_path}...")
        file_docs = 0
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    
                    try:
                        log_entry = json.loads(line)
                        # Ensure the document has the required fields for bulk indexing
                        yield {
                            "_index": INDEX_NAME,
                            "_source": log_entry
                        }
                        total_docs += 1
                        file_docs += 1
                    except json.JSONDecodeError as e:
                        print(f"Warning: Invalid JSON on line {line_num} in {file_path}: {e}")
                        continue
                        
            print(f"  Processed {file_docs} documents from {file_path}")
            
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            continue
            
    print(f"\nTotal documents to be uploaded: {total_docs}")

def main():
    """
    Connects to Elasticsearch and performs the bulk upload.
    """
    print("=" * 60)
    print("Elasticsearch Log Uploader")
    print("=" * 60)
    
    # Check if files exist before connecting to Elasticsearch
    existing_files = []
    for file_path in FILES_TO_UPLOAD:
        if os.path.exists(file_path):
            existing_files.append(file_path)
            file_size = os.path.getsize(file_path)
            print(f"✓ Found: {file_path} ({file_size:,} bytes)")
        else:
            print(f"✗ Missing: {file_path}")
    
    if not existing_files:
        print("\nError: No files found to upload!")
        print("Please ensure the normalized log files exist in the normalized_logs/ directory.")
        return
    
    print(f"\nConnecting to Elasticsearch at {ELASTICSEARCH_HOST}...")
    try:
        es_client = Elasticsearch([ELASTICSEARCH_HOST], request_timeout=30)
        # Check if the connection is successful
        if not es_client.ping():
            raise ConnectionError("Could not connect to Elasticsearch.")
        print("✓ Connection successful!")

        # Check if index exists, create if it doesn't
        if not es_client.indices.exists(index=INDEX_NAME):
            print(f"Creating index '{INDEX_NAME}'...")
            es_client.indices.create(index=INDEX_NAME)
            print(f"✓ Index '{INDEX_NAME}' created successfully!")

        print(f"\nUploading logs to index '{INDEX_NAME}'...")
        print("-" * 40)
        
        success, failed = bulk(es_client, generate_actions(existing_files), chunk_size=1000)
        
        print("-" * 40)
        print("Upload complete!")
        print(f"✓ Successfully indexed documents: {success}")
        if failed:
            print(f"✗ Failed to index documents: {failed}")
        else:
            print("✓ All documents indexed successfully!")
            
        # Show index stats
        try:
            stats = es_client.indices.stats(index=INDEX_NAME)
            doc_count = stats['indices'][INDEX_NAME]['total']['docs']['count']
            print(f"\nIndex '{INDEX_NAME}' now contains {doc_count:,} documents")
        except Exception as e:
            print(f"Could not retrieve index stats: {e}")

    except ConnectionError as e:
        print(f"\n✗ Connection Error: {e}")
        print("Please ensure your Elasticsearch container is running:")
        print("  docker-compose up -d")
        print(f"  Or check if Elasticsearch is accessible at {ELASTICSEARCH_HOST}")
    except Exception as e:
        print(f"\n✗ An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
