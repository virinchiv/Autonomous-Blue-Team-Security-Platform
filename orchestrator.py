# In your main orchestrator.py
from elasticsearch import Elasticsearch

es_client = Elasticsearch("http://localhost:9200")

def fetch_pending_logs(batch_size=50):
    """Fetches a batch of unanalyzed logs from Elasticsearch."""
    query = {
        "query": {
            "term": {
                "aion.status": "pending"
            }
        }
    }
    response = es_client.search(index="unified-logs", body=query, size=batch_size)
    return response['hits']['hits'] # Returns a list of log documents