# In a new file, e.g., tier2_detector.py
from sentence_transformers import SentenceTransformer
import hdbscan
import joblib

class BertAnomalyDetector:
    def __init__(self, model_path=None):
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        if model_path:
            self.clusterer = joblib.load(model_path)
        else:
            # Min cluster size is a key parameter to tune
            self.clusterer = hdbscan.HDBSCAN(min_cluster_size=15, prediction_data=True)

    def fit(self, log_messages):
        """Train the clusterer on a large batch of 'normal' logs."""
        print("Generating embeddings for fitting...")
        embeddings = self.embedding_model.encode(log_messages, show_progress_bar=True)
        print("Fitting HDBSCAN clusterer...")
        self.clusterer.fit(embeddings)
        joblib.dump(self.clusterer, "hdbscan_model.joblib")
        print("Model saved!")

    def predict(self, log_message):
        """Predict if a single log is an anomaly."""
        try:
            # Check if the model has been fitted
            if not hasattr(self.clusterer, 'clusterer_') or self.clusterer.clusterer_ is None:
                # Model not trained yet, return False (not anomaly) for now
                return False
            
            embedding = self.embedding_model.encode([log_message])
            cluster_label, _ = hdbscan.approximate_predict(self.clusterer, embedding)
            # HDBSCAN labels outliers as -1. This is the magic!
            is_anomaly = True if cluster_label[0] == -1 else False
            return is_anomaly
        except Exception as e:
            print(f"Error in anomaly prediction: {e}")
            return False