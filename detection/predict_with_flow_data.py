import pickle
import pandas as pd
import numpy as np
import sys
import os

# Add the parent directory to the path so we can import from ingestion
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion.flow_aggregator import FlowAggregator
from ingestion.parser import LogParser

def load_model_and_encoder():
    """Load the saved XGBoost model and label encoder."""
    try:
        # Look for model files in the parent directory
        model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'xgb_model.pkl')
        encoder_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'label_encoder.pkl')
        
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        with open(encoder_path, 'rb') as f:
            label_encoder = pickle.load(f)
        print("Model and label encoder loaded successfully!")
        return model, label_encoder
    except FileNotFoundError:
        print("Error: Model files not found. Please run XGBoost.py first to train and save the model.")
        return None, None

def predict_flows(flow_data, model, label_encoder):
    """Predict labels for flow data using the trained model."""
    if flow_data.empty:
        print("No flow data to predict on.")
        return None
    
    # Ensure the flow data has the same features as the training data
    expected_features = [
        'Idle Mean', 'PSH Flag Count', 'Average Packet Size',
        'Max Packet Length', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Bwd Packets/s', 'FIN Flag Count',
        'Destination Port', 'Flow Bytes/s'
    ]
    
    # Check which features are available
    available_features = [col for col in expected_features if col in flow_data.columns]
    missing_features = [col for col in expected_features if col not in flow_data.columns]
    
    if missing_features:
        print(f"Warning: Missing features: {missing_features}")
        print("These features will be filled with 0.")
        
        # Fill missing features with 0
        for feature in missing_features:
            flow_data[feature] = 0
    
    # Select only the expected features in the correct order
    X_pred = flow_data[expected_features]
    
    # Make predictions
    predictions = model.predict(X_pred)
    prediction_proba = model.predict_proba(X_pred)
    
    # Convert numeric predictions back to original labels
    predicted_labels = label_encoder.inverse_transform(predictions)
    
    # Create results DataFrame
    results = pd.DataFrame({
        'Flow_Index': range(len(flow_data)),
        'Predicted_Label': predicted_labels,
        'Prediction_Confidence': np.max(prediction_proba, axis=1)
    })
    
    # Add original features for reference
    for feature in expected_features:
        results[f'Feature_{feature}'] = X_pred[feature].values
    
    return results

def main():
    print("="*60)
    print("FLOW TRAFFIC ANOMALY DETECTION USING XGBOOST")
    print("="*60)
    
    # Load the trained model and label encoder
    model, label_encoder = load_model_and_encoder()
    if model is None:
        return
    
    # Parse and aggregate flow data
    print("\n1. Parsing and aggregating flow data...")
    parser = LogParser()
    
    # Use the test connection log
    log_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'test_conn.log')
    if not os.path.exists(log_file):
        print(f"Error: Log file {log_file} not found.")
        return
    
    parsed_logs = parser.load_file(log_file)
    print(f"Parsed {len(parsed_logs)} log entries.")
    
    # Process logs with the aggregator
    aggregator = FlowAggregator()
    for log in parsed_logs:
        aggregator.process_log(log)
    
    # Finalize any remaining flows
    completed_flows = aggregator.check_for_timeouts()
    
    if not completed_flows:
        print("No completed flows found.")
        return
    
    # Convert to DataFrame
    flow_df = pd.DataFrame(completed_flows)
    print(f"\n2. Generated {len(flow_df)} flow features:")
    print(flow_df.head())
    
    # Make predictions
    print("\n3. Making predictions with XGBoost model...")
    results = predict_flows(flow_df, model, label_encoder)
    
    if results is not None:
        print("\n4. Prediction Results:")
        print("="*40)
        print(results[['Flow_Index', 'Predicted_Label', 'Prediction_Confidence']])
        
        # Summary statistics
        print("\n5. Summary:")
        print("="*20)
        label_counts = results['Predicted_Label'].value_counts()
        print("Predicted Label Distribution:")
        for label, count in label_counts.items():
            print(f"  {label}: {count}")
        
        # Check for anomalies
        benign_count = label_counts.get('BENIGN', 0)
        anomaly_count = len(results) - benign_count
        
        print(f"\nTotal Flows: {len(results)}")
        print(f"Benign Flows: {benign_count}")
        print(f"Anomaly Flows: {anomaly_count}")
        
        if anomaly_count > 0:
            print(f"\n⚠️  DETECTED {anomaly_count} POTENTIAL ANOMALIES!")
            anomaly_flows = results[results['Predicted_Label'] != 'BENIGN']
            print("\nAnomaly Details:")
            print(anomaly_flows[['Flow_Index', 'Predicted_Label', 'Prediction_Confidence']])
        else:
            print("\n✅ All flows classified as benign.")
        
        # Save results
        results.to_csv('flow_prediction_results.csv', index=False)
        print(f"\nResults saved to 'flow_prediction_results.csv'")

if __name__ == "__main__":
    main() 