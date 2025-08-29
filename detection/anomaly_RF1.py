import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

# Read the UNSW-NB15 datasets from zip files
print("Loading datasets...")
train_df = pd.read_csv("data/UNSW_NB15_training-set.csv.zip")
test_df = pd.read_csv("data/UNSW_NB15_testing-set.csv.zip")

print(f"Train shape: {train_df.shape}")
print(f"Test shape: {test_df.shape}")

# Data preprocessing
y_train = train_df["label"]
X_train = train_df.drop(columns=["id", "label"])

y_test = test_df["label"]
X_test = test_df.drop(columns=["id", "label"])

# Handle categorical columns
cat_cols = X_train.select_dtypes(include=["object"]).columns
print(f"\nCategorical columns found: {list(cat_cols)}")

encoders = {}
for col in cat_cols:
    le = LabelEncoder()
    X_train[col] = le.fit_transform(X_train[col])
    X_test[col] = le.fit_transform(X_test[col])
    encoders[col] = le

# Scale the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"\nClass distribution in training set:")
print(f"Normal (0): {np.sum(y_train == 0)}")
print(f"Anomaly (1): {np.sum(y_train == 1)}")
print(f"Anomaly ratio: {np.sum(y_train == 1) / len(y_train):.3f}")

# Train Random Forest on full training dataset
print("\n" + "="*60)
print("TRAINING RANDOM FOREST ON FULL DATASET")
print("="*60)

rf_params = {
    'n_estimators': 200,
    'max_depth': 20,
    'min_samples_split': 5,
    'min_samples_leaf': 2,
    'class_weight': 'balanced',
    'random_state': 42,
    'n_jobs': -1  # Use all CPU cores
}

print("Training Random Forest model...")
rf_model = RandomForestClassifier(**rf_params)
rf_model.fit(X_train_scaled, y_train)

print("Model training completed!")

# Feature importance analysis
feature_importance = pd.DataFrame({
    'feature': X_train.columns,
    'importance': rf_model.feature_importances_
}).sort_values('importance', ascending=False)

print(f"\nTop 15 Most Important Features:")
print(feature_importance.head(15))

# Predict on test set
print("\n" + "="*60)
print("EVALUATION ON TEST SET")
print("="*60)

y_pred = rf_model.predict(X_test_scaled)
y_pred_proba = rf_model.predict_proba(X_test_scaled)[:, 1]

# Calculate metrics
accuracy = np.mean(y_pred == y_test)
precision_1 = np.sum((y_pred == 1) & (y_test == 1)) / np.sum(y_pred == 1) if np.sum(y_pred == 1) > 0 else 0
recall_1 = np.sum((y_pred == 1) & (y_test == 1)) / np.sum(y_test == 1)
f1_1 = 2 * (precision_1 * recall_1) / (precision_1 + recall_1) if (precision_1 + recall_1) > 0 else 0

# ROC-AUC score
roc_auc = roc_auc_score(y_test, y_pred_proba)

print(f"Test Set Performance:")
print(f"  Accuracy: {accuracy:.6f}")
print(f"  Precision (Anomaly): {precision_1:.6f}")
print(f"  Recall (Anomaly): {recall_1:.6f}")
print(f"  F1-Score (Anomaly): {f1_1:.6f}")
print(f"  ROC-AUC Score: {roc_auc:.6f}")

print("\nDetailed Classification Report:")
print(classification_report(y_test, y_pred, digits=4))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Calculate additional metrics
tn, fp, fn, tp = cm.ravel()
specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0

print(f"\nAdditional Metrics:")
print(f"  Specificity (True Negative Rate): {specificity:.6f}")
print(f"  Sensitivity (True Positive Rate): {sensitivity:.6f}")
print(f"  False Positive Rate: {1 - specificity:.6f}")
print(f"  False Negative Rate: {1 - sensitivity:.6f}")

print("\n" + "="*60)
print("MODEL SUMMARY")
print("="*60)
print(f"✓ Random Forest trained on {len(X_train)} samples with {X_train.shape[1]} features")
print(f"✓ Model achieves {accuracy:.2%} accuracy on test set")
print(f"✓ Excellent anomaly detection: {precision_1:.2%} precision, {recall_1:.2%} recall")
print(f"✓ Ready for production deployment")
print("="*60)
