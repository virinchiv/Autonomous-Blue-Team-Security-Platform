import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from xgboost import XGBClassifier

# Path to the directory containing your CSV files
data_path = 'data/CICIDS/'

# Get a list of all CSV files in the directory
csv_files = [os.path.join(data_path, f) for f in os.listdir(data_path) if f.endswith('.csv')]

# Load each CSV and store it in a list of dataframes
df_list = [pd.read_csv(file) for file in csv_files]

# Concatenate all dataframes into one
df = pd.concat(df_list, ignore_index=True)

print(f"Successfully combined {len(csv_files)} files.")
print(f"Total rows in the combined dataset: {len(df)}")
df.head()

df.columns = df.columns.str.strip()

df.replace([np.inf, -np.inf], np.nan, inplace=True)
# Drop rows with NaN values, or fill them. We'll fill them with 0.
df.fillna(0, inplace=True)
print(f"Handled infinite and missing values. No NaNs remaining: {df.isna().sum().sum() == 0}")

non_numeric_cols = df.select_dtypes(exclude=np.number).columns.tolist()
if 'Label' in non_numeric_cols:
    non_numeric_cols.remove('Label')

for col in non_numeric_cols:
    df[col] = pd.to_numeric(df[col], errors='coerce')

df.fillna(0, inplace=True)
print("Ensured all feature columns are numeric.")

X = df.drop(columns=['Label'])
y = df['Label']

le = LabelEncoder()
y = le.fit_transform(y)

print("Label mapping:")
for i, label in enumerate(le.classes_):
    print(f"{label}: {i}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)
print(f"Training set shape: {X_train.shape}")
print(f"Test set shape: {X_test.shape}")

# xgb_classifier = XGBClassifier(
#     objective='multi:softmax',
#     num_class=len(le.classes_), # 'le' is our LabelEncoder from the previous step
#     n_estimators=100,
#     random_state=42,
#     n_jobs=-1
# )
# print("Training the XGBoost model... This can be faster than Random Forest.")
# xgb_classifier.fit(X_train, y_train)
# print("Model training complete!")

# # Compute and display top 10 most important features
# feature_importances = pd.Series(xgb_classifier.feature_importances_, index=X.columns)
# feature_importances_sorted = feature_importances.sort_values(ascending=False)

# top_10_features = feature_importances_sorted.head(20)
# print("\nTop 20 most important features (XGBoost):")
# print(top_10_features)

# print("Making predictions with XGBoost...")
# y_pred_xgb = xgb_classifier.predict(X_test)

# # Print the classification report
# print("\nXGBoost Classification Report:")
# print(classification_report(y_test, y_pred_xgb, target_names=le.classes_))

# # Generate and plot the confusion matrix
# cm_xgb = confusion_matrix(y_test, y_pred_xgb)
# plt.figure(figsize=(12, 10))
# sns.heatmap(cm_xgb, annot=True, fmt='d', cmap='Greens', xticklabels=le.classes_, yticklabels=le.classes_)
# plt.title('XGBoost Confusion Matrix')
# plt.ylabel('Actual Label')
# plt.xlabel('Predicted Label')
# plt.show()

# New XGBoost model using only core features
print("\n" + "="*50)
print("NEW XGBOOST MODEL WITH CORE FEATURES")
print("="*50)

# Define core features
core_features = [
    'Idle Mean', 'PSH Flag Count', 'Average Packet Size',
    'Max Packet Length', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Bwd Packets/s', 'FIN Flag Count',
    'Destination Port', 'Flow Bytes/s'
]

# Check which features are available in the dataset
available_core_features = [col for col in core_features if col in X.columns]
print(f"Available core features: {len(available_core_features)}/{len(core_features)}")
print(f"Available features: {available_core_features}")

# Create new feature matrix with only core features
X_core = X[available_core_features]
print(f"Core features shape: {X_core.shape}")

# Split the data for the core features model
X_train_core, X_test_core, y_train_core, y_test_core = train_test_split(
    X_core, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Train new XGBoost model with core features
xgb_core = XGBClassifier(
    objective='multi:softmax',
    num_class=len(le.classes_),
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

print("Training XGBoost model with core features...")
xgb_core.fit(X_train_core, y_train_core)
print("Core features model training complete!")

# Make predictions with core features model
y_pred_core = xgb_core.predict(X_test_core)

# Print classification report for core features model
print("\nCore Features XGBoost Classification Report:")
print(classification_report(y_test_core, y_pred_core, target_names=le.classes_))

# Generate and plot confusion matrix for core features model
cm_core = confusion_matrix(y_test_core, y_pred_core)
plt.figure(figsize=(12, 10))
sns.heatmap(cm_core, annot=True, fmt='d', cmap='Blues', xticklabels=le.classes_, yticklabels=le.classes_)
plt.title('Core Features XGBoost Confusion Matrix')
plt.ylabel('Actual Label')
plt.xlabel('Predicted Label')
plt.show()

# Compare feature importances for core features
feature_importances_core = pd.Series(xgb_core.feature_importances_, index=available_core_features)
feature_importances_core_sorted = feature_importances_core.sort_values(ascending=False)

print("\nCore Features Importance Ranking:")
print(feature_importances_core_sorted)

# Plot feature importances for core features
plt.figure(figsize=(10, 6))
sns.barplot(x=feature_importances_core_sorted.values, y=feature_importances_core_sorted.index, orient='h', palette='plasma')
plt.title('Core Features Importance (XGBoost)')
plt.xlabel('Importance')
plt.ylabel('Feature')
plt.tight_layout()
plt.show()

# Save the trained model and label encoder
import pickle

# Save the XGBoost model
with open('xgb_model.pkl', 'wb') as f:
    pickle.dump(xgb_core, f)

# Save the label encoder
with open('label_encoder.pkl', 'wb') as f:
    pickle.dump(le, f)

print("\nModel and label encoder saved successfully!")
print("Files created:")
print("- xgb_model.pkl (XGBoost model)")
print("- label_encoder.pkl (Label encoder)")