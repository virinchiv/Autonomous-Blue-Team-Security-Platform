import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix

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

rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf_classifier.fit(X_train, y_train)
print("Model training complete!")

# Use the trained model to make predictions on the test data
print("Making predictions on the test set...")
y_pred = rf_classifier.predict(X_test)
print("Predictions complete.")


# Generate the classification report
# We use le.classes_ to show the original text labels instead of numbers
report = classification_report(y_test, y_pred, target_names=le.classes_)

print("\nClassification Report:")
print(report)

# Generate the confusion matrix
cm = confusion_matrix(y_test, y_pred)
# Plot the confusion matrix as a heatmap for better visualization
plt.figure(figsize=(12, 10))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=le.classes_, yticklabels=le.classes_)
plt.title('Confusion Matrix')
plt.ylabel('Actual Label')
plt.xlabel('Predicted Label')
plt.show()