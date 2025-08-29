import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
from sklearn.feature_selection import SelectKBest, mutual_info_classif
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

class OptimizedLightGBM:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        
    def load_and_preprocess_data(self):
        """Load and preprocess the UNSW-NB15 dataset"""
        print("Loading and preprocessing data...")
        
        # Load the training and testing sets
        train_df = pd.read_csv('data/UNSW_NB15_training-set.csv.zip')
        test_df = pd.read_csv('data/UNSW_NB15_testing-set.csv.zip')
        
        print(f"Training set shape: {train_df.shape}")
        print(f"Testing set shape: {test_df.shape}")
        
        # Identify label column (last column)
        label_col = train_df.columns[-1]
        feature_cols = [col for col in train_df.columns if col not in ['id', label_col]]
        
        print(f"Label column: {label_col}")
        print(f"Feature columns: {len(feature_cols)}")
        
        X_train = train_df[feature_cols]
        y_train = train_df[label_col]
        X_test = test_df[feature_cols]
        y_test = test_df[label_col]
        
        # Handle categorical variables
        categorical_cols = []
        for col in X_train.columns:

            if X_train[col].dtype == 'object' or X_train[col].nunique() < 20:
                categorical_cols.append(col)
        
        print(f"Identified categorical columns: {categorical_cols}")
        
        # One-hot encoding for categorical variables
        if categorical_cols:
            X_train = pd.get_dummies(X_train, columns=categorical_cols, drop_first=False)
            X_test = pd.get_dummies(X_test, columns=categorical_cols, drop_first=False)
            
            # Ensure both datasets have the same columns
            train_cols = set(X_train.columns)
            test_cols = set(X_test.columns)
            common_cols = list(train_cols.intersection(test_cols))
            
            X_train = X_train[common_cols]
            X_test = X_test[common_cols]
        
        print(f"Features after preprocessing: {X_train.shape[1]}")
        print(f"Training samples: {len(X_train)}")
        print(f"Testing samples: {len(X_test)}")
        
        return X_train, X_test, y_train, y_test, X_train.columns.tolist()
    
    def feature_engineering(self, X_train, X_test, y_train):
        """Advanced feature engineering"""
        print("Performing feature engineering...")
        
        # 1. Statistical features
        X_train_stats = X_train.copy()
        X_test_stats = X_test.copy()
        
        # Add statistical features
        X_train_stats['mean_features'] = X_train_stats.mean(axis=1)
        X_train_stats['std_features'] = X_train_stats.std(axis=1)
        X_train_stats['max_features'] = X_train_stats.max(axis=1)
        X_train_stats['min_features'] = X_train_stats.min(axis=1)
        X_train_stats['range_features'] = X_train_stats.max(axis=1) - X_train_stats.min(axis=1)
        
        X_test_stats['mean_features'] = X_test_stats.mean(axis=1)
        X_test_stats['std_features'] = X_test_stats.std(axis=1)
        X_test_stats['max_features'] = X_test_stats.max(axis=1)
        X_test_stats['min_features'] = X_test_stats.min(axis=1)
        X_test_stats['range_features'] = X_test_stats.max(axis=1) - X_test_stats.min(axis=1)
        
        # 2. Feature selection using mutual information
        print("Performing feature selection...")
        selector = SelectKBest(score_func=mutual_info_classif, k=min(200, X_train_stats.shape[1]))
        X_train_selected = selector.fit_transform(X_train_stats, y_train)
        X_test_selected = selector.transform(X_test_stats)
        
        # Get selected feature names
        selected_features = X_train_stats.columns[selector.get_support()].tolist()
        print(f"Selected {len(selected_features)} features out of {X_train_stats.shape[1]}")
        
        # 3. Standardization
        X_train_scaled = self.scaler.fit_transform(X_train_selected)
        X_test_scaled = self.scaler.transform(X_test_selected)
        
        return X_train_scaled, X_test_scaled, selected_features
    
    def train_optimized_model(self, X_train, y_train):
        """Train the LightGBM model with best parameters"""
        print("Training optimized model...")
        
        # Best parameters based on extensive testing
        self.model = lgb.LGBMClassifier(
            objective='binary',
            metric='auc',
            n_estimators=1000,
            max_depth=10,
            learning_rate=0.05,
            num_leaves=127,
            min_child_samples=50,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_alpha=0.1,
            reg_lambda=0.1,
            random_state=42,
            n_jobs=-1,
            verbose=-1
        )
        
        # Train the model
        self.model.fit(X_train, y_train)
        
        print("Training complete!")
        return self.model
    
    def evaluate_model(self, X_test, y_test):
        """Comprehensive model evaluation"""
        print("Evaluating model performance...")
        
        # Make predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        
        print(f"Accuracy: {accuracy * 100:.2f}%")
        print(f"ROC AUC: {roc_auc:.4f}")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        # Calculate additional metrics
        tn, fp, fn, tp = cm.ravel()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\nDetailed Metrics:")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1-Score: {f1:.4f}")
        print(f"True Negatives: {tn}")
        print(f"False Positives: {fp}")
        print(f"False Negatives: {fn}")
        print(f"True Positives: {tp}")
        
        return accuracy, roc_auc, cm
    
    def plot_results(self, X_test, y_test):
        """Plot model results and feature importance"""
        print("Generating plots...")
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.model.feature_name_,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        plt.figure(figsize=(12, 8))
        plt.subplot(2, 2, 1)
        top_features = feature_importance.head(20)
        plt.barh(range(len(top_features)), top_features['importance'])
        plt.yticks(range(len(top_features)), top_features['feature'])
        plt.xlabel('Feature Importance')
        plt.title('Top 20 Feature Importances')
        plt.gca().invert_yaxis()
        
        # ROC Curve
        plt.subplot(2, 2, 2)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        from sklearn.metrics import roc_curve
        fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
        plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc_score(y_test, y_pred_proba):.3f})')
        plt.plot([0, 1], [0, 1], 'k--', label='Random')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve')
        plt.legend()
        
        # Precision-Recall Curve
        plt.subplot(2, 2, 3)
        from sklearn.metrics import precision_recall_curve
        precision, recall, _ = precision_recall_curve(y_test, y_pred_proba)
        plt.plot(recall, precision, label=f'PR Curve')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend()
        
        # Confusion Matrix Heatmap
        plt.subplot(2, 2, 4)
        cm = confusion_matrix(y_test, self.model.predict(X_test))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Normal', 'Attack'], 
                    yticklabels=['Normal', 'Attack'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        
        plt.tight_layout()
        plt.savefig('reports/lightgbm_results.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Plots saved to 'reports/lightgbm_results.png'")
    
    def cross_validation_analysis(self, X_train, y_train):
        """Perform cross-validation analysis"""
        print("Performing cross-validation analysis...")
        
        cv_scores = cross_val_score(
            self.model, X_train, y_train, 
            cv=5, scoring='roc_auc', n_jobs=-1
        )
        
        print(f"Cross-validation ROC AUC scores: {cv_scores}")
        print(f"Mean CV ROC AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        return cv_scores

def main():
    """Main execution function"""
    print("=" * 60)
    print("LIGHTGBM MODEL FOR UNSW-NB15 DATASET")
    print("=" * 60)
    
    # Initialize the optimized model
    model = OptimizedLightGBM()
    
    # Load and preprocess data
    X_train, X_test, y_train, y_test, feature_cols = model.load_and_preprocess_data()
    
    # Feature engineering
    X_train_engineered, X_test_engineered, selected_features = model.feature_engineering(
        X_train, X_test, y_train
    )
    
    # Train the optimized model
    print("\n" + "="*40)
    print("TRAINING OPTIMIZED MODEL")
    print("="*40)
    final_model = model.train_optimized_model(X_train_engineered, y_train)
    
    # Evaluate the model
    print("\n" + "="*40)
    print("MODEL EVALUATION")
    print("="*40)
    accuracy, roc_auc, cm = model.evaluate_model(X_test_engineered, y_test)
    
    # Cross-validation analysis
    print("\n" + "="*40)
    print("CROSS-VALIDATION ANALYSIS")
    print("="*40)
    cv_scores = model.cross_validation_analysis(X_train_engineered, y_train)
    
    # Generate plots
    print("\n" + "="*40)
    print("GENERATING VISUALIZATIONS")
    print("="*40)
    model.plot_results(X_test_engineered, y_test)
    
    print("\n" + "=" * 60)
    print("OPTIMIZATION COMPLETE!")
    print(f"Final Accuracy: {accuracy * 100:.2f}%")
    print(f"Final ROC AUC: {roc_auc:.4f}")
    print("=" * 60)
    
    print("\nModel training completed successfully!")
    print("Best parameters used:")
    print("- n_estimators: 1000")
    print("- max_depth: 10")
    print("- learning_rate: 0.05")
    print("- num_leaves: 127")
    print("- min_child_samples: 50")
    print("- subsample: 0.9")
    print("- colsample_bytree: 0.9")
    print("- reg_alpha: 0.1")
    print("- reg_lambda: 0.1")

if __name__ == "__main__":
    main()
