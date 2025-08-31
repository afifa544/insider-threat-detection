# src/train_baseline_lightweight.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import joblib
import os

def train_lightweight_model():
    """Train model on lightweight data"""
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Load features
    print("Loading features...")
    features = pd.read_parquet('data/processed/lightweight_features.parquet')
    
    # Prepare data
    X = features.drop(['user'], axis=1, errors='ignore')
    
    # Check if we have threat labels for evaluation
    has_labels = 'threat_label_sum' in features.columns
    
    if has_labels:
        y = features['threat_label_sum']
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
    else:
        X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
        y_test = None
    
    # Train Isolation Forest
    print("Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=50,
        max_samples=100,
        contamination=0.05,
        random_state=42,
        verbose=1
    )
    
    model.fit(X_train)
    
    # Evaluate if we have labels
    if has_labels and y_test is not None:
        print("Evaluating model...")
        predictions = model.predict(X_test)
        predictions_binary = np.where(predictions == -1, 1, 0)
        
        print("Confusion Matrix:")
        print(confusion_matrix(y_test > 0, predictions_binary))
        
        print("\nClassification Report:")
        print(classification_report(y_test > 0, predictions_binary))
    
    # Save model
    joblib.dump(model, 'models/lightweight_isolation_forest.pkl')
    print("Model saved to models/lightweight_isolation_forest.pkl")
    
    return model

if __name__ == "__main__":
    train_lightweight_model()