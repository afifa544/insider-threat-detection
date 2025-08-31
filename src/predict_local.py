# src/predict_local.py
import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime
import os
# Add at the top:
from src.aws_integration import AWSManager

# Add after saving local JSON:
def upload_to_aws(data):
    aws = AWSManager()
    
    # Upload to S3
    aws.upload_to_s3(
        data, 
        'your-threat-detection-bucket',
        'processed_data/latest_threats.json'
    )
    
    # Log metrics to CloudWatch
    anomalies = sum(1 for d in data if d['is_anomaly'] == 1)
    aws.log_to_cloudwatch(
        'AnomaliesDetected',
        anomalies,
        [{'Name': 'System', 'Value': 'Production'}]
    )
def simulate_elasticsearch():
    """Simulate Elasticsearch functionality locally"""
    print("🔍 Starting prediction pipeline...")
    
    # Create directory if it doesn't exist
    os.makedirs('data/processed', exist_ok=True)
    
    # Check if model exists
    model_path = 'models/lightweight_isolation_forest.pkl'
    if not os.path.exists(model_path):
        print(f"❌ Model file not found: {model_path}")
        print("Please run: python src/train_baseline_lightweight.py")
        return False
    
    # Check if features exist
    features_path = 'data/processed/lightweight_features.parquet'
    if not os.path.exists(features_path):
        print(f"❌ Features file not found: {features_path}")
        print("Please run: python src/preprocess_lightweight.py")
        return False
    
    # Load model and data
    print("📦 Loading model and data...")
    try:
        model = joblib.load(model_path)
        features = pd.read_parquet(features_path)
        print(f"✅ Loaded {len(features)} user records")
    except Exception as e:
        print(f"❌ Error loading files: {e}")
        return False
    
    # Make predictions
    print("🤖 Making predictions...")
    try:
        # Check if user column exists
        if 'user' not in features.columns:
            print("❌ 'user' column not found in features")
            return False
            
        X = features.drop(['user'], axis=1, errors='ignore')
        predictions = model.predict(X)
        
        # Get decision scores for better risk scoring
        if hasattr(model, 'decision_function'):
            decision_scores = model.decision_function(X)
            # Convert to probabilities (0-1 range)
            risk_scores = 1 / (1 + np.exp(-decision_scores))
        else:
            # Fallback: simple scoring
            risk_scores = [0.9 if pred == -1 else 0.1 for pred in predictions]
        
        # Create "documents" for our simulated Elasticsearch
        documents = []
        for i, (_, row) in enumerate(features.iterrows()):
            doc = {
                "timestamp": datetime.now().isoformat(),
                "user": row['user'],
                "risk_score": float(risk_scores[i]),
                "is_anomaly": int(predictions[i] == -1),
                "model_version": "lightweight_v1"
            }
            documents.append(doc)
        
        # Save to JSON file
        output_path = 'data/processed/simulated_es_data.json'
        with open(output_path, 'w') as f:
            json.dump(documents, f, indent=2)
        
        anomalies = sum(1 for d in documents if d['is_anomaly'] == 1)
        print(f"✅ Created {output_path} with {len(documents)} records")
        print(f"📊 Anomalies detected: {anomalies} ({anomalies/len(documents)*100:.1f}%)")
        return True
        
    except Exception as e:
        print(f"❌ Error during prediction: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = simulate_elasticsearch()
    if not success:
        print("\n💡 Troubleshooting tips:")
        print("1. Run: python src/download_data.py")
        print("2. Run: python src/preprocess_lightweight.py") 
        print("3. Run: python src/train_baseline_lightweight.py")
        print("4. Then run this script again")
        exit(1)