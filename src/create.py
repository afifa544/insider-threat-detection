# src/create_test_data.py
import json
import os
from datetime import datetime, timedelta
import random

def create_test_json():
    """Create a simple test JSON file for the dashboard"""
    test_data = []
    
    users = [f"user_{i:03d}" for i in range(1, 21)]
    
    for user in users:
        risk_score = random.uniform(0.1, 0.9)
        test_data.append({
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "risk_score": risk_score,
            "is_anomaly": 1 if risk_score > 0.7 else 0,
            "model_version": "test_data"
        })
    
    os.makedirs('data/processed', exist_ok=True)
    
    with open('data/processed/simulated_es_data.json', 'w') as f:
        json.dump(test_data, f, indent=2)
    
    print(f"✅ Created test data with {len(test_data)} records")
    anomalies = sum(1 for d in test_data if d['is_anomaly'] == 1)
    print(f"📊 Anomalies: {anomalies}")

if __name__ == "__main__":
    create_test_json()