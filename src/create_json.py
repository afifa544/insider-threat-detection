# create_json.py
import pandas as pd
import json
import os
from datetime import datetime
import random
import numpy as np

def add_tor_usage_features(documents):
    """Add Tor usage simulation to the data"""
    tor_count = 0
    for doc in documents:
        # 5% of users use Tor
        if random.random() < 0.05:
            doc['tor_usage'] = True
            doc['risk_score'] = min(1.0, doc['risk_score'] + 0.3)  # Increase risk
            doc['is_anomaly'] = 1  # Mark as anomaly
            tor_count += 1
        else:
            doc['tor_usage'] = False
            
    print(f"🔍 Tor users simulated: {tor_count}")
    return documents

def create_json_file():
    """Create the JSON file that the dashboard needs"""
    print("📊 Creating dashboard data file...")
    
    # Load your existing features to get real user names
    try:
        features = pd.read_parquet('data/processed/lightweight_features.parquet')
        users = features['user'].tolist()
        print(f"✅ Loaded {len(users)} real users from your data")
    except:
        # Fallback: create demo users
        users = [f"user_{i:03d}" for i in range(1, 51)]
        print("⚠️ Using demo users (could not load features)")
    
    # Create more realistic risk data
    documents = []
    for i, user in enumerate(users):
        # Create a more realistic risk distribution:
        # - 70% normal users (risk 0.1-0.4)
        # - 20% slightly suspicious (risk 0.4-0.6) 
        # - 10% high risk (risk 0.7-0.9)
        
        if i < len(users) * 0.7:  # 70% normal
            risk_score = round(random.uniform(0.1, 0.4), 3)
        elif i < len(users) * 0.9:  # 20% medium risk
            risk_score = round(random.uniform(0.4, 0.6), 3)
        else:  # 10% high risk
            risk_score = round(random.uniform(0.7, 0.9), 3)
        
        is_anomaly = 1 if risk_score > 0.6 else 0
        
        doc = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "risk_score": risk_score,
            "is_anomaly": is_anomaly,
            "model_version": "production_v1"
        }
        documents.append(doc)
    
    # Add Tor usage features
# In create_json.py, add this function:
def add_tor_usage_features(documents):
    """Add Tor usage simulation to the data"""
    tor_count = 0
    for doc in documents:
        # 5% of users use Tor
        if random.random() < 0.05:
            doc['tor_usage'] = True
            doc['risk_score'] = min(1.0, doc['risk_score'] + 0.3)  # Increase risk
            doc['is_anomaly'] = 1  # Mark as anomaly
            tor_count += 1
        else:
            doc['tor_usage'] = False
            
    print(f"🔍 Tor users simulated: {tor_count}")
    return documents

# Call this function before saving:
documents = add_tor_usage_features(documents)    
    # Make sure directory exists
    os.makedirs('data/processed', exist_ok=True)
    
    # Save to JSON file
    json_path = 'data/processed/simulated_es_data.json'
    with open(json_path, 'w') as f:
        json.dump(documents, f, indent=2)
    
    print(f"✅ Created {json_path}")
    print(f"📊 Total records: {len(documents)}")
    
    anomalies = sum(1 for d in documents if d['is_anomaly'] == 1)
    print(f"🚨 Anomalies detected: {anomalies} ({anomalies/len(documents)*100:.1f}%)")
    
    tor_users = sum(1 for d in documents if d.get('tor_usage', False))
    print(f"🕵️ Tor users: {tor_users} ({tor_users/len(documents)*100:.1f}%)")

if __name__ == "__main__":
    create_json_file()