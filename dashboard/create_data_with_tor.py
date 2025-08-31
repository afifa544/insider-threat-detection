# create_data_with_tor.py
import pandas as pd
import json
import os
from datetime import datetime
import random

def create_json_with_tor():
    """Create JSON data with Tor usage simulation"""
    print("📊 Creating data with Tor detection...")
    
    # Create sample users
    users = [f"user_{i:03d}" for i in range(1, 51)]
    
    documents = []
    for i, user in enumerate(users):
        # Realistic risk distribution
        if i < len(users) * 0.7:  # 70% normal
            risk_score = round(random.uniform(0.1, 0.4), 3)
        elif i < len(users) * 0.9:  # 20% medium risk
            risk_score = round(random.uniform(0.4, 0.6), 3)
        else:  # 10% high risk
            risk_score = round(random.uniform(0.7, 0.9), 3)
        
        # 5% use Tor
        tor_usage = random.random() < 0.05
        if tor_usage:
            risk_score = min(1.0, risk_score + 0.3)  # Increase risk for Tor users
        
        doc = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "risk_score": risk_score,
            "is_anomaly": 1 if risk_score > 0.6 else 0,
            "tor_usage": tor_usage
        }
        documents.append(doc)
    
    # Save to JSON file
    os.makedirs('data/processed', exist_ok=True)
    json_path = 'data/processed/simulated_es_data.json'
    
    with open(json_path, 'w') as f:
        json.dump(documents, f, indent=2)
    
    print(f"✅ Created {json_path}")
    print(f"📊 Total records: {len(documents)}")
    
    anomalies = sum(1 for d in documents if d['is_anomaly'] == 1)
    tor_users = sum(1 for d in documents if d['tor_usage'])
    
    print(f"🚨 Anomalies: {anomalies} ({anomalies/len(documents)*100:.1f}%)")
    print(f"🕵️ Tor users: {tor_users} ({tor_users/len(documents)*100:.1f}%)")

if __name__ == "__main__":
    create_json_with_tor()