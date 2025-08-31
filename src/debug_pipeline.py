# src/debug_pipeline.py
import os
import json
import pandas as pd

def check_files():
    """Check if all required files exist"""
    files_to_check = [
        'data/raw/synthetic_insider_data.csv',
        'data/processed/lightweight_features.parquet',
        'data/processed/lightweight_features.csv', 
        'models/lightweight_isolation_forest.pkl',
        'data/processed/simulated_es_data.json'
    ]
    
    print("🔍 Checking if files exist:")
    for file_path in files_to_check:
        exists = os.path.exists(file_path)
        status = "✅ EXISTS" if exists else "❌ MISSING"
        print(f"{status}: {file_path}")
        
        if exists and file_path.endswith('.json'):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                print(f"   📊 JSON has {len(data)} records")
            except Exception as e:
                print(f"   ❌ Error reading JSON: {e}")
        
        if exists and file_path.endswith('.csv'):
            try:
                df = pd.read_csv(file_path)
                print(f"   📊 CSV has {len(df)} rows, {len(df.columns)} columns")
            except Exception as e:
                print(f"   ❌ Error reading CSV: {e}")

if __name__ == "__main__":
    check_files()
    