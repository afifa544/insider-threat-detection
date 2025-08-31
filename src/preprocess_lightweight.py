# src/preprocess_lightweight.py
import pandas as pd
import numpy as np
from datetime import datetime
import os

def preprocess_data(file_path):
    """Preprocess the lightweight data"""
    print(f"Loading data from {file_path}...")
    df = pd.read_csv(file_path)
    
    # Convert timestamp
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
    
    print(f"Preprocessed {len(df)} records")
    return df

def extract_features(df):
    """Extract features from the preprocessed data"""
    print("Extracting features...")
    
    # User behavior features
    user_features = df.groupby('user').agg({
        'timestamp': ['count', 'nunique'],  # Total activities, unique days
        'hour': ['mean', 'std'],  # Activity timing
        'day_of_week': ['mean', 'std'],  # Activity patterns
        'status': lambda x: (x == 'failed').mean(),  # Failure rate
        'threat_label': 'sum'  # Total threats
    }).reset_index()
    
    # Flatten column names
    user_features.columns = ['_'.join(col).strip() if col[1] else col[0] 
                            for col in user_features.columns.values]
    
    # Activity type features
    activity_counts = pd.crosstab(df['user'], df['activity'], normalize='index')
    activity_counts.columns = [f'activity_{col}_ratio' for col in activity_counts.columns]
    
    # Merge all features
    features = user_features.merge(activity_counts, left_on='user', right_index=True)
    
    print(f"Extracted features for {len(features)} users")
    return features

def main():
    # Create directories if they don't exist
    os.makedirs('data/processed', exist_ok=True)
    
    # Preprocess data
    df = preprocess_data('data/raw/synthetic_insider_data.csv')
    features = extract_features(df)
    
    # Save processed data
    features.to_parquet('data/processed/lightweight_features.parquet')
    features.to_csv('data/processed/lightweight_features.csv', index=False)
    
    print(f"Features shape: {features.shape}")
    print("Features saved to data/processed/lightweight_features.parquet and .csv")
    
    return features

if __name__ == "__main__":
    main()