# src/advanced_models.py
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
import xgboost as xgb
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

class AdvancedThreatDetector:
    def __init__(self):
        self.models = {
            'isolation_forest': IsolationForest(contamination=0.1),
            'random_forest': RandomForestClassifier(n_estimators=100),
            'xgboost': xgb.XGBClassifier(),
            'svm': OneClassSVM(nu=0.1),
            'dbscan': DBSCAN(eps=0.5, min_samples=5)
        }
    
    def create_lstm_autoencoder(self, input_shape):
        """Advanced LSTM Autoencoder for sequence data"""
        model = Sequential([
            LSTM(64, activation='relu', input_shape=input_shape, return_sequences=True),
            Dropout(0.2),
            LSTM(32, activation='relu', return_sequences=False),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(32, activation='relu'),
            Dense(64, activation='relu'),
            Dense(input_shape[0], activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='mse')
        return model