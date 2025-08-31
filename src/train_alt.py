# src/train_alternative.py
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import OneClassSVM
import joblib

def train_alternative_models():
    """Train alternative lightweight models"""
    features = pd.read_parquet('data/processed/lightweight_features.parquet')
    
    X = features.drop(['user', 'threat_label_sum'], axis=1, errors='ignore')
    y = features.get('threat_label_sum', None)
    
    # Option 1: Random Forest (if we have labels)
    if y is not None and y.sum() > 0:
        rf_model = RandomForestClassifier(n_estimators=50, random_state=42)
        rf_model.fit(X, y > 0)  # Binary classification: threat or not
        joblib.dump(rf_model, 'models/lightweight_rf.pkl')
        print("Random Forest model trained and saved")
    
    # Option 2: One-Class SVM (unsupervised)
    oc_svm = OneClassSVM(nu=0.05, kernel='rbf')
    oc_svm.fit(X)
    joblib.dump(oc_svm, 'models/lightweight_oc_svm.pkl')
    print("One-Class SVM model trained and saved")

if __name__ == "__main__":
    train_alternative_models()