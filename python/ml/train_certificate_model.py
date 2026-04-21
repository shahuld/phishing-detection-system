"""
Certificate Phishing Detection Model Training
Uses SSL certificate features to detect phishing sites
"""

import numpy as np
import json
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

# Certificate features:
# 0: days_until_expiry (normalized 0-1)
# 1: key_size_normalized (0.5 for 2048, 1.0 for 4096)
# 2: has_chain (0 or 1)
# 3: san_count_normalized (0-1)
# 4: has_wildcard (0 or 1)
# 5: expiring_soon (0 or 1)
# 6: key_strength (0-1, weak=0, strong=1)
# 7: tld_risk (0-1, common safe=0, suspicious=1)

def generate_certificate_data():
    """Generate synthetic certificate data for training"""
    np.random.seed(42)
    
    # Valid certificates (label 0)
    valid_samples = 500
    X_valid = np.zeros((valid_samples, 8))
    
    # Valid certs: long expiry, proper chain, reasonable SAN count, no wildcard
    X_valid[:, 0] = np.random.uniform(0.3, 1.0, valid_samples)  # days until expiry
    X_valid[:, 1] = np.random.choice([0.5, 1.0], valid_samples)  # 2048 or 4096 bit
    X_valid[:, 2] = np.random.choice([0, 1], valid_samples, p=[0.1, 0.9])  # has chain
    X_valid[:, 3] = np.random.uniform(0.1, 0.5, valid_samples)  # san count
    X_valid[:, 4] = np.random.choice([0, 1], valid_samples, p=[0.95, 0.05])  # wildcard rare
    X_valid[:, 5] = np.random.choice([0, 1], valid_samples, p=[0.95, 0.05])  # expiring soon rare
    X_valid[:, 6] = np.random.uniform(0.5, 1.0, valid_samples)  # strong keys
    X_valid[:, 7] = np.random.uniform(0, 0.2, valid_samples)  # safe TLDs
    
    y_valid = np.zeros(valid_samples)  # 0 = valid/safe
    
    # Phishing certificates (label 1)
    phishing_samples = 500
    X_phishing = np.zeros((phishing_samples, 8))
    
    # Phishing certs: short expiry, no chain, suspicious TLDs, wildcard abuse
    X_phishing[:, 0] = np.random.uniform(0, 0.3, phishing_samples)  # short expiry
    X_phishing[:, 1] = np.random.choice([0.25, 0.5], phishing_samples)  # weak keys (1024 or 2048)
    X_phishing[:, 2] = np.random.choice([0, 1], phishing_samples, p=[0.6, 0.4])  # no chain often
    X_phishing[:, 3] = np.random.choice([0, 0.1, 0.2], phishing_samples)  # few SANs
    X_phishing[:, 4] = np.random.choice([0, 1], phishing_samples, p=[0.5, 0.5])  # wildcard common
    X_phishing[:, 5] = np.random.choice([0, 1], phishing_samples, p=[0.3, 0.7])  # expiring soon common
    X_phishing[:, 6] = np.random.uniform(0, 0.5, phishing_samples)  # weak keys
    X_phishing[:, 7] = np.random.uniform(0.3, 1.0, phishing_samples)  # suspicious TLDs
    
    y_phishing = np.ones(phishing_samples)  # 1 = phishing/suspicious
    
    # Combine
    X = np.vstack([X_valid, X_phishing])
    y = np.concatenate([y_valid, y_phishing])
    
    return X, y

def main():
    print("Generating certificate training data...")
    X, y = generate_certificate_data()
    
    print(f"Total samples: {len(y)}")
    print(f"Safe: {sum(y==0)}, Phishing: {sum(y==1)}")
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train model
    print("Training certificate model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    train_acc = model.score(X_train_scaled, y_train)
    test_acc = model.score(X_test_scaled, y_test)
    print(f"Train accuracy: {train_acc:.2%}")
    print(f"Test accuracy: {test_acc:.2%}")
    
    # Save model and scaler
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_path = os.path.join(script_dir, '../../backend/models')
    
    os.makedirs(base_path, exist_ok=True)
    
    model_path = os.path.join(base_path, 'certificate_phishing_model.joblib')
    scaler_path = os.path.join(base_path, 'certificate_scaler.joblib')
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"\nModel saved to: {model_path}")
    print(f"Scaler saved to: {scaler_path}")
    
    # Test prediction
    print("\nTest predictions:")
    test_cases = [
        [0.9, 1.0, 1, 0.3, 0, 0, 1.0, 0.1],  # Good cert
        [0.1, 0.5, 0, 0.1, 1, 1, 0.3, 0.8],  # Bad cert
    ]
    for case in test_cases:
        scaled = scaler.transform([case])
        pred = model.predict(scaled)[0]
        prob = model.predict_proba(scaled)[0]
        print(f"  Features: {case[:4]}...")
        print(f"  Prediction: {'Phishing' if pred == 1 else 'Valid'}")
        print(f"  Confidence: Valid={prob[0]:.2%}, Phishing={prob[1]:.2%}\n")

if __name__ == '__main__':
    main()
