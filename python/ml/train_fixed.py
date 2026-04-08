import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load UCI data (real dataset)
df = pd.read_csv('../../datasets/combined_real_data.csv')

# Use 'label' column
label_col = 'label'
feature_cols = [col for col in df.columns if col != label_col]
X = df[feature_cols].fillna(0)
y = df[label_col]

logger.info(f'Data loaded: {X.shape}, classes: {np.bincount(y)}')

# 80/20 split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train RF with regularization (prevent overfitting)
rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
rf.fit(X_train_scaled, y_train)

# Test
y_pred = rf.predict(X_test_scaled)
acc = accuracy_score(y_test, y_pred)
auc = roc_auc_score(y_test, rf.predict_proba(X_test_scaled)[:,1])

logger.info(f'Test Accuracy: {acc:.4f}, AUC: {auc:.4f}')
print(classification_report(y_test, y_pred))

# Save for backend
os.makedirs('../../backend/models', exist_ok=True)
joblib.dump(rf, '../../backend/models/url_phishing_model.joblib')
joblib.dump(scaler, '../../backend/models/url_scaler.joblib')

logger.info('Models saved - overfitting fixed with split/regularization')
