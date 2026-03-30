#!/usr/bin/env python3
"""
Train with Actual UCI Phishing Websites Dataset
================================================
Uses the real UCI Phishing Websites dataset for training
and gets realistic accuracy metrics.

Run: python train_with_uci_real.py
"""

import os
import sys
import json
import time
import warnings
import numpy as np
import pandas as pd

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

warnings.filterwarnings('ignore')

# ML Libraries
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)

# Try to import XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# Configuration
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'models')
DATASET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'datasets')
UCI_DIR = os.path.join(DATASET_DIR, 'uci_actual')

os.makedirs(MODEL_DIR, exist_ok=True)


def parse_arff(filepath):
    """Parse ARFF file to DataFrame."""
    print(f"Parsing ARFF file: {filepath}")
    
    attributes = []
    data = []
    reading_data = False
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('@attribute'):
                # Extract attribute name and type
                parts = line.replace('@attribute', '').strip().split()
                attr_name = parts[0]
                attr_type = parts[1] if len(parts) > 1 else 'string'
                attributes.append((attr_name, attr_type))
            elif line.startswith('@data'):
                reading_data = True
            elif reading_data and line and not line.startswith('%'):
                # Parse data line
                values = parse_arff_line(line)
                if len(values) == len(attributes):
                    data.append(values)
    
    # Create DataFrame
    df = pd.DataFrame(data, columns=[a[0] for a in attributes])
    
    # Convert to numeric where possible
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='ignore')
    
    print(f"Loaded: {len(df)} rows, {len(attributes)} features")
    return df


def parse_arff_line(line):
    """Parse ARFF data line handling quoted strings."""
    values = []
    current = ''
    in_quotes = False
    
    for char in line:
        if char == "'" and not in_quotes:
            in_quotes = True
        elif char == "'" and in_quotes:
            in_quotes = False
        elif char == ',' and not in_quotes:
            values.append(current.strip("'").strip('"').strip())
            current = ''
        else:
            current += char
    
    values.append(current.strip("'").strip('"').strip())
    return values


def load_uci_dataset():
    """Load the actual UCI Phishing Websites dataset."""
    print("\n" + "="*60)
    print("LOADING UCI PHISHING WEBSITES DATASET")
    print("="*60)
    
    arff_path = os.path.join(UCI_DIR, 'Training Dataset.arff')
    
    if not os.path.exists(arff_path):
        print(f"ARFF file not found: {arff_path}")
        return None
    
    df = parse_arff(arff_path)
    
    print(f"\nDataset shape: {df.shape}")
    print(f"Columns: {list(df.columns[:10])}...")
    
    # Check label distribution
    if 'class' in df.columns:
        label_col = 'class'
    elif 'Result' in df.columns:
        label_col = 'Result'
    else:
        # Find label column
        for col in df.columns:
            if df[col].nunique() <= 2:
                label_col = col
                break
    
    print(f"\nLabel column: {label_col}")
    print(f"Label distribution:\n{df[label_col].value_counts()}")
    
    # Map labels to binary (1=phishing, 0=legitimate)
    # UCI uses: -1 for phishing, 1 for legitimate (or 1 for phishing, -1 for legitimate)
    if label_col in df.columns:
        # Check unique values
        unique_vals = df[label_col].unique()
        print(f"Unique label values: {unique_vals}")
        
        # Standardize: 1 = phishing, 0 = legitimate
        if -1 in unique_vals and 1 in unique_vals:
            # If -1 means phishing, convert to 1
            df['label'] = df[label_col].apply(lambda x: 1 if x == -1 else 0)
        else:
            df['label'] = df[label_col]
        
        print(f"Converted label distribution:")
        print(f"  Phishing (1): {sum(df['label']==1)}")
        print(f"  Legitimate (0): {sum(df['label']==0)}")
    
    return df


def add_url_based_features(df):
    """Add URL-based features to UCI dataset for hybrid training."""
    print("\nAdding URL-based features...")
    
    # Generate sample URLs based on UCI features
    np.random.seed(42)
    n = len(df)
    
    # Generate URLs that match the UCI features
    urls = []
    
    for idx, row in df.iterrows():
        # Build URL based on features
        has_ip = row.get('having_IP_Address', -1)
        url_length = row.get('URL_Length', 20)
        has_at = row.get('having_At_Symbol', -1)
        https = row.get('SSLfinal_State', 1)
        
        if has_ip == 1 or has_ip == -1:
            # Suspicious
            if np.random.random() < 0.5:
                url = f"http://192.168.1.{np.random.randint(1,255)}/login"
            else:
                url = f"http://secure-{np.random.choice(['paypal','bank','account'])}-{np.random.choice(['verify','update','login'])}.tk/path"
        else:
            # Normal
            domain = np.random.choice(['google', 'facebook', 'amazon', 'microsoft', 'github'])
            url = f"https://www.{domain}.com/{np.random.choice(['search','profile','item'])}"
        
        urls.append(url)
    
    # Extract features from URLs
    from phishing_detector import URLFeatureExtractor
    extractor = URLFeatureExtractor()
    
    features_list = []
    for url in urls:
        features = extractor.extract_features(url)
        if features:
            features_list.append(features)
    
    url_features_df = pd.DataFrame(features_list)
    
    # Combine UCI features with URL features
    feature_cols = [c for c in df.columns if c != label_col]
    
    # Use UCI features
    X_uci = df[feature_cols].copy()
    
    # Add URL features (aligned by index)
    for col in url_features_df.columns:
        if col in X_uci.columns:
            X_uci[col] = url_features_df[col].values
        else:
            X_uci[col] = url_features_df[col].values
    
    X_uci['label'] = df['label']
    
    print(f"Combined dataset: {X_uci.shape}")
    return X_uci


def train_models(df):
    """Train and evaluate models with real UCI data."""
    print("\n" + "="*60)
    print("TRAINING MODELS WITH UCI DATASET")
    print("="*60)
    
    # Prepare features and labels
    label_col = 'label'
    X = df.drop(columns=[label_col])
    y = df[label_col]
    
    # Ensure all features are numeric
    X = X.select_dtypes(include=[np.number])
    
    # Handle any missing values
    X = X.fillna(0)
    
    print(f"\nFeatures: {X.shape[1]}")
    print(f"Training samples: {len(X)}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)}")
    print(f"Test set: {len(X_test)}")
    print(f"Test phishing: {sum(y_test==1)}, legitimate: {sum(y_test==0)}")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    results = {}
    
    # Train Random Forest
    print("\n--- Training Random Forest ---")
    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    start_time = time.time()
    rf_model.fit(X_train_scaled, y_train)
    rf_time = time.time() - start_time
    
    y_pred_rf = rf_model.predict(X_test_scaled)
    y_prob_rf = rf_model.predict_proba(X_test_scaled)[:, 1]
    
    rf_acc = accuracy_score(y_test, y_pred_rf)
    rf_prec = precision_score(y_test, y_pred_rf)
    rf_rec = recall_score(y_test, y_pred_rf)
    rf_f1 = f1_score(y_test, y_pred_rf)
    rf_auc = roc_auc_score(y_test, y_prob_rf)
    
    results['Random Forest'] = {
        'accuracy': rf_acc,
        'precision': rf_prec,
        'recall': rf_rec,
        'f1_score': rf_f1,
        'roc_auc': rf_auc,
        'train_time': rf_time
    }
    
    print(f"  Accuracy:  {rf_acc:.4f} ({rf_acc*100:.2f}%)")
    print(f"  Precision: {rf_prec:.4f}")
    print(f"  Recall:    {rf_rec:.4f}")
    print(f"  F1-Score:  {rf_f1:.4f}")
    print(f"  ROC-AUC:   {rf_auc:.4f}")
    
    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf_model, X_train_scaled, y_train, cv=cv, scoring='accuracy')
    print(f"  CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
    results['Random Forest']['cv_accuracy'] = cv_scores.mean()
    
    # Train XGBoost if available
    if XGBOOST_AVAILABLE:
        print("\n--- Training XGBoost ---")
        
        scale_pos = len(y_train[y_train==0]) / max(len(y_train[y_train==1]), 1)
        
        xgb_model = xgb.XGBClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos,
            random_state=42,
            eval_metric='logloss',
            n_jobs=-1
        )
        
        start_time = time.time()
        xgb_model.fit(X_train_scaled, y_train)
        xgb_time = time.time() - start_time
        
        y_pred_xgb = xgb_model.predict(X_test_scaled)
        y_prob_xgb = xgb_model.predict_proba(X_test_scaled)[:, 1]
        
        xgb_acc = accuracy_score(y_test, y_pred_xgb)
        xgb_prec = precision_score(y_test, y_pred_xgb)
        xgb_rec = recall_score(y_test, y_pred_xgb)
        xgb_f1 = f1_score(y_test, y_pred_xgb)
        xgb_auc = roc_auc_score(y_test, y_prob_xgb)
        
        results['XGBoost'] = {
            'accuracy': xgb_acc,
            'precision': xgb_prec,
            'recall': xgb_rec,
            'f1_score': xgb_f1,
            'roc_auc': xgb_auc,
            'train_time': xgb_time
        }
        
        print(f"  Accuracy:  {xgb_acc:.4f} ({xgb_acc*100:.2f}%)")
        print(f"  Precision: {xgb_prec:.4f}")
        print(f"  Recall:    {xgb_rec:.4f}")
        print(f"  F1-Score:  {xgb_f1:.4f}")
        print(f"  ROC-AUC:   {xgb_auc:.4f}")
        
        cv_scores_xgb = cross_val_score(xgb_model, X_train_scaled, y_train, cv=cv, scoring='accuracy')
        print(f"  CV Accuracy: {cv_scores_xgb.mean():.4f} (+/- {cv_scores_xgb.std()*2:.4f})")
        results['XGBoost']['cv_accuracy'] = cv_scores_xgb.mean()
        
        # Ensemble
        print("\n--- Training Ensemble ---")
        
        ensemble = VotingClassifier(
            estimators=[('rf', rf_model), ('xgb', xgb_model)],
            voting='soft'
        )
        
        ensemble.fit(X_train_scaled, y_train)
        y_pred_ens = ensemble.predict(X_test_scaled)
        y_prob_ens = ensemble.predict_proba(X_test_scaled)[:, 1]
        
        ens_acc = accuracy_score(y_test, y_pred_ens)
        ens_prec = precision_score(y_test, y_pred_ens)
        ens_rec = recall_score(y_test, y_pred_ens)
        ens_f1 = f1_score(y_test, y_pred_ens)
        ens_auc = roc_auc_score(y_test, y_prob_ens)
        
        results['Ensemble'] = {
            'accuracy': ens_acc,
            'precision': ens_prec,
            'recall': ens_rec,
            'f1_score': ens_f1,
            'roc_auc': ens_auc
        }
        
        print(f"  Accuracy:  {ens_acc:.4f} ({ens_acc*100:.2f}%)")
        print(f"  Precision: {ens_prec:.4f}")
        print(f"  Recall:    {ens_rec:.4f}")
        print(f"  F1-Score:  {ens_f1:.4f}")
        print(f"  ROC-AUC:   {ens_auc:.4f}")
        
        best_model = ensemble
    else:
        best_model = rf_model
    
    # Feature importance
    print("\n--- Top 10 Feature Importances ---")
    importances = rf_model.feature_importances_
    feature_names = list(X.columns)
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    }).sort_values('importance', ascending=False)
    
    for idx, row in importance_df.head(10).iterrows():
        print(f"  {row['feature']}: {row['importance']:.4f}")
    
    # Save models
    print("\n--- Saving Models ---")
    import joblib
    
    model_path = os.path.join(MODEL_DIR, 'url_phishing_model.joblib')
    joblib.dump(best_model, model_path)
    print(f"✓ Saved model: {model_path}")
    
    scaler_path = os.path.join(MODEL_DIR, 'url_scaler.joblib')
    joblib.dump(scaler, scaler_path)
    print(f"✓ Saved scaler: {scaler_path}")
    
    # Save results
    results_path = os.path.join(DATASET_DIR, 'uci_training_results.json')
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"✓ Saved results: {results_path}")
    
    # Confusion matrix
    print("\n--- Confusion Matrix ---")
    cm = confusion_matrix(y_test, y_pred_rf)
    print(f"  True Negatives:  {cm[0][0]}")
    print(f"  False Positives: {cm[0][1]}")
    print(f"  False Negatives: {cm[1][0]}")
    print(f"  True Positives:  {cm[1][1]}")
    
    return results


def main():
    """Main function."""
    print("\n" + "="*70)
    print("TRAINING WITH UCI REAL PHISHING DATASET")
    print("="*70)
    
    # Load UCI dataset
    df = load_uci_dataset()
    
    if df is not None:
        # Train models
        results = train_models(df)
        
        # Print summary
        print("\n" + "="*70)
        print("TRAINING COMPLETE - UCI DATASET RESULTS")
        print("="*70)
        
        for model_name, metrics in results.items():
            print(f"\n{model_name}:")
            print(f"  Accuracy:    {metrics['accuracy']*100:.2f}%")
            print(f"  Precision:   {metrics['precision']:.4f}")
            print(f"  Recall:      {metrics['recall']:.4f}")
            print(f"  F1-Score:    {metrics['f1_score']:.4f}")
            print(f"  ROC-AUC:     {metrics['roc_auc']:.4f}")
        
        best = max(results.items(), key=lambda x: x[1]['accuracy'])
        print(f"\n{'='*70}")
        print(f"BEST MODEL: {best[0]} with {best[1]['accuracy']*100:.2f}% Accuracy")
        print(f"{'='*70}")
    else:
        print("Failed to load UCI dataset")


if __name__ == '__main__':
    main()

