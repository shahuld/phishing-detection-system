#!/usr/bin/env python3
"""
Train with Realistic Data - More Real-World Accuracy
====================================================
This creates more realistic noisy data to simulate 
real-world detection challenges and get practical accuracy.

Run: python train_realistic.py
"""

import os
import sys
import json
import time
import warnings
import numpy as np
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

from URLFeatureExtractor import URLFeatureExtractor
import joblib

# Configuration
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'models')
DATASET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'datasets')

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATASET_DIR, exist_ok=True)


def generate_realistic_urls(n_samples=20000, noise_level=0.15):
    """
    Generate realistic URL dataset with noise to simulate real-world challenges.
    - Some legitimate URLs with suspicious features
    - Some phishing URLs that look legitimate
    - Edge cases and ambiguous patterns
    """
    np.random.seed(42)
    
    print(f"Generating {n_samples} realistic URL samples with {noise_level*100}% noise...")
    
    urls = []
    labels = []
    
    # Legitimate URL patterns (with occasional suspicious features)
    legitimate_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co']
    legitimate_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'github', 
                         'linkedin', 'twitter', 'youtube', 'netflix', 'yahoo', 'ebay',
                         'instagram', 'reddit', 'wikipedia', 'dropbox', 'shopify']
    
    # Phishing URL patterns (sometimes look legitimate)
    phishing_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', 
                    '.click', '.pw', '.cc', '.site', '.online', '.shop']
    phishing_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 
                        'confirm', 'banking', 'support', 'service']
    
    # Generate 60% legitimate (0)
    n_legit = int(n_samples * 0.6)
    for i in range(n_legit):
        # Base: clean legitimate URL
        domain = np.random.choice(legitimate_domains)
        tld = np.random.choice(legitimate_tlds)
        
        # Sometimes add path/query (normal behavior)
        if np.random.random() < 0.5:
            path = np.random.choice(['search', 'profile', 'dashboard', 'settings', 
                                   'products', 'item', 'category', 'blog', 'about'])
            url = f"https://www.{domain}{tld}/{path}"
        else:
            url = f"https://www.{domain}{tld}"
        
        # Add noise: some legitimate URLs have suspicious features
        if np.random.random() < noise_level:
            noise_type = np.random.choice(['long', 'path', 'query', 'tld'])
            if noise_type == 'long':
                url = url + "/path/to/some/deeply/nested/resource/page"
            elif noise_type == 'path':
                url = f"https://www.{domain}{tld}/login"
            elif noise_type == 'query':
                url = url + "?ref=external&utm_source=test"
            elif noise_type == 'tld':
                # Change to less common but still legitimate TLD
                url = f"https://{domain}.io"
        
        urls.append(url)
        labels.append(0)
    
    # Generate 40% phishing (1)
    n_phish = n_samples - n_legit
    for i in range(n_phish):
        # Base: suspicious phishing URL
        keyword = np.random.choice(phishing_keywords)
        tld = np.random.choice(phishing_tlds)
        domain = np.random.choice(legitimate_domains + ['secure', 'account', 'verify'])
        
        # Various phishing patterns
        pattern = np.random.choice([
            f"https://secure-{keyword}-{domain}{tld}/verify",
            f"https://{keyword}.{domain}{tld}/login",
            f"http://{domain}-{keyword}{tld}/confirm",
            f"https://account-{domain}{tld}/secure",
            f"http://{keyword}@{domain}.{tld}",
            f"https://{domain}.{tld}/{keyword}/update",
            f"http://login-{domain}{tld}.php",
            f"https://www.{keyword}-{domain}{tld}/auth"
        ])
        
        url = pattern
        
        # Add noise: some phishing URLs look very legitimate
        if np.random.random() < noise_level:
            # Sometimes use legitimate TLDs
            url = f"https://{keyword}.{np.random.choice(legitimate_tlds)}/login"
        
        urls.append(url)
        labels.append(1)
    
    # Shuffle
    indices = np.random.permutation(len(urls))
    urls = [urls[i] for i in indices]
    labels = [labels[i] for i in indices]
    
    return urls, labels


def extract_features(urls, labels):
    """Extract features from URLs."""
    print("Extracting features from URLs...")
    
    extractor = URLFeatureExtractor()
    feature_list = []
    valid_labels = []
    
    for i, (url, label) in enumerate(zip(urls, labels)):
        features = extractor.extract_features(url)
        if features:
            feature_list.append(features)
            valid_labels.append(label)
        
        if (i + 1) % 5000 == 0:
            print(f"  Processed {i+1}/{len(urls)} URLs...")
    
    df = pd.DataFrame(feature_list)
    df['label'] = valid_labels
    
    print(f"Extracted features for {len(df)} URLs")
    return df


def add_feature_noise(df, noise_prob=0.05):
    """Add noise to features to simulate real-world imperfection."""
    print(f"Adding {noise_prob*100}% feature noise...")
    
    df_noisy = df.copy()
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    
    for col in numeric_cols:
        if col != 'label':
            # Flip some features randomly
            mask = np.random.random(len(df_noisy)) < noise_prob
            df_noisy.loc[mask, col] = np.random.choice([0, 1], size=mask.sum())
    
    return df_noisy


def train_and_evaluate(df, dataset_name="Realistic"):
    """Train models and evaluate with realistic metrics."""
    print(f"\n{'='*60}")
    print(f"TRAINING ON {dataset_name} DATASET")
    print(f"{'='*60}")
    
    # Prepare features
    # Select EXACTLY 11 ML features matching detector
    ml_feature_cols = [
        'url_length_log', 'has_ip', 'has_at', 'dash_count_norm', 
        'suspicious_tld', 'http_no_ssl', 'subdomain_norm', 'digit_ratio',
        'entropy', 'hex_ratio', 'is_shortener'
    ]
    X = df[ml_feature_cols]
    y = df['label']
    
    feature_names = list(X.columns)
    print(f"\nFeatures ({len(feature_names)}): {feature_names}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training: {len(X_train)}, Test: {len(y_test)}")
    print(f"Class distribution - Train: {dict(y_train.value_counts())}, Test: {dict(y_test.value_counts())}")
    
    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    results = {}
    
    # Random Forest
    print("\n--- Random Forest ---")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    start = time.time()
    rf.fit(X_train_scaled, y_train)
    rf_time = time.time() - start
    
    y_pred = rf.predict(X_test_scaled)
    y_prob = rf.predict_proba(X_test_scaled)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_prob)
    
    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf, X_train_scaled, y_train, cv=cv, scoring='accuracy')
    
    results['Random Forest'] = {
        'accuracy': acc, 'precision': prec, 'recall': rec,
        'f1_score': f1, 'roc_auc': roc, 'train_time': rf_time,
        'cv_accuracy': cv_scores.mean(), 'cv_std': cv_scores.std()
    }
    
    print(f"  Accuracy:    {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision:   {prec:.4f}")
    print(f"  Recall:      {rec:.4f}")
    print(f"  F1-Score:    {f1:.4f}")
    print(f"  ROC-AUC:     {roc:.4f}")
    print(f"  CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:")
    print(f"    TN: {cm[0,0]}, FP: {cm[0,1]}")
    print(f"    FN: {cm[1,0]}, TP: {cm[1,1]}")
    
    # XGBoost
    if XGBOOST_AVAILABLE:
        print("\n--- XGBoost ---")
        
        scale_pos = len(y_train[y_train==0]) / max(len(y_train[y_train==1]), 1)
        
        xgb_model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos,
            random_state=42,
            eval_metric='logloss',
            n_jobs=-1
        )
        
        start = time.time()
        xgb_model.fit(X_train_scaled, y_train)
        xgb_time = time.time() - start
        
        y_pred_xgb = xgb_model.predict(X_test_scaled)
        y_prob_xgb = xgb_model.predict_proba(X_test_scaled)[:, 1]
        
        acc_xgb = accuracy_score(y_test, y_pred_xgb)
        prec_xgb = precision_score(y_test, y_pred_xgb)
        rec_xgb = recall_score(y_test, y_pred_xgb)
        f1_xgb = f1_score(y_test, y_pred_xgb)
        roc_xgb = roc_auc_score(y_test, y_prob_xgb)
        
        cv_scores_xgb = cross_val_score(xgb_model, X_train_scaled, y_train, cv=cv, scoring='accuracy')
        
        results['XGBoost'] = {
            'accuracy': acc_xgb, 'precision': prec_xgb, 'recall': rec_xgb,
            'f1_score': f1_xgb, 'roc_auc': roc_xgb, 'train_time': xgb_time,
            'cv_accuracy': cv_scores_xgb.mean(), 'cv_std': cv_scores_xgb.std()
        }
        
        print(f"  Accuracy:    {acc_xgb:.4f} ({acc_xgb*100:.2f}%)")
        print(f"  Precision:   {prec_xgb:.4f}")
        print(f"  Recall:      {rec_xgb:.4f}")
        print(f"  F1-Score:    {f1_xgb:.4f}")
        print(f"  ROC-AUC:     {roc_xgb:.4f}")
        print(f"  CV Accuracy: {cv_scores_xgb.mean():.4f} (+/- {cv_scores_xgb.std()*2:.4f})")
        
        # Ensemble
        print("\n--- Ensemble (RF + XGBoost) ---")
        
        ensemble = VotingClassifier(
            estimators=[('rf', rf), ('xgb', xgb_model)],
            voting='soft', n_jobs=-1
        )
        
        start = time.time()
        ensemble.fit(X_train_scaled, y_train)
        ens_time = time.time() - start
        
        y_pred_ens = ensemble.predict(X_test_scaled)
        y_prob_ens = ensemble.predict_proba(X_test_scaled)[:, 1]
        
        acc_ens = accuracy_score(y_test, y_pred_ens)
        prec_ens = precision_score(y_test, y_pred_ens)
        rec_ens = recall_score(y_test, y_pred_ens)
        f1_ens = f1_score(y_test, y_pred_ens)
        roc_ens = roc_auc_score(y_test, y_prob_ens)
        
        results['Ensemble'] = {
            'accuracy': acc_ens, 'precision': prec_ens, 'recall': rec_ens,
            'f1_score': f1_ens, 'roc_auc': roc_ens, 'train_time': ens_time
        }
        
        print(f"  Accuracy:    {acc_ens:.4f} ({acc_ens*100:.2f}%)")
        print(f"  Precision:   {prec_ens:.4f}")
        print(f"  Recall:      {rec_ens:.4f}")
        print(f"  F1-Score:    {f1_ens:.4f}")
        print(f"  ROC-AUC:     {roc_ens:.4f}")
        
        best_model = ensemble
    else:
        best_model = rf
    
    # Save models
    print("\n--- Saving Models ---")
    
    joblib.dump(best_model, os.path.join(MODEL_DIR, 'url_phishing_model.joblib'))
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'url_scaler.joblib'))
    print(f"✓ Saved model and scaler")
    
    # Feature importance
    if hasattr(best_model, 'feature_importances_'):
        importances = best_model.feature_importances_
        imp_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Feature Importances:")
        for _, row in imp_df.head(10).iterrows():
            print(f"  {row['feature']}: {row['importance']:.4f}")
        
        imp_df.to_csv(os.path.join(DATASET_DIR, 'feature_importance.csv'), index=False)
    
    return results


def main():
    print("\n" + "="*70)
    print("REALISTIC PHISHING DETECTION MODEL TRAINING")
    print("="*70)
    
    # Generate realistic data
    urls, labels = generate_realistic_urls(n_samples=20000, noise_level=0.15)
    
    # Extract features
    df = extract_features(urls, labels)
    
    # Add feature noise for more realistic training
    df_noisy = add_feature_noise(df, noise_prob=0.05)
    
    # Balance dataset
    phishing = df_noisy[df_noisy['label'] == 1]
    legitimate = df_noisy[df_noisy['label'] == 0]
    
    min_count = min(len(phishing), len(legitimate))
    phishing = phishing.sample(n=min_count, random_state=42)
    legitimate = legitimate.sample(n=min_count, random_state=42)
    
    df_balanced = pd.concat([phishing, legitimate], ignore_index=True)
    df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\nDataset: {len(df_balanced)} samples (balanced)")
    print(f"  Phishing: {sum(df_balanced['label']==1)}")
    print(f"  Legitimate: {sum(df_balanced['label']==0)}")
    
    # Save dataset
    df_balanced.to_csv(os.path.join(DATASET_DIR, 'realistic_training_data.csv'), index=False)
    print(f"Saved to: {DATASET_DIR}/realistic_training_data.csv")
    
