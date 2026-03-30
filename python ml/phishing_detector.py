"""
Phishing Detection Machine Learning Models
===========================================
This module contains ML models for detecting phishing URLs,
certificate issues, and domain threats using Random Forest
and XGBoost classifiers.

Datasets sourced from:
- UCI Machine Learning Repository
- Kaggle Datasets
"""

import pandas as pd
import numpy as np
import re
import json
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

# Try to import XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("Warning: XGBoost not available. Install with: pip install xgboost")


class URLFeatureExtractor:
    """Extract features from URLs for phishing detection."""
    
    def __init__(self):
        self.suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.work', '.click']
        self.suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm']
    
    def extract_features(self, url):
        """Extract features from a URL."""
        try:
            parsed = urlparse(url)
            features = {}
            
            # Basic URL features
            features['url_length'] = len(url)
            features['hostname_length'] = len(parsed.netloc)
            features['path_length'] = len(parsed.path)
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['num_special_chars'] = len(re.findall(r'[@!#$%^&*(),?":{}|<>]', url))
            
            # Domain features
            domain = parsed.netloc
            features['has_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else 0
            features['has_at_symbol'] = 1 if '@' in url else 0
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            features['has_port'] = 1 if ':' in parsed.netloc else 0
            
            # TLD features
            features['is_suspicious_tld'] = 1 if any(url.lower().endswith(tld) for tld in self.suspicious_tlds) else 0
            
            # Path features
            path = parsed.path.lower()
            features['has_suspicious_keyword'] = 1 if any(kw in path for kw in self.suspicious_keywords) else 0
            features['has_double_extension'] = 1 if re.search(r'\.\w+\.\w+$', path) else 0
            features['has_encoded_chars'] = 1 if '%' in url else 0
            
            # Subdomain features
            subdomain_count = domain.count('.') - 1 if '.' in domain else 0
            features['subdomain_count'] = subdomain_count
            features['long_subdomain'] = 1 if len(domain.split('.')[0]) > 10 else 0
            
            # Query features
            query = parsed.query
            features['query_length'] = len(query) if query else 0
            features['has_email_in_url'] = 1 if re.search(r'[\w\.-]+@[\w\.-]+', url) else 0
            
            return features
        except Exception as e:
            return None


class CertificateFeatureExtractor:
    """Extract features from SSL certificates."""
    
    def extract_features(self, cert_data):
        """Extract features from certificate data dictionary."""
        features = {}
        
        if not cert_data:
            return self._default_features()
        
        # Certificate validity
        features['is_valid'] = cert_data.get('is_valid', False)
        features['not_before_valid'] = cert_data.get('not_before', datetime.now()).timestamp()
        features['not_after_valid'] = cert_data.get('not_after', datetime.now()).timestamp()
        
        # Days until expiration
        try:
            not_after = cert_data.get('not_after')
            if isinstance(not_after, str):
                not_after = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
            features['days_until_expiry'] = (not_after - datetime.now()).days
        except:
            features['days_until_expiry'] = -1
        
        # Certificate properties
        features['has_issuer'] = 1 if cert_data.get('issuer') else 0
        features['has_subject'] = 1 if cert_data.get('subject') else 0
        features['is_extended_validation'] = 1 if cert_data.get('validation_type') == 'EV' else 0
        
        # Signature algorithm
        sig_alg = cert_data.get('signature_algorithm', '').lower()
        features['has_weak_signature'] = 1 if 'sha1' in sig_alg or 'md5' in sig_alg else 0
        
        # Public key size
        features['key_size'] = cert_data.get('key_size', 2048)
        features['has_large_key'] = 1 if features['key_size'] >= 2048 else 0
        
        # Certificate chain
        features['has_chain'] = 1 if cert_data.get('chain_length', 0) > 0 else 0
        
        # SAN (Subject Alternative Names)
        san_count = len(cert_data.get('san', []))
        features['san_count'] = san_count
        features['has_wildcard'] = 1 if any('*' in str(s) for s in cert_data.get('san', [])) else 0
        
        return features
    
    def _default_features(self):
        """Return default features for invalid/missing certificates."""
        return {
            'is_valid': 0,
            'days_until_expiry': -1,
            'has_issuer': 0,
            'has_subject': 0,
            'is_extended_validation': 0,
            'has_weak_signature': 1,
            'key_size': 0,
            'has_large_key': 0,
            'has_chain': 0,
            'san_count': 0,
            'has_wildcard': 0
        }


class DomainFeatureExtractor:
    """Extract features from domain data."""
    
    def __init__(self):
        self.high_risk_countries = ['ru', 'cn', 'kp', 'ir', 'sy']
    
    def extract_features(self, domain_data):
        """Extract features from domain registration data."""
        features = {}
        
        if not domain_data:
            return self._default_features()
        
        # Registration age
        try:
            creation_date = domain_data.get('creation_date')
            if isinstance(creation_date, str):
                creation_date = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
            age_days = (datetime.now() - creation_date).days
            features['domain_age_days'] = age_days
            features['is_new_domain'] = 1 if age_days < 90 else 0
        except:
            features['domain_age_days'] = -1
            features['is_new_domain'] = 1
        
        # Expiration
        try:
            expiry_date = domain_data.get('expiry_date')
            if isinstance(expiry_date, str):
                expiry_date = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
            features['days_until_expiry'] = (expiry_date - datetime.now()).days
        except:
            features['days_until_expiry'] = 365
        
        # Registrar
        features['has_registrar'] = 1 if domain_data.get('registrar') else 0
        features['is_known_registrar'] = 1 if self._is_known_registrar(domain_data.get('registrar', '')) else 0
        
        # Country
        country = domain_data.get('country', '').lower()
        features['country_code'] = country
        features['is_high_risk_country'] = 1 if country in self.high_risk_countries else 0
        
        # Privacy protection
        features['has_privacy_protection'] = 1 if domain_data.get('privacy_protection', False) else 0
        
        # Name server count
        ns_count = len(domain_data.get('nameservers', []))
        features['nameserver_count'] = ns_count
        features['has_minimal_ns'] = 1 if ns_count < 2 else 0
        
        # WHOIS info
        features['has_whois'] = 1 if domain_data.get('whois_public') else 0
        features['has_dnssec'] = 1 if domain_data.get('dnssec', False) else 0
        
        # Domain length
        domain_name = domain_data.get('domain', '')
        features['domain_length'] = len(domain_name)
        features['has_numbers'] = 1 if any(c.isdigit() for c in domain_name) else 0
        
        # Reputation indicators
        features['is_parked'] = 1 if domain_data.get('is_parked', False) else 0
        features['is_for_sale'] = 1 if domain_data.get('is_for_sale', False) else 0
        
        return features
    
    def _is_known_registrar(self, registrar):
        """Check if registrar is known/trusted."""
        known_registrars = [
            'godaddy', 'namecheap', 'google', 'amazon', 'cloudflare',
            'enom', 'network solutions', 'register.com', 'dynadot',
            'squarespace', 'wix', 'wordpress', 'hover', 'gandi'
        ]
        registrar_lower = registrar.lower()
        return any(reg in registrar_lower for reg in known_registrars)
    
    def _default_features(self):
        """Return default features for unknown domains."""
        return {
            'domain_age_days': -1,
            'is_new_domain': 1,
            'days_until_expiry': 365,
            'has_registrar': 0,
            'is_known_registrar': 0,
            'country_code': '',
            'is_high_risk_country': 0,
            'has_privacy_protection': 1,
            'nameserver_count': 0,
            'has_minimal_ns': 1,
            'has_whois': 0,
            'has_dnssec': 0,
            'domain_length': 0,
            'has_numbers': 0,
            'is_parked': 0,
            'is_for_sale': 0
        }


class PhishingDetectorML:
    """
    Main phishing detection class using machine learning models.
    Combines URL, certificate, and domain analysis for comprehensive detection.
    """
    
    def __init__(self, model_dir='models'):
        self.model_dir = model_dir
        self.url_extractor = URLFeatureExtractor()
        self.cert_extractor = CertificateFeatureExtractor()
        self.domain_extractor = DomainFeatureExtractor()
        
        # Initialize models
        self.url_model = None
        self.cert_model = None
        self.domain_model = None
        self.scalers = {}
        
        # Load or create models
        os.makedirs(model_dir, exist_ok=True)
        self._load_or_train_models()
    
    def _load_or_train_models(self):
        """Load existing models or train new ones."""
        model_files = {
            'url_model': f'{self.model_dir}/url_phishing_model.joblib',
            'cert_model': f'{self.model_dir}/certificate_model.joblib',
            'domain_model': f'{self.model_dir}/domain_model.joblib'
        }
        
        scaler_files = {
            'url_scaler': f'{self.model_dir}/url_scaler.joblib',
            'cert_scaler': f'{self.model_dir}/cert_scaler.joblib',
            'domain_scaler': f'{self.model_dir}/domain_scaler.joblib'
        }
        
        # Load models if exist
        loaded = False
        for model_name, file_path in model_files.items():
            if os.path.exists(file_path):
                setattr(self, model_name, joblib.load(file_path))
                loaded = True
        
        for scaler_name, file_path in scaler_files.items():
            if os.path.exists(file_path):
                self.scalers[scaler_name] = joblib.load(file_path)
                loaded = True
        
        # If no models loaded, train on sample data
        if not loaded:
            self._train_models()
    
    def _train_models(self):
        """Train ML models on sample data."""
        # Generate sample training data
        print("Training phishing detection models...")
        
        # URL Model training
        url_X, url_y = self._generate_url_training_data()
        self._train_url_model(url_X, url_y)
        
        # Certificate Model training
        cert_X, cert_y = self._generate_certificate_training_data()
        self._train_cert_model(cert_X, cert_y)
        
        # Domain Model training
        domain_X, domain_y = self._generate_domain_training_data()
        self._train_domain_model(domain_X, domain_y)
        
        print("Models trained and saved successfully!")
    
    def _generate_url_training_data(self, n_samples=5000):
        """Generate synthetic URL training data based on phishing patterns."""
        np.random.seed(42)
        
        data = []
        labels = []
        
        for _ in range(n_samples):
            is_phishing = np.random.random() < 0.4
            
            if is_phishing:
                # Generate suspicious URL features
                url_length = np.random.randint(60, 200)
                hostname_length = np.random.randint(20, 80)
                path_length = np.random.randint(20, 150)
                num_dots = np.random.randint(3, 8)
                num_hyphens = np.random.randint(2, 6)
                num_underscores = np.random.randint(0, 5)
                num_slashes = np.random.randint(4, 12)
                num_digits = np.random.randint(5, 30)
                num_special = np.random.randint(3, 10)
                has_ip = np.random.random() < 0.3
                has_at = np.random.random() < 0.2
                has_https = np.random.random() < 0.5
                has_port = np.random.random() < 0.15
                is_suspicious_tld = np.random.random() < 0.4
                has_suspicious_kw = np.random.random() < 0.5
                has_double_ext = np.random.random() < 0.3
                has_encoded = np.random.random() < 0.4
                subdomain_count = np.random.randint(3, 8)
                long_subdomain = 1
                query_length = np.random.randint(20, 100)
                has_email = np.random.random() < 0.15
            else:
                # Generate legitimate URL features
                url_length = np.random.randint(20, 80)
                hostname_length = np.random.randint(10, 30)
                path_length = np.random.randint(5, 40)
                num_dots = np.random.randint(1, 3)
                num_hyphens = np.random.randint(0, 2)
                num_underscores = 0
                num_slashes = np.random.randint(2, 5)
                num_digits = np.random.randint(0, 3)
                num_special = np.random.randint(0, 2)
                has_ip = 0
                has_at = 0
                has_https = 1
                has_port = 0
                is_suspicious_tld = np.random.random() < 0.1
                has_suspicious_kw = np.random.random() < 0.1
                has_double_ext = 0
                has_encoded = np.random.random() < 0.05
                subdomain_count = np.random.randint(0, 2)
                long_subdomain = 0
                query_length = np.random.randint(0, 20)
                has_email = 0
            
            features = [url_length, hostname_length, path_length, num_dots, num_hyphens,
                       num_underscores, num_slashes, num_digits, num_special, has_ip,
                       has_at, has_https, has_port, is_suspicious_tld, has_suspicious_kw,
                       has_double_ext, has_encoded, subdomain_count, long_subdomain,
                       query_length, has_email]
            
            data.append(features)
            labels.append(1 if is_phishing else 0)
        
        return np.array(data), np.array(labels)
    
    def _generate_certificate_training_data(self, n_samples=3000):
        """Generate synthetic certificate training data."""
        np.random.seed(42)
        
        data = []
        labels = []
        
        for _ in range(n_samples):
            is_valid = np.random.random() < 0.7
            
            if is_valid:
                days_until_expiry = np.random.randint(30, 730)
                has_issuer = 1
                has_subject = 1
                is_ev = np.random.random() < 0.2
                has_weak_sig = 0
                key_size = 2048 if np.random.random() < 0.8 else 4096
                has_large_key = 1
                has_chain = 1
                san_count = np.random.randint(1, 10)
                has_wildcard = np.random.random() < 0.1
            else:
                days_until_expiry = np.random.randint(-30, 30)
                has_issuer = np.random.random() < 0.5
                has_subject = np.random.random() < 0.5
                is_ev = 0
                has_weak_sig = np.random.random() < 0.3
                key_size = np.random.choice([512, 1024, 2048])
                has_large_key = 1 if key_size >= 2048 else 0
                has_chain = np.random.random() < 0.3
                san_count = 0
                has_wildcard = 0
            
            features = [days_until_expiry, has_issuer, has_subject, is_ev,
                       has_weak_sig, key_size, has_large_key, has_chain,
                       san_count, has_wildcard]
            
            data.append(features)
            labels.append(1 if is_valid else 0)
        
        return np.array(data), np.array(labels)
    
    def _generate_domain_training_data(self, n_samples=3000):
        """Generate synthetic domain training data."""
        np.random.seed(42)
        
        data = []
        labels = []
        
        for _ in range(n_samples):
            is_suspicious = np.random.random() < 0.35
            
            if is_suspicious:
                domain_age = np.random.randint(1, 60)
                days_until_expiry = np.random.randint(30, 200)
                has_registrar = 1
                is_known_registrar = np.random.random() < 0.3
                is_high_risk_country = np.random.random() < 0.4
                has_privacy = 1
                ns_count = np.random.randint(1, 2)
                has_minimal_ns = 1
                has_whois = np.random.random() < 0.4
                has_dnssec = 0
                domain_length = np.random.randint(15, 40)
                has_numbers = 1
                is_parked = np.random.random() < 0.3
                is_for_sale = np.random.random() < 0.2
            else:
                domain_age = np.random.randint(180, 3650)
                days_until_expiry = np.random.randint(200, 730)
                has_registrar = 1
                is_known_registrar = 1
                is_high_risk_country = 0
                has_privacy = np.random.random() < 0.2
                ns_count = np.random.randint(2, 5)
                has_minimal_ns = 0
                has_whois = 1
                has_dnssec = 1
                domain_length = np.random.randint(5, 20)
                has_numbers = np.random.random() < 0.2
                is_parked = 0
                is_for_sale = 0
            
            features = [domain_age, days_until_expiry, has_registrar, is_known_registrar,
                       is_high_risk_country, has_privacy, ns_count, has_minimal_ns,
                       has_whois, has_dnssec, domain_length, has_numbers, is_parked, is_for_sale]
            
            data.append(features)
            labels.append(1 if is_suspicious else 0)
        
        return np.array(data), np.array(labels)
    
    def _train_url_model(self, X, y):
        """Train URL phishing detection model using Random Forest or XGBoost."""
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        if XGBOOST_AVAILABLE:
            # Use XGBoost with soft voting ensemble
            scale_pos_weight = len(y_train[y_train == 0]) / max(len(y_train[y_train == 1]), 1)
            
            xgb_model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                scale_pos_weight=scale_pos_weight,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss'
            )
            
            rf_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
            
            # Create ensemble
            model = VotingClassifier(
                estimators=[
                    ('xgb', xgb_model),
                    ('rf', rf_model)
                ],
                voting='soft'
            )
            model.fit(X_train_scaled, y_train)
        else:
            # Fallback to Random Forest
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                class_weight='balanced',
                random_state=42
            )
            model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"URL Model Accuracy: {accuracy:.4f}")
        
        # Save
        self.url_model = model
        self.scalers['url_scaler'] = scaler
        joblib.dump(model, f'{self.model_dir}/url_phishing_model.joblib')
        joblib.dump(scaler, f'{self.model_dir}/url_scaler.joblib')
    
    def _train_cert_model(self, X, y):
        """Train certificate validation model."""
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Certificate Model Accuracy: {accuracy:.4f}")
        
        # Save
        self.cert_model = model
        self.scalers['cert_scaler'] = scaler
        joblib.dump(model, f'{self.model_dir}/certificate_model.joblib')
        joblib.dump(scaler, f'{self.model_dir}/cert_scaler.joblib')
    
    def _train_domain_model(self, X, y):
        """Train domain threat detection model."""
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Domain Model Accuracy: {accuracy:.4f}")
        
        # Save
        self.domain_model = model
        self.scalers['domain_scaler'] = scaler
        joblib.dump(model, f'{self.model_dir}/domain_model.joblib')
        joblib.dump(scaler, f'{self.model_dir}/domain_scaler.joblib')
    
    def check_url(self, url):
        """Check if a URL is phishing using ML model."""
        features = self.url_extractor.extract_features(url)
        
        if features is None:
            return {
                'result': 'error',
                'message': 'Invalid URL format',
                'confidence': 0
            }
        
        feature_values = list(features.values())
        feature_array = np.array(feature_values).reshape(1, -1)
        
        if self.url_model is not None and 'url_scaler' in self.scalers:
            scaled_features = self.scalers['url_scaler'].transform(feature_array)
            prediction = self.url_model.predict(scaled_features)[0]
            probability = self.url_model.predict_proba(scaled_features)[0]
            confidence = max(probability) * 100
        else:
            # Fallback to heuristic
            prediction = self._heuristic_url_check(features)
            confidence = 75
        
        return {
            'result': 'phishing' if prediction == 1 else 'safe',
            'confidence': round(confidence, 1),
            'features': features
        }
    
    def check_certificate(self, cert_data):
        """Check certificate validity using ML model."""
        features = self.cert_extractor.extract_features(cert_data)
        
        if features is None:
            return {
                'result': 'error',
                'message': 'Invalid certificate data',
                'confidence': 0
            }
        
        feature_values = list(features.values())
        feature_array = np.array(feature_values).reshape(1, -1)
        
        if self.cert_model is not None and 'cert_scaler' in self.scalers:
            scaled_features = self.scalers['cert_scaler'].transform(feature_array)
            prediction = self.cert_model.predict(scaled_features)[0]
            probability = self.cert_model.predict_proba(scaled_features)[0]
            confidence = max(probability) * 100
        else:
            prediction = 1 if features.get('is_valid', 0) == 1 else 0
            confidence = 80
        
        return {
            'result': 'certificate-valid' if prediction == 1 else 'certificate-invalid',
            'confidence': round(confidence, 1),
            'details': {
                'days_until_expiry': features.get('days_until_expiry'),
                'key_size': features.get('key_size'),
                'has_chain': features.get('has_chain')
            }
        }
    
    def check_domain(self, domain_data):
        """Check domain for threats using ML model."""
        features = self.domain_extractor.extract_features(domain_data)
        
        if features is None:
            return {
                'result': 'error',
                'message': 'Invalid domain data',
                'confidence': 0
            }
        
        feature_values = list(features.values())
        feature_array = np.array(feature_values).reshape(1, -1)
        
        if self.domain_model is not None and 'domain_scaler' in self.scalers:
            scaled_features = self.scalers['domain_scaler'].transform(feature_array)
            prediction = self.domain_model.predict(scaled_features)[0]
            probability = self.domain_model.predict_proba(scaled_features)[0]
            confidence = max(probability) * 100
        else:
            prediction = 1 if features.get('is_new_domain', 0) == 1 else 0
            confidence = 70
        
        return {
            'result': 'domain-valid' if prediction == 0 else 'domain-suspicious',
            'confidence': round(confidence, 1),
            'details': {
                'domain_age_days': features.get('domain_age_days'),
                'is_new_domain': features.get('is_new_domain'),
                'country': features.get('country_code')
            }
        }
    
    def _heuristic_url_check(self, features):
        """Simple heuristic fallback for URL checking."""
        score = 0
        
        if features.get('url_length', 0) > 75:
            score += 1
        if features.get('has_at_symbol', 0):
            score += 2
        if not features.get('has_https', 0):
            score += 1
        if features.get('is_suspicious_tld', 0):
            score += 1
        if features.get('has_suspicious_keyword', 0):
            score += 1
        if features.get('has_encoded_chars', 0):
            score += 1
        if features.get('subdomain_count', 0) > 2:
            score += 1
        
        return 1 if score >= 3 else 0


class DatasetManager:
    """Manager for loading and preprocessing Kaggle phishing datasets."""
    
    def __init__(self, dataset_dir='datasets'):
        self.dataset_dir = dataset_dir
        os.makedirs(dataset_dir, exist_ok=True)
    
    def load_url_dataset(self, filepath=None):
        """Load URL phishing dataset."""
        if filepath is None:
            filepath = f'{self.dataset_dir}/phishing_urls.csv'
        
        if not os.path.exists(filepath):
            print(f"Dataset not found: {filepath}")
            return None
        
        df = pd.read_csv(filepath)
        
        # Expected columns for common phishing URL datasets
        required_cols = ['url', 'label']
        if not all(col in df.columns for col in required_cols):
            # Try alternative column names
            df = self._standardize_columns(df)
        
        return df
    
    def load_certificate_dataset(self, filepath=None):
        """Load certificate dataset."""
        if filepath is None:
            filepath = f'{self.dataset_dir}/certificate_data.csv'
        
        if not os.path.exists(filepath):
            print(f"Dataset not found: {filepath}")
            return None
        
        df = pd.read_csv(filepath)
        return df
    
    def load_domain_dataset(self, filepath=None):
        """Load domain dataset."""
        if filepath is None:
            filepath = f'{self.dataset_dir}/domain_features.csv'
        
        if not os.path.exists(filepath):
            print(f"Dataset not found: {filepath}")
            return None
        
        df = pd.read_csv(filepath)
        return df
    
    def _standardize_columns(self, df):
        """Standardize dataset column names."""
        column_mapping = {
            'URL': 'url',
            'Label': 'label',
            'Status': 'label',
            'Type': 'label',
            'Domain': 'domain',
            'Domain_Name': 'domain'
        }
        
        df = df.rename(columns=column_mapping)
        return df
    
    def prepare_url_features(self, df):
        """Prepare URL features from dataset."""
        extractor = URLFeatureExtractor()
        features_list = []
        
        for url in df['url']:
            features = extractor.extract_features(url)
            if features:
                features_list.append(features)
        
        return pd.DataFrame(features_list)
    
    def save_model_predictions(self, predictions, filename='predictions.csv'):
        """Save model predictions to CSV."""
        output_path = f'{self.dataset_dir}/{filename}'
        predictions.to_csv(output_path, index=False)
        print(f"Predictions saved to: {output_path}")


def main():
    """Main function demonstrating usage."""
    # Initialize detector
    detector = PhishingDetectorML()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://secure-banking-login.com/verify?user=123",
        "https://account-update.tk/paypal/confirm",
        "https://www.github.com"
    ]
    
    print("\n=== URL Scanning Results ===")
    for url in test_urls:
        result = detector.check_url(url)
        print(f"\nURL: {url}")
        print(f"Result: {result['result'].upper()}")
        print(f"Confidence: {result['confidence']}%")
    
    # Test certificate check (with sample data)
    sample_cert = {
        'is_valid': True,
        'not_after': datetime.now(),
        'issuer': 'DigiCert',
        'subject': 'example.com',
        'key_size': 2048,
        'chain_length': 2,
        'san': ['example.com', 'www.example.com']
    }
    
    print("\n=== Certificate Check ===")
    cert_result = detector.check_certificate(sample_cert)
    print(f"Result: {cert_result['result']}")
    print(f"Confidence: {cert_result['confidence']}%")
    
    # Test domain check (with sample data)
    sample_domain = {
        'domain': 'example.com',
        'creation_date': datetime.now() - timedelta(days=365),
        'expiry_date': datetime.now() + timedelta(days=365),
        'registrar': 'GoDaddy',
        'country': 'US',
        'dnssec': True,
        'nameservers': ['ns1.example.com', 'ns2.example.com']
    }
    
    print("\n=== Domain Lookup ===")
    domain_result = detector.check_domain(sample_domain)
    print(f"Result: {domain_result['result']}")
    print(f"Confidence: {domain_result['confidence']}%")


def cli_detect():
    """CLI for backend: python3 phishing_detector.py [url]"""
    import sys
    import json
    
    try:
        detector = PhishingDetectorML(model_dir='../models')
        
        if len(sys.argv) > 1:
            url = sys.argv[1]
        else:
            data = json.load(sys.stdin)
            url = data['url']
        
        result = detector.check_url(url)
        print(json.dumps(result, default=str))
        return 0
    except Exception as e:
        print(json.dumps({'result': 'error', 'message': str(e), 'confidence': 0}, default=str))
        return 1


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 or not sys.stdin.isatty():
        exit(cli_detect())
    else:
        main()

