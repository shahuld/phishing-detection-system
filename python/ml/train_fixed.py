import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
import joblib
import os
import logging
import re
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_url_features(url):
    """Extract 15 features matching phishing_detector_fixed.py"""
    parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    netloc = parsed.netloc.lower()
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = parsed.scheme

    features = np.zeros(15)

    # Original 11 features
    features[0] = len(url)
    features[1] = len(netloc)
    features[2] = len(path)
    features[3] = netloc.count('.')
    features[4] = netloc.count('-')
    features[5] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', netloc.split(':')[0]) else 0
    features[6] = url.count('@')
    suspicious_tld = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.site', '.online']
    features[7] = 1 if any(tld in netloc for tld in suspicious_tld) else 0
    features[8] = len([d for d in netloc.split('.') if d])
    features[9] = len(query)
    features[10] = 1 if '@' in url and url.find('@') < url.find(netloc) else 0

    # NEW: Advanced phishing features (11-14)
    features[11] = len(re.findall(r'%[0-9a-f]{2}', url)) / 10  # Percent encoding
    features[12] = len(re.findall(r'\\\\|0x[0-9a-f]{2}', url)) / 5  # Hex/escapes
    features[13] = 1 if re.search(r'login|bank|paypal|amazon|update|verify', path+query, re.I) else 0
    features[14] = 1 if parsed.port and parsed.port not in [80, 443] else 0

    return features

def extract_domain_features(domain):
    """Extract 10 features matching phishing_detector_fixed.py domain detector"""
    features = np.zeros(10)

    if not domain:
        return features

    domain = domain.lower()
    tld = domain.split('.')[-1] if '.' in domain else ''

    # Feature 0: Domain age (normalized 0-1, default mature)
    features[0] = 0.8  # Assume mature

    # Feature 1: Is new domain (< 90 days)
    features[1] = 0

    # Feature 2: Not known registrar
    features[2] = 0  # Assume known

    # Feature 3: Suspicious TLD
    suspicious_tlds = ['.sbs', '.ru', '.top', '.xyz', '.site', '.tk', '.ml', '.ga', '.cf', '.gq']
    features[3] = 1 if tld in suspicious_tlds else 0

    # Feature 4: Subdomain count
    features[4] = max(0, domain.count('.') - 2) / 5

    # Feature 5: IDN homograph risk
    features[5] = 1 if 'xn--' in domain else 0

    # Feature 6: Hyphens in domain
    features[6] = domain.count('-') / 10

    # Feature 7: Digits count
    features[7] = sum(c.isdigit() for c in domain) / 10

    # Feature 8: Total length
    features[8] = len(domain) / 50

    # Feature 9: Has suspicious words
    suspicious_words = ['login', 'bank', 'verify', 'update', 'secure', 'account']
    features[9] = 1 if any(w in domain for w in suspicious_words) else 0

    return features

def extract_cert_features():
    """Extract 12 features matching phishing_detector_fixed.py certificate detector"""
    # For training, we generate synthetic cert features
    features = np.zeros(12)

    # Return features (will be randomized for training data)
    return features

# ==================== TRAIN URL MODEL ====================
logger.info("=" * 50)
logger.info("Training URL model (15 features)...")
logger.info("=" * 50)

MODEL_DIR = '/Users/shahulhameed/phishing/backend/models'
os.makedirs(MODEL_DIR, exist_ok=True)
dataset_path = '../../datasets/combined_real_data.csv'

if os.path.exists(dataset_path):
    df = pd.read_csv(dataset_path)
    if 'url' in df.columns:
        logger.info(f'Extracting 15 features from {len(df)} URLs...')
        X_list = []
        for url in df['url']:
            try:
                features = extract_url_features(str(url))
                X_list.append(features)
            except:
                X_list.append(np.zeros(15))
        X = np.array(X_list)
        y = df['label'].values
    else:
        # Use only first 15 columns
        label_col = 'label'
        feature_cols = [col for col in df.columns if col != label_col][:15]
        X = df[feature_cols].fillna(0).values
        y = df[label_col].values
        logger.info(f'Using first 15 features: {X.shape}')
else:
    # Generate synthetic data
    logger.info('Generating synthetic URL dataset with 15 features...')
    np.random.seed(42)
    n_samples = 5000

    safe_urls = []
    for _ in range(n_samples // 2):
        domain = f"www.{['google','github','stackoverflow','microsoft','apple'][np.random.randint(0,5)]}.com"
        safe_urls.append(f"https://{domain}/{'/'.join(['page','article','blog'][np.random.randint(0,3)])}")

    phish_urls = []
    for _ in range(n_samples // 2):
        tld = ['.tk', '.ml', '.xyz', '.top', '.online'][np.random.randint(0,5)]
        keywords = ['login', 'bank', 'paypal', 'verify', 'update']
        kw = keywords[np.random.randint(0, len(keywords))]
        domain = f"secure-{kw}-{np.random.randint(1000,9999)}{tld}"
        phish_urls.append(f"http://{domain}/{kw}-account")

    all_urls = safe_urls + phish_urls
    labels = [0] * (n_samples // 2) + [1] * (n_samples // 2)

    X = np.array([extract_url_features(url) for url in all_urls])
    y = np.array(labels)

# Train URL model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler_url = StandardScaler()
X_train_scaled = scaler_url.fit_transform(X_train)
X_test_scaled = scaler_url.transform(X_test)

rf_url = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
rf_url.fit(X_train_scaled, y_train)

y_pred = rf_url.predict(X_test_scaled)
acc = accuracy_score(y_test, y_pred)
logger.info(f'URL Model Accuracy: {acc:.4f}')

joblib.dump(rf_url, f'{MODEL_DIR}/url_phishing_model.joblib')
joblib.dump(scaler_url, f'{MODEL_DIR}/url_scaler.joblib')
logger.info('URL model saved (15 features)')

# ==================== TRAIN DOMAIN MODEL ====================
logger.info("=" * 50)
logger.info("Training DOMAIN model (10 features)...")
logger.info("=" * 50)

# Generate synthetic domain data
np.random.seed(42)
n_domains = 5000

safe_domains = [f"{['google','github','microsoft','apple','amazon'][np.random.randint(0,5)]}.com" for _ in range(n_domains // 2)]
phish_domains = [f"secure-{['login','bank','paypal','verify'][np.random.randint(0,4)]}-{np.random.randint(100,999)}.xyz" for _ in range(n_domains // 2)]

all_domains = safe_domains + phish_domains
domain_labels = [0] * (n_domains // 2) + [1] * (n_domains // 2)

X_domain = np.array([extract_domain_features(d) for d in all_domains])
y_domain = np.array(domain_labels)

X_train_d, X_test_d, y_train_d, y_test_d = train_test_split(X_domain, y_domain, test_size=0.2, random_state=42, stratify=y_domain)

scaler_domain = StandardScaler()
X_train_d_scaled = scaler_domain.fit_transform(X_train_d)
X_test_d_scaled = scaler_domain.transform(X_test_d)

rf_domain = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
rf_domain.fit(X_train_d_scaled, y_train_d)

acc_d = accuracy_score(y_test_d, rf_domain.predict(X_test_d_scaled))
logger.info(f'Domain Model Accuracy: {acc_d:.4f}')

joblib.dump(rf_domain, f'{MODEL_DIR}/domain_phishing_model.joblib')
joblib.dump(scaler_domain, f'{MODEL_DIR}/domain_scaler.joblib')
logger.info('Domain model saved (10 features)')

# ==================== TRAIN CERTIFICATE MODEL ====================
logger.info("=" * 50)
logger.info("Training CERTIFICATE model (12 features)...")
logger.info("=" * 50)

# Generate synthetic certificate data
np.random.seed(42)
n_certs = 5000

# Safe certs: good key size, valid expiry, known issuer
# Phishing certs: weak key, short expiry, free issuer like Let's Encrypt
X_cert = []
for _ in range(n_certs):
    if np.random.randint(0, 2) == 0:  # Safe
        features = [
            np.random.uniform(0.7, 1.0),  # Days until expiry
            np.random.randint(0, 1),     # Weak key
            np.random.uniform(0, 0.2),    # SAN count
            np.random.randint(0, 1),      # Wildcard
            np.random.randint(0, 1),      # Weak signature
            np.random.randint(0, 1),      # Old version
            0,                             # Hostname match
            0,                             # Free issuer (Let's Encrypt)
            np.random.uniform(0, 0.2),    # SAN ratio
            0,                             # Expired
            1,                             # Has chain
            np.random.uniform(0, 0.3),  # Key size ratio
        ]
    else:  # Phishing
        features = [
            np.random.uniform(0, 0.3),   # Days until expiry (short)
            np.random.randint(0, 1),       # Weak key
            np.random.uniform(0.3, 0.8),     # Many SANs
            np.random.randint(0, 1),        # Wildcard
            np.random.randint(0, 1),       # Weak signature
            np.random.randint(0, 1),       # Old version
            1,                              # Hostname mismatch
            1,                              # Free issuer
            np.random.uniform(0.3, 0.8),    # SAN ratio
            np.random.randint(0, 1),         # Near expiry
            np.random.randint(0, 1),        # No chain
            np.random.uniform(0.3, 0.7),    # Key size ratio
        ]
    X_cert.append(features)

X_cert = np.array(X_cert)
y_cert = np.array([0] * (n_certs // 2) + [1] * (n_certs // 2))

X_train_c, X_test_c, y_train_c, y_test_c = train_test_split(X_cert, y_cert, test_size=0.2, random_state=42, stratify=y_cert)

scaler_cert = StandardScaler()
X_train_c_scaled = scaler_cert.fit_transform(X_train_c)
X_test_c_scaled = scaler_cert.transform(X_test_c)

rf_cert = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
rf_cert.fit(X_train_c_scaled, y_train_c)

acc_c = accuracy_score(y_test_c, rf_cert.predict(X_test_c_scaled))
logger.info(f'Certificate Model Accuracy: {acc_c:.4f}')

joblib.dump(rf_cert, f'{MODEL_DIR}/certificate_phishing_model.joblib')
joblib.dump(scaler_cert, f'{MODEL_DIR}/certificate_scaler.joblib')
logger.info('Certificate model saved (12 features)')

logger.info("=" * 50)
logger.info("ALL MODELS TRAINED SUCCESSFULLY!")
logger.info("=" * 50)
print(f'URL model: {X.shape[1]} features - Accuracy: {acc:.4f}')
print(f'Domain model: {X_domain.shape[1]} features - Accuracy: {acc_d:.4f}')
print(f'Certificate model: {X_cert.shape[1]} features - Accuracy: {acc_c:.4f}')