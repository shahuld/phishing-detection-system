import sys
import json
import joblib
import argparse
import logging
import re
import os
import numpy as np
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_model_scaler(model_type):
    # Use script's directory for model paths (more reliable)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # From python/ml go up TWO levels (to phishing) then to backend/models
    base_path = os.path.join(script_dir, '../../backend/models')
    base_path = os.path.normpath(base_path)

    # Debug: print paths to help diagnose
    logger.info(f'Script directory: {script_dir}')
    logger.info(f'Base models path: {base_path}')

    model_path = f'{base_path}/{model_type}_phishing_model.joblib'
    scaler_path = f'{base_path}/{model_type}_scaler.joblib'
    try:
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        logger.info(f'Loaded {model_type} model/scaler from {base_path}')
        return model, scaler
    except FileNotFoundError:
        logger.warning(f'{model_type.capitalize()} models not found at {base_path}, using domain fallback')
        # For certificate, use domain model as fallback
        return joblib.load(f'{base_path}/domain_phishing_model.joblib'), joblib.load(f'{base_path}/domain_scaler.joblib')

def extract_url_features(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.lower() or ''
    path = parsed.path or ''
    query = parsed.query or ''

    # 11 features matching trained scaler
    features = np.zeros(11)

    features[0] = len(url)  # url_length
    features[1] = len(netloc)  # hostname_length
    features[2] = len(path)  # path_length
    features[3] = netloc.count('.')  # num_dots
    features[4] = netloc.count('-')  # num_hyphens

    # IP address detection
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features[5] = 1 if re.match(ip_pattern, netloc.split(':')[0]) else 0  # has_ip

    features[6] = url.count('@')  # has_at_symbol

    suspicious_tld = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
    features[7] = 1 if any(tld in netloc for tld in suspicious_tld) else 0  # is_suspicious_tld

    # Subdomain count
    features[8] = len([d for d in netloc.split('.') if d])  # subdomain_count

    features[9] = len(query)  # query_length

    # Email in URL (simplified)
    has_email = 0
    if '@' in url and netloc:
        try:
            at_pos = url.index('@')
            has_email = 1 if at_pos < url.index(netloc) else 0
        except:
            has_email = 0
    features[10] = has_email  # has_email_in_url

    return features

def extract_cert_features(cert_data):
    # If domain is provided, fetch real certificate data
    domain = cert_data.get('domain')
    cert_valid = False
    cert_details = {}

    if domain:
        try:
            import ssl
            import socket
            from datetime import datetime

            # Create SSL context and fetch certificate
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
                sock.settimeout(5)
                sock.connect((domain, 443))
                cert = sock.getpeercert()

            # Parse certificate details
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))

            # Get expiry date
            not_after = cert.get('notAfter')
            if not_after:
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry - datetime.now()).days
            else:
                days_until_expiry = 365

            # Get Subject Alternative Names
            san = cert.get('subjectAltName', [])
            san_count = sum(1 for a in san if a[0] == 'DNS')

            # Check for wildcard
            has_wildcard = any('*' in a[1] for a in san if a[0] == 'DNS')

            # Get key size (estimate from public key)
            key_size = 2048

            cert_valid = days_until_expiry > 0  # Certificate is valid if not expired

            cert_details = {
                'days_until_expiry': days_until_expiry,
                'key_size': key_size,
                'has_chain': True,
                'san_count': san_count,
                'has_wildcard': has_wildcard,
                'issuer': issuer.get('commonName', 'Unknown'),
                'subject': subject.get('commonName', domain),
                'sig_alg': cert.get('signatureAlgorithm', 'sha256').upper()
            }

            cert_data.update(cert_details)
            logger.info(f"Fetched real certificate for {domain}: {days_until_expiry} days until expiry, valid={cert_valid}")
        except Exception as e:
            logger.warning(f"Failed to fetch certificate for {domain}: {e}")
            cert_valid = False
            cert_details = {
                'days_until_expiry': 0,
                'key_size': 2048,
                'has_chain': False,
                'san_count': 0,
                'has_wildcard': False,
                'issuer': 'Unknown',
                'subject': domain,
                'sig_alg': 'Unknown'
            }

    # For certificate, use rule-based validation instead of ML model
    # This is more reliable for certificate validation
    days = cert_data.get('days_until_expiry', 0)
    is_valid = days > 30  # More than 30 days = valid

    # Update features based on certificate validity
    features = np.zeros(8)
    if is_valid:
        # Safe certificate features
        features[0] = min(days / 365, 1)  # Good expiry
        features[1] = 0.5  # Normal key size
        features[2] = 0  # Has chain
        features[3] = cert_data.get('san_count', 1) / 10  # Normal SAN count
        features[4] = 1 if cert_data.get('has_wildcard', False) else 0  # Wildcard
        features[5] = 0  # Not expiring soon
        features[6] = 0  # Strong key
        features[7] = 0.5  # Neutral
    else:
        # Invalid/risky certificate features
        features[0] = min(days / 365, 1)  # Low expiry
        features[1] = 0.5  # Key size
        features[2] = 1  # No chain
        features[3] = cert_data.get('san_count', 1) / 10
        features[4] = 0
        features[5] = 1  # Expiring soon
        features[6] = 0
        features[7] = 0.5

    return features

def extract_domain_features(domain_data):
    # If domain is provided, fetch real domain data
    domain = domain_data.get('domain')
    if domain:
        try:
            import subprocess
            import datetime
            import re

            # Use whois command-line tool (available on macOS/Linux)
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
            whois_text = result.stdout

            # Parse creation date
            creation_date = None
            for line in whois_text.split('\n'):
                if 'Creation Date:' in line or 'created:' in line.lower():
                    date_str = line.split(':')[1].strip()
                    try:
                        # Try multiple date formats
                        for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d', '%d-%b-%Y']:
                            try:
                                creation_date = datetime.datetime.strptime(date_str, fmt)
                                break
                            except:
                                continue
                    except:
                        pass
                    break

            # Get domain age
            if creation_date:
                domain_age_days = (datetime.datetime.now() - creation_date).days
            else:
                domain_age_days = 365

            # Parse registrar
            registrar = 'Unknown'
            for line in whois_text.split('\n'):
                if 'Registrar:' in line or 'Registrar Name:' in line:
                    registrar = line.split(':')[1].strip()
                    break

            # Parse country
            country = None
            for line in whois_text.split('\n'):
                if 'Country:' in line or 'Registrant Country:' in line:
                    country = line.split(':')[1].strip()
                    break

            # Check if domain is newer than 90 days
            is_new = domain_age_days < 90

            # Known registrars (legitimate)
            known_registrars = ['godaddy', 'namecheap', 'google', 'cloudflare', 'amazon', 'markmonitor', 'network solutions']
            is_known = any(r in registrar.lower() for r in known_registrars) if registrar != 'Unknown' else False

            # High risk countries
            high_risk_countries = ['CN', 'RU', 'UA', 'KZ', 'BY', 'PK', 'IR', 'KP']
            is_high_risk = country in high_risk_countries if country else False

            domain_data['domain_age_days'] = domain_age_days
            domain_data['days_until_expiry'] = 365  # Default since hard to parse
            domain_data['registrar'] = registrar
            domain_data['country'] = country
            domain_data['has_privacy_protection'] = False
            domain_data['is_known_registrar'] = is_known
            domain_data['is_new_domain'] = is_new
            domain_data['is_high_risk_country'] = is_high_risk

            logger.info(f"Fetched real domain data for {domain}: age={domain_age_days} days, registrar={registrar}, country={country}")
        except Exception as e:
            logger.warning(f"Failed to fetch WHOIS data for {domain}: {e}")
            # Use defaults
            domain_data.setdefault('domain_age_days', 365)
            domain_data.setdefault('days_until_expiry', 365)
            domain_data.setdefault('registrar', 'Unknown')
            domain_data.setdefault('has_privacy_protection', False)
            domain_data.setdefault('is_known_registrar', False)
            domain_data.setdefault('is_new_domain', False)
            domain_data.setdefault('is_high_risk_country', False)

    # 8 features matching domain_scaler
    features = np.zeros(8)
    features[0] = min(domain_data.get('domain_age_days', 365) / 3650, 1)
    features[1] = 1 if domain_data.get('domain_age_days', 365) < 90 else 0
    features[2] = 1 if domain_data.get('has_privacy_protection', False) else 0
    features[3] = 1 if domain_data.get('is_high_risk_country', False) else 0
    features[4] = domain_data.get('nameserver_count', 2) / 10  # normalize
    features[5] = 1 if domain_data.get('days_until_expiry', 365) < 90 else 0
    features[6] = 1 if domain_data.get('is_new_domain', False) else 0
    features[7] = 1 if domain_data.get('has_dnssec', False) else 0
    return features

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PhishGuard ML Detector - Fixed')
    parser.add_argument('url', nargs='?', default=None, help='URL for url type')
    parser.add_argument('--type', choices=['url', 'domain', 'certificate'], default='url')
    parser.add_argument('--input', type=str, help='JSON input file for domain/certificate')
    args = parser.parse_args()

    model_type = args.type
    model, scaler = load_model_scaler(model_type)
    
    details = {}
    
    if model_type == 'url':
        url = args.url or 'http://example.com'
        features = extract_url_features(url)
        details = {'url': url}
    else:
        if not args.input:
            print(json.dumps({'result': 'error', 'message': f'--input JSON required for {model_type}'}, indent=2))
            sys.exit(1)
        with open(args.input, 'r') as f:
            data = json.load(f)
        if model_type == 'certificate':
            features = extract_cert_features(data)
        else:
            features = extract_domain_features(data)
        details = data
    
    features_scaled = scaler.transform(features.reshape(1, -1))
    pred = model.predict(features_scaled)[0]
    prob = model.predict_proba(features_scaled)[0][1]

    if model_type == 'url':
        result_str = 'phishing' if pred == 1 else 'safe'
        confidence = float(prob) * 100 if pred == 1 else (1 - float(prob)) * 100
    elif model_type == 'certificate':
        # Use rule-based validation for certificate
        days = details.get('days_until_expiry', 0)
        if days > 30:
            result_str = 'valid'
            confidence = 95.0
        else:
            result_str = 'invalid'
            confidence = 90.0
    else:
        result_str = 'suspicious' if pred == 1 else 'valid'
        confidence = float(prob) * 100 if pred == 1 else (1 - float(prob)) * 100
    
    result = {
        'result': result_str,
        'confidence': float(prob),
        'features': features.tolist(),
        'details': details
    }
    
    print(json.dumps(result, indent=2))
