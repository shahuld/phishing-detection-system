#!/usr/bin/env python3
"""
URLFeatureExtractor - Extracts EXACTLY 11 features matching phishing_detector.py
Used by train_realistic.py for consistent model training
"""

import re
import math
import numpy as np
from urllib.parse import urlparse
from collections import Counter
import sys

def entropy(s):
    """Calculate character entropy (phishing uses random chars)"""
    if not s:
        return 0.0
    prob = [v/len(s) for v in Counter(s).values()]
    return -sum(p * math.log2(p) for p in prob if p > 0)

class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'ru', 'top', 'xyz', 'site', 
            'online', 'pw', 'cc', 'work', 'click', 'club'
        }
        self.shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'}

    def extract_features(self, url):
        """
        Extract EXACTLY 11 features matching phishing_detector.predict_url()
        Returns dict or None if invalid URL
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            url = url.lower()
            parsed = urlparse(url)

            netloc = parsed.netloc or ''
            path = parsed.path or ''
            url_len = len(url)

            # === 11 EXACT FEATURES ===
            
            # 1. log(url_length + 1)
            url_len_log = math.log(url_len + 1)
            
            # 2. has_ip
            has_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}', netloc))
            
            # 3. has_at  
            has_at = '@' in netloc
            
            # 4. dash_count normalized
            dash_count = netloc.count('-') + path.count('-')
            dash_norm = min(dash_count / 15.0, 1.0)
            
            # 5. suspicious_tld
            tld = netloc.split('.')[-1] if '.' in netloc else ''
            suspicious_tld = tld in self.suspicious_tlds
            
            # 6. http_no_ssl
            http_no_ssl = parsed.scheme != 'https'
            
            # 7. subdomain_count normalized
            parts = [p for p in netloc.split('.') if p]
            subdomain_count = max(len(parts) - 2, 0) / 8.0
            
            # 8. digit_ratio
            digits = sum(c.isdigit() for c in url)
            digit_ratio = digits / max(url_len, 1)
            
            # 9. url_entropy
            url_entropy = entropy(url)
            
            # 10. hex_chars ratio
            hex_chars = sum(1 for c in url if c in '0123456789abcdefABCDEF') / max(url_len, 1)
            
            # 11. is_shortener
            is_shortener = any(short in url for short in self.shorteners)

            return {
                'url_length_log': url_len_log,
                'has_ip': float(has_ip),
                'has_at': float(has_at),
                'dash_count_norm': dash_norm,
                'suspicious_tld': float(suspicious_tld),
                'http_no_ssl': float(http_no_ssl),
                'subdomain_norm': subdomain_count,
                'digit_ratio': digit_ratio,
                'entropy': url_entropy,
                'hex_ratio': hex_chars,
                'is_shortener': float(is_shortener),
                # Training labels (extract_features doesn't need but included for completeness)
                'url_length': url_len,
                'raw_features': True  # Marker: exactly 11 ML features
            }
        except Exception as e:
            print(f"Feature extraction failed for {url}: {e}", file=sys.stderr)
            return None

# Test extraction
if __name__ == "__main__":
    extractor = URLFeatureExtractor()
    test_urls = [
        "https://example.com",
        "http://192.168.1.1/login",
        "https://secure-bank-login.xyz/verify"
    ]
    
    for url in test_urls:
        features = extractor.extract_features(url)
        if features:
            print(f"{url}: 11 features ✓")
            ml_features = [features['url_length_log'], features['has_ip'], features['has_at'], 
                          features['dash_count_norm'], features['suspicious_tld'], features['http_no_ssl'],
                          features['subdomain_norm'], features['digit_ratio'], features['entropy'],
                          features['hex_ratio'], features['is_shortener']]
            print(f"  ML Features ({len(ml_features)}): {ml_features[:3]}...")
        print()

