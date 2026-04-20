# utils/feature_extraction.py
import re
from urllib.parse import urlparse

def extract_features(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    features = []
    features.append(len(url))
    features.append(url.count('.'))
    features.append(1 if urlparse(url).scheme == 'https' else 0)
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else 0)
    features.append(1 if '@' in url else 0)
    path = urlparse(url).path
    features.append(1 if '//' in path else 0)
  
    suspicious_keywords = [
        'login', 'signin', 'verify', 'account', 'secure', 'update',
        'confirm', 'banking', 'paypal', 'ebay', 'amazon', 'apple',
        'microsoft', 'google', 'facebook', 'instagram', 'authenticate',
        'validate', 'security', 'alert', 'warning', 'billing'
    ]
    url_lower = url.lower()
    kw_count = sum(1 for kw in suspicious_keywords if kw in url_lower)
    features.append(kw_count)

    features.append(1 if url.count('/') > 3 else 0)

    
    features.append(-1)  
    return features