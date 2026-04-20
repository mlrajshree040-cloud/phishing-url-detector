# utils/scanner.py
import re
import whois
from urllib.parse import urlparse
from datetime import datetime, timezone

class PhishingScanner:
    def __init__(self):
   
     self.google_api_key = "AIzaSyDdJ02RGjPQ0eVxLRy6wu_YTy4AEAKI9rc"
     self.virustotal_api_key = "06fc38b21897addef6ca8d57a9a473d1c3cbb5bb6ce459a183f492d3d191bc66" 

     self.suspicious_keywords = [
        'login', 'signin', 'verify', 'account', 'secure', 'update',
        'confirm', 'banking', 'paypal', 'ebay', 'amazon', 'apple',
        'microsoft', 'google', 'facebook', 'instagram', 'authenticate',
        'validate', 'security', 'alert', 'warning', 'billing'
    ]
    
   
     self.whitelist = [
        'google.com', 'gmail.com', 'youtube.com', 'facebook.com',
        'amazon.com', 'microsoft.com', 'apple.com', 'github.com',
        'stackoverflow.com', 'wikipedia.org'
    ]
    
    
     self.api_cache = {}

    def check_https(self, url):
        parsed = urlparse(url)
        return parsed.scheme == 'https'

    def get_domain_age(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            domain = domain.split(':')[0]
            w = whois.whois(domain)
            creation_date = w.creation_date
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - creation_date).days
                return age
        except Exception:
            pass
        return None

    def count_suspicious_keywords(self, url):
        # Only check path and query (ignore domain)
        parsed = urlparse(url)
        check_string = (parsed.path + '?' + parsed.query).lower()
        return sum(1 for kw in self.suspicious_keywords if kw in check_string)

    def has_ip_address(self, url):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return re.search(ip_pattern, url) is not None

    def url_length_score(self, url):
        length = len(url)
        if length > 75:
            return 2   # high risk
        elif length > 54:
            return 1   # medium risk
        return 0

    def special_chars_ratio(self, url):
        specials = sum(1 for c in url if c in '@_-./:?=&')
        ratio = specials / len(url) if len(url) > 0 else 0
        return ratio > 0.3

    def is_shortened(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        return any(s in domain for s in shorteners)

    # NEW RULES:
    def has_at_symbol(self, url):
        """Phishing trick: https://www.bank.com@fake.com"""
        return '@' in url

    def has_double_slash_after_domain(self, url):
        """Detects multiple slashes after domain: https://example.com//login"""
        parsed = urlparse(url)
        path = parsed.path
        return '//' in path

    def detect_homoglyph_domain(self, url):
        """Check for common character substitutions in domain"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        
        homoglyph_patterns = [
            (r'0', 'o'),   # g00gle -> google
            (r'1', 'i'),   # paypa1 -> paypal
            (r'3', 'e'),   # go3gle -> google
            (r'5', 's'),   # micro5oft -> microsoft
            (r'@', 'a'),   # f@cebook -> facebook
            (r'rn', 'm'),  # rnicrosoft -> microsoft (m = rn)
        ]
        suspicious = False
        for pattern, replacement in homoglyph_patterns:
            test_domain = re.sub(pattern, replacement, domain)
            popular_brands = ['google', 'facebook', 'amazon', 'microsoft', 'paypal', 'apple', 'instagram']
            for brand in popular_brands:
                if brand in test_domain and brand not in domain:
                    suspicious = True
                    break
            if suspicious:
                break
        return suspicious

    def calculate_risk_score(self, url, https, age_days, kw_count, has_ip, is_short, url_len_score, special_ratio, has_at, double_slash, homoglyph):
        """Start from 100, subtract points for risks, add for security features"""
        score = 100

        if https:
            score += 15
        if age_days is not None and age_days > 365:
            score += 20
        elif age_days is not None and age_days > 180:
            score += 10
        if url_len_score == 0:  # short URL
            score += 5

        if not https:
            score -= 25
        if age_days is not None and age_days < 30:
            score -= 30
        elif age_days is not None and age_days < 180:
            score -= 15
        if kw_count >= 2:
            score -= 25
        elif kw_count == 1:
            score -= 10
        if has_ip:
            score -= 40
        if is_short:
            score -= 15
        if url_len_score >= 2:   
            score -= 15
        elif url_len_score == 1:
            score -= 5
        if special_ratio:
            score -= 10
        if has_at:
            score -= 35   
        if double_slash:
            score -= 15
        if homoglyph:
            score -= 30   
        return max(0, min(100, score))

    def get_risk_level(self, score):
        if score >= 70:
            return "SAFE"
        elif score >= 40:
            return "MEDIUM_RISK"
        else:
            return "DANGEROUS"

    def scan(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        if domain in self.whitelist:
            return {
                'url': url,
                'verdict': 'SAFE',
                'risk_score': 100,
                'risk_level': 'SAFE',
                'issues': [],
                'warnings': [],
                'details': {
                    'https': self.check_https(url),
                    'domain_age_days': self.get_domain_age(url),
                    'suspicious_keyword_count': 0,
                    'has_ip': False,
                    'is_shortened': False,
                    'url_length': len(url),
                    'has_at_symbol': False,
                    'has_double_slash': False,
                    'homoglyph_detected': False
                }
            }

        
        https = self.check_https(url)
        age_days = self.get_domain_age(url)
        kw_count = self.count_suspicious_keywords(url)
        has_ip = self.has_ip_address(url)
        is_short = self.is_shortened(url)
        url_len_score = self.url_length_score(url)
        special_ratio = self.special_chars_ratio(url)
        has_at = self.has_at_symbol(url)
        double_slash = self.has_double_slash_after_domain(url)
        homoglyph = self.detect_homoglyph_domain(url)

        issues = []
        warnings = []

        if not https:
            issues.append("No HTTPS (insecure connection)")
        if age_days is not None and age_days < 30:
            issues.append(f"Domain is very new ({age_days} days old)")
        elif age_days is not None and age_days < 180:
            warnings.append(f"Domain is relatively new ({age_days} days)")
        elif age_days is None:
            warnings.append("Could not retrieve domain age")
        if kw_count >= 2:
            issues.append(f"Contains {kw_count} suspicious keyword(s) in path/query")
        elif kw_count == 1:
            warnings.append("Contains 1 suspicious keyword in path/query")
        if has_ip:
            issues.append("URL uses IP address instead of domain name")
        if is_short:
            warnings.append("URL shortened – destination hidden")
        if url_len_score == 2:
            issues.append("Excessively long URL")
        elif url_len_score == 1:
            warnings.append("Long URL")
        if special_ratio:
            warnings.append("High number of special characters")
        if has_at:
            issues.append("URL contains '@' symbol (often used for phishing redirection)")
        if double_slash:
            warnings.append("Multiple slashes in URL path (possible redirection trick)")
        if homoglyph:
            issues.append("Domain uses homoglyph characters (e.g., 0 for o, 1 for i) to mimic trusted brand")

        risk_score = self.calculate_risk_score(
            url, https, age_days, kw_count, has_ip, is_short,
            url_len_score, special_ratio, has_at, double_slash, homoglyph
        )
        risk_level = self.get_risk_level(risk_score)

        return {
            'url': url,
            'verdict': risk_level,   
            'risk_score': risk_score,
            'risk_level': risk_level,
            'issues': issues,
            'warnings': warnings,
            'details': {
                'https': https,
                'domain_age_days': age_days,
                'suspicious_keyword_count': kw_count,
                'has_ip': has_ip,
                'is_shortened': is_short,
                'url_length': len(url),
                'has_at_symbol': has_at,
                'has_double_slash': double_slash,
                'homoglyph_detected': homoglyph
            }
        }