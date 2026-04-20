import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.scanner import PhishingScanner

def test_https_check():
    scanner = PhishingScanner()
    assert scanner.check_https("https://google.com") == True
    assert scanner.check_https("http://google.com") == False

def test_suspicious_keywords():
    scanner = PhishingScanner()
    assert scanner.count_suspicious_keywords("http://login.com") >= 1
    assert scanner.count_suspicious_keywords("http://example.com") == 0

def test_ip_detection():
    scanner = PhishingScanner()
    assert scanner.has_ip_address("http://192.168.1.1/login") == True
    assert scanner.has_ip_address("http://example.com") == False

if __name__ == "__main__":
    test_https_check()
    test_suspicious_keywords()
    test_ip_detection()
    print("All tests passed!")