import re

def is_suspicious_url(url):
    # Define a list of regular expressions to match against different suspicious patterns
    suspicious_patterns = [
        r"\b(?:https?://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP address in the URL
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/.*\.php\b",  # PHP file in the URL
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/.*\b(?:login|signin|account|bank|paypal|secure|confirm|password|verify|update|billing)\b",  # Phishing-related patterns
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/.*\b(?:update|install|download|patch)\b(?:\d+\.\d+)+",  # Fake software update URLs
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/.*\b(?:malware|trojan|virus|spyware|keylogger|backdoor|exploit)\b",  # Malware distribution URLs
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/.*\.(?:exe|dll|bat|cmd|vbs|js|jar)\b",  # Suspicious file extensions
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/\?.*\b(?:cmd|exec|eval|javascript|script)\b",  # Suspicious query parameters
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/.*\b(?:bit\.ly|goo\.gl|t\.co|ow\.ly|tinyurl)\b",  # URL shorteners
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/\?(?:.*&)?(?:u|url|link|dest|target|redir|redirect)=\b",  # URL redirection in query parameters
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/.*\b(?:script|iframe|embed)\b",  # Script, iframe, or embed tags in the URL
        r"\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+)\.(?:[a-zA-Z]{2,})/.*\b(?:buy|cheap|discount|sale|deal|offer)\b",  # URLs with keywords suggesting suspicious offers
    ]

    # Check if the URL matches any of the suspicious patterns
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True

    return False

# Test the function with some example URLs
url1 = "https://www.example.com/some-page"
url2 = "http://192.168.0.1"
url3 = "https://www.suspicious-site.com/malicious.php"
url4 = "https://www.valid-site.com/"
url5 = "https://www.phishing-site.com/login.php"
url6 = "https://www.update-site.com/1.0.0/update"
url7 = "https://www.malware-site.com/malware.exe"
url8 = "https://www.site-with-query-param.com/?cmd=execute"
url9 = "https://www.redirect-site.com/?u=https://malicious-site.com"

print(is_suspicious_url(url1))  # Output: False
print(is_suspicious_url(url2))  # Output: True
print(is_suspicious_url(url3))  # Output: True
print(is_suspicious_url(url4))  # Output: False
print(is_suspicious_url(url5))  # Output: True
print(is_suspicious_url(url6))  # Output: True
print(is_suspicious_url(url7))  # Output: True
print(is_suspicious_url(url8))  # Output: True
print(is_suspicious_url(url9)) # Output: True
