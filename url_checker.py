def is_suspicious_url(url):
    suspicious_keywords = {"login", "signin", "account", "bank", "paypal", "secure",
                           "confirm", "password", "verify", "update", "billing",
                           "malware", "trojan", "virus", "spyware", "keylogger", "backdoor", "exploit",
                           "buy", "cheap", "discount", "sale", "deal", "offer"}

    def contains_suspicious_keyword(url):
        return any(keyword in url.lower() for keyword in suspicious_keywords)

    def is_ip_address(url):
        parts = url.split(".")
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def is_shortened_url(url):
        shortened_domains = {"bit.ly", "goo.gl", "t.co", "ow.ly", "tinyurl"}
        return any(domain in url for domain in shortened_domains)

    def has_suspicious_extension(url):
        suspicious_extensions = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".jar"}
        return any(url.lower().endswith(extension) for extension in suspicious_extensions)

    return is_ip_address(url) or contains_suspicious_keyword(url) or is_shortened_url(url) or has_suspicious_extension(url)

# Test the function with some example URLs
if __name__ == "__main__":
    urls = [
        "https://www.example.com/some-page",
        "http://192.168.0.1",
        "https://www.suspicious-site.com/malicious.php",
        "https://www.valid-site.com/",
        "https://www.phishing-site.com/login.php",
        "https://www.update-site.com/1.0.0/update",
        "https://www.malware-site.com/malware.exe",
        "https://www.site-with-query-param.com/?cmd=execute",
        "https://bit.ly/xyz",
        "https://www.redirect-site.com/?u=https://malicious-site.com",
        "https://www.embed-site.com/script_embed",
    ]

    for url in urls:
        print(f"{url}: {is_suspicious_url(url)}")
