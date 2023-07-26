from pysafebrowsing import SafeBrowsing

KEY = "AIzaSyAggK9tCPWuVumps4VcQEDB2bcRVcJCfR0"
s = SafeBrowsing(KEY)


def check_url_safety(url):
    results = s.lookup_urls([url])

    for domain, info in results.items():
        if info['malicious']:
            return f"Malicious: Yes\nPlatforms: {', '.join(info['platforms'])}\nThreats: {', '.join(info['threats'])}"
        else:
            return "Malicious: No"


def print_url_safety(url):
    safety_info = check_url_safety(url)
    print(safety_info)


if __name__ == "__main__":
    domain = input("Enter the URL to check safety: ")
    print_url_safety(domain)
