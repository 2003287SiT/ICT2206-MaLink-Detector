from pysafebrowsing import SafeBrowsing

KEY = "AIzaSyAggK9tCPWuVumps4VcQEDB2bcRVcJCfR0"
s = SafeBrowsing(KEY)


def check_url_safety(url):
    results = s.lookup_urls([url])

    for domain, info in results.items():
        print("Domain:", domain)
        if info['malicious']:
            print("Malicious: Yes")
            print("Platforms:", ", ".join(info['platforms']))
            print("Threats:", ", ".join(info['threats']))
        else:
            print("Malicious: No")


if __name__ == '__main__':
    url_to_check = input("Enter the URL you want to check: ")
    check_url_safety(url_to_check)
