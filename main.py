from whois import get_whois_data, extract_whois_info
from nslookup import get_dns_records
from sslinfo import scan_website_ssl
from location import get_domain_location, print_location_info
from header import get_url_headers
from safebrowsing import check_url_safety

if __name__ == "__main__":
    domain = input("Enter the URL to scan (e.g., example.com):  ")

    print("-" * 100)
    print("Safe Browsing:")
    check_url_safety(domain)

    print("-" * 100)
    whois_raw_data = get_whois_data(domain)
    whois_info = extract_whois_info(whois_raw_data)
    print("WHOIS Information:")
    print(whois_info)

    print("-" * 100)

    print("DNSLOOKUP Information")
    print("-" * 100)
    dns_records = get_dns_records(domain)

    print("-" * 100)

    print("SSL Information:")
    supported_versions, cert_info = scan_website_ssl(domain)

    print("Header Information:")
    print("-" * 100)
    headers_dict = get_url_headers(domain)

    print("-" * 100)
    print("Location Information:")
    country, region, city, latitude, longitude = get_domain_location(domain)
    print_location_info(country, region, city, latitude, longitude)



