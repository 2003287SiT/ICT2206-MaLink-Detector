from whois import extract_whois_info, get_whois_data
from nslookup import get_dns_records
from sslinfo import scan_website_ssl
from location import get_domain_location, print_location_info
from header import get_url_headers, print_headers
from safebrowsing import print_url_safety


if __name__ == "__main__":
    domain = input("Enter the URL to scan (e.g., example.com):  ")
    headers_dict = get_url_headers(domain)
    # print("Generating...")
    whois_raw_data = get_whois_data(domain)
    whois_info = extract_whois_info(whois_raw_data)
    print("-" * 100)
    print("WHOIS Information:")
    print("-" * 100)
    print(whois_info)

    print("-" * 100)
    print("DNSLOOKUP Information")
    print("-" * 100)
    dns_records = get_dns_records(domain)
    print(get_dns_records(domain))

    print("-" * 100)
    print("SSL Information:")
    print("-" * 100)
    scan_website_ssl(domain)
    print("-" * 100)

    print("-" * 100)
    print("Header Information:")
    print("-" * 100)
    headers = get_url_headers(domain)

    # Print the headers using the print_headers function
    print_headers(headers)
    print("-" * 100)

    print("-" * 100)
    print("Location Information:")
    print("-" * 100)
    country, region, city, latitude, longitude = get_domain_location(domain)
    print_location_info(country, region, city, latitude, longitude)
    #
    print("-" * 100)
    print("Safe Browsing:")
    print("-" * 100)
    print_url_safety(domain)
