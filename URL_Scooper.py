from whois import get_whois_data, extract_whois_info
from nslookup import get_dns_records
from sslinfo import scan_website_ssl
from location import get_domain_location, print_location_info
from header import get_url_headers, print_headers
from safebrowsing import check_url_safety, print_url_safety
from printall import print_all_info
from htmlreport import generate_html
from traceroute import traceroute
import re
import socket

art = """
██╗   ██╗██████╗ ██╗         ███████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗██████╗ 
██║   ██║██╔══██╗██║         ██╔════╝██╔════╝██╔═══██╗██╔═══██╗██╔══██╗██╔════╝██╔══██╗
██║   ██║██████╔╝██║         ███████╗██║     ██║   ██║██║   ██║██████╔╝█████╗  ██████╔╝
██║   ██║██╔══██╗██║         ╚════██║██║     ██║   ██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗
╚██████╔╝██║  ██║███████╗    ███████║╚██████╗╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
 """


def display_menu():
    print(art)
    print("Choose an option:")
    print("1. WHOIS Information")
    print("2. DNSLOOKUP Information")
    print("3. SSL Information")
    print("4. Header Information")
    print("5. Location Information")
    print("6. Safe Browsing")
    print("7. Trace Route")
    print("8. Print All")
    print("9. Generate Report")
    print("10. Change URL")
    print("11. Exit")


def is_valid_domain(domain):
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$'
    return re.match(pattern, domain) is not None


def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


if __name__ == "__main__":
    while True:
        domain = input("Enter the URL to scan (e.g., example.com): ")
        if not domain:
            print("Error: URL cannot be empty. Please try again.")
            continue
        # Remove any leading/trailing spaces from the input
        domain = domain.strip()

        if not is_valid_domain(domain):
            print("Error: Invalid domain format. Please enter a valid URL.")
            continue

        if not domain_exists(domain):
            print("Error: Domain does not exist or cannot be resolved. Please enter a valid URL.")
            continue

        whois_info = None
        dns_records = None
        supported_versions = None
        cert_info = None
        headers_dict = None
        country = None
        region = None
        city = None
        latitude = None
        longitude = None

        while True:
            display_menu()
            choice = input("Enter your choice (1-11): ").strip()
            print("=" * 100)

            if choice == "1":
                whois_raw_data = get_whois_data(domain)
                whois_info = extract_whois_info(whois_raw_data)
                print("WHOIS Information:")
                print("=" * 100)
                print(whois_info)
                print("=" * 100)

            elif choice == "2":
                print("DNSLOOKUP Information:")
                print("=" * 100)
                dns_records = get_dns_records(domain)
                print(get_dns_records(domain))
                print("=" * 100)

            elif choice == "3":
                print("SSL Information:")
                print("=" * 100)
                supported_versions, cert_info = scan_website_ssl(domain)
                print("=" * 100)

            elif choice == "4":
                print("Header Information:")
                print("=" * 100)
                headers = get_url_headers(domain)
                # Print the headers using the print_headers function
                print_headers(headers)
                print("=" * 100)

            elif choice == "5":
                print("Location Information:")
                print("=" * 100)
                country, region, city, latitude, longitude = get_domain_location(domain)
                print_location_info(country, region, city, latitude, longitude)
                print("=" * 100)

            elif choice == "6":
                print("Safe Browsing: ")
                print("=" * 100)
                check_url_safety(domain)
                print_url_safety(domain)
                print("=" * 100)

            elif choice == "7":
                traceroute(domain)

            elif choice == "8":
                print_all_info(domain)

            elif choice == "9":
                print("Generating HTML Report...")
                generate_html(domain)
                break

            elif choice == "10":
                print("Changing URL...")
                break

            elif choice == "11":
                print("Exiting...")
                exit()

            else:
                print("Invalid choice. Please select a valid option.")
