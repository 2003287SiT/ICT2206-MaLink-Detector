from whois import get_whois_data, extract_whois_info
from nslookup import get_dns_records
from sslinfo import scan_website_ssl
from location import get_domain_location, print_location_info
from header import get_url_headers

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
    print("6. Change URL")
    print("7. Exit")


if __name__ == "__main__":
    while True:
        domain = input("Enter the URL to scan (e.g., example.com): ")
        if not domain:
            print("Invalid URL. Please try again.")
            continue

        while True:
            display_menu()
            choice = input("Enter your choice (1-7): ")

            if choice == "1":
                print("=" * 100)
                whois_raw_data = get_whois_data(domain)
                whois_info = extract_whois_info(whois_raw_data)
                print("WHOIS Information:")
                print(whois_info)
                print("-" * 100)

            elif choice == "2":
                print("DNSLOOKUP Information")
                print("=" * 100)
                dns_records = get_dns_records(domain)
                print("-" * 100)

            elif choice == "3":
                print("SSL Information:")
                supported_versions, cert_info = scan_website_ssl(domain)

            elif choice == "4":
                print("Header Information:")
                print("=" * 100)
                headers_dict = get_url_headers(domain)
                print("=" * 100)

            elif choice == "5":
                print("Location Information:")
                country, region, city, latitude, longitude = get_domain_location(domain)
                print_location_info(country, region, city, latitude, longitude)


            elif choice == "6":
                print("Changing URL...")
                break

            elif choice == "7":
                print("Exiting...")
                exit()

            else:
                print("Invalid choice. Please select a valid option.")
