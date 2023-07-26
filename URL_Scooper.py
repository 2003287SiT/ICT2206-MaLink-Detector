from whois import get_whois_data, extract_whois_info
from nslookup import get_dns_records
from sslinfo import scan_website_ssl
from location import get_domain_location, print_location_info
from header import get_url_headers, print_headers
from safebrowsing import check_url_safety, print_url_safety
from htmlreport import generate_html
from domainvalidation import is_multi_line_input

art = """
██╗   ██╗██████╗ ██╗         ███████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗██████╗ 
██║   ██║██╔══██╗██║         ██╔════╝██╔════╝██╔═══██╗██╔═══██╗██╔══██╗██╔════╝██╔══██╗
██║   ██║██████╔╝██║         ███████╗██║     ██║   ██║██║   ██║██████╔╝█████╗  ██████╔╝
██║   ██║██╔══██╗██║         ╚════██║██║     ██║   ██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗
╚██████╔╝██║  ██║███████╗    ███████║╚██████╗╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
 """

art1 = """
░█░█░█░█░█▀█░▀█▀░█▀▀░░░▀█▀░█▀█░█▀▀░█▀█░█▀▄░█▄█░█▀█░▀█▀░▀█▀░█▀█░█▀█
░█▄█░█▀█░█░█░░█░░▀▀█░░░░█░░█░█░█▀▀░█░█░█▀▄░█░█░█▀█░░█░░░█░░█░█░█░█
░▀░▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░░░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░▀░▀░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀
      """

art2 = """
░█▀▄░█▀█░█▀▀░█░░░█▀█░█▀█░█░█░█░█░█▀█░░░▀█▀░█▀█░█▀▀░█▀█░█▀▄░█▄█░█▀█░▀█▀░▀█▀░█▀█░█▀█
░█░█░█░█░▀▀█░█░░░█░█░█░█░█▀▄░█░█░█▀▀░░░░█░░█░█░█▀▀░█░█░█▀▄░█░█░█▀█░░█░░░█░░█░█░█░█
░▀▀░░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░░░░░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░▀░▀░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀
      """

art3 = """
░█▀▀░█▀▀░█░░░░░▀█▀░█▀█░█▀▀░█▀█░█▀▄░█▄█░█▀█░▀█▀░▀█▀░█▀█░█▀█
░▀▀█░▀▀█░█░░░░░░█░░█░█░█▀▀░█░█░█▀▄░█░█░█▀█░░█░░░█░░█░█░█░█
░▀▀▀░▀▀▀░▀▀▀░░░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░▀░▀░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀
      """

art4 = """
░█░█░█▀▀░█▀█░█▀▄░█▀▀░█▀▄░░░▀█▀░█▀█░█▀▀░█▀█░█▀▄░█▄█░█▀█░▀█▀░▀█▀░█▀█░█▀█
░█▀█░█▀▀░█▀█░█░█░█▀▀░█▀▄░░░░█░░█░█░█▀▀░█░█░█▀▄░█░█░█▀█░░█░░░█░░█░█░█░█
░▀░▀░▀▀▀░▀░▀░▀▀░░▀▀▀░▀░▀░░░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░▀░▀░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀
      """

art5 = """
░█░░░█▀█░█▀▀░█▀█░▀█▀░▀█▀░█▀█░█▀█░░░▀█▀░█▀█░█▀▀░█▀█░█▀▄░█▄█░█▀█░▀█▀░▀█▀░█▀█░█▀█
░█░░░█░█░█░░░█▀█░░█░░░█░░█░█░█░█░░░░█░░█░█░█▀▀░█░█░█▀▄░█░█░█▀█░░█░░░█░░█░█░█░█
░▀▀▀░▀▀▀░▀▀▀░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀░░░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░▀░▀░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀
      """

art6 = """
░█▀▀░█▀█░█▀▀░█▀▀░░░█▀▄░█▀▄░█▀█░█░█░█▀▀░▀█▀░█▀█░█▀▀
░▀▀█░█▀█░█▀▀░█▀▀░░░█▀▄░█▀▄░█░█░█▄█░▀▀█░░█░░█░█░█░█
░▀▀▀░▀░▀░▀░░░▀▀▀░░░▀▀░░▀░▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀
      """

art7 = """
░█▀█░█▀▄░▀█▀░█▀█░▀█▀░░░█▀█░█░░░█░░░░░█▀█░█▀█░▀█▀░▀█▀░█▀█░█▀█░█▀▀
░█▀▀░█▀▄░░█░░█░█░░█░░░░█▀█░█░░░█░░░░░█░█░█▀▀░░█░░░█░░█░█░█░█░▀▀█
░▀░░░▀░▀░▀▀▀░▀░▀░░▀░░░░▀░▀░▀▀▀░▀▀▀░░░▀▀▀░▀░░░░▀░░▀▀▀░▀▀▀░▀░▀░▀▀▀
      """

art8 = """
░█▀▀░█▀▀░█▀█░█▀▀░█▀▄░█▀█░▀█▀░▀█▀░█▀█░█▀▀░░░█░█░▀█▀░█▄█░█░░░░░█▀▄░█▀▀░█▀█░█▀█░█▀▄░▀█▀░░░░░░░░░
░█░█░█▀▀░█░█░█▀▀░█▀▄░█▀█░░█░░░█░░█░█░█░█░░░█▀█░░█░░█░█░█░░░░░█▀▄░█▀▀░█▀▀░█░█░█▀▄░░█░░░░░░░░░░
░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀░░░▀░▀░░▀░░▀░▀░▀▀▀░░░▀░▀░▀▀▀░▀░░░▀▀▀░▀░▀░░▀░░▀░░▀░░▀░
      """

art9 = """
░█▀▀░█░█░█▀█░█▀█░█▀▀░█▀▀░░░█░█░█▀▄░█░░
░█░░░█▀█░█▀█░█░█░█░█░█▀▀░░░█░█░█▀▄░█░░
░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀▀▀░░░▀▀▀░▀░▀░▀▀▀
      """

art0 = """
░█▀▀░█▀█░█▀█░█▀▄░█▀▄░█░█░█▀▀░█
░█░█░█░█░█░█░█░█░█▀▄░░█░░█▀▀░▀
░▀▀▀░▀▀▀░▀▀▀░▀▀░░▀▀░░░▀░░▀▀▀░▀
      """

def display_menu():
    print("\n")
    print(art)
    print("Choose an option:")
    print("1. WHOIS Information")
    print("2. DNSLOOKUP Information")
    print("3. SSL Information")
    print("4. Header Information")
    print("5. Location Information")
    print("6. Safe Browsing")
    print("7. Print All")
    print("8. Generate Report")
    print("9. Change URL")
    print("0. Exit")


if __name__ == "__main__":
    while True:
        domain = input("Enter the URL to scan (e.g., example.com): ")
        if not domain:
            print("Error: URL cannot be empty. Please try again.")
            continue

        if is_multi_line_input(domain):
            print("Error: URL cannot be more than one line of input. Please try again.")
            continue

        # Remove any leading/trailing spaces from the input
        domain = domain.strip()

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
            choice = input("Enter your choice (1-9): ")
            print("\n")

            if choice == "1":
                print("=" * 100)
                print(art1)
                print("=" * 100)

                whois_raw_data = get_whois_data(domain)
                whois_info = extract_whois_info(whois_raw_data)

                print(whois_info)

                print("=" * 100)
                print("=" * 100)
                print("\n")
                input("Press enter to continue: ")



            elif choice == "2":
                print("=" * 100)
                print(art2)
                print("=" * 100)

                dns_records = get_dns_records(domain)
                print(get_dns_records(domain))

                print("=" * 100)
                print("=" * 100)
                print("\n")
                input("Press enter to continue: ")


            elif choice == "3":
                print("=" * 100)
                print(art3)
                print("=" * 100)

                supported_versions, cert_info = scan_website_ssl(domain)

                print("=" * 100)
                print("=" * 100)
                print("\n")
                input("Press enter to continue: ")


            elif choice == "4":
                print("=" * 100)
                print(art4)
                print("=" * 100)
                headers_dict = get_url_headers(domain)
                print_headers(headers_dict)

                print("=" * 100)
                print("=" * 100)
                print("\n")
                input("Press enter to continue: ")


            elif choice == "5":
                print("=" * 100)
                print(art5)
                print("=" * 100)
                country, region, city, latitude, longitude = get_domain_location(domain)
                print_location_info(country, region, city, latitude, longitude)

                print("=" * 100)
                print("=" * 100)
                print("\n")
                input("Press enter to continue: ")


            elif choice == "6":
                print("=" * 100)
                print(art6)
                print("=" * 100)
                check_url_safety(domain)
                print_url_safety(domain)

                print("=" * 100)
                print("=" * 100)
                print("\n")
                input("Press enter to continue: ")


            elif choice == "7":
                print("=" * 100)
                print(art7)
                print("=" * 100)
                print("Generating...")
                whois_raw_data = get_whois_data(domain)
                whois_info = extract_whois_info(whois_raw_data)
                print("-" * 100)
                print(art1)
                print("-" * 100)
                print(whois_info)

                print("-" * 100)
                print(art2)
                print("-" * 100)
                dns_records = get_dns_records(domain)
                print(get_dns_records(domain))

                print("-" * 100)
                print(art3)
                print("-" * 100)
                scan_website_ssl(domain)
                print("-" * 100)

                print("-" * 100)
                print(art4)
                print("-" * 100)
                headers = get_url_headers(domain)
                # Print the headers using the print_headers function
                print_headers(headers)
                print("-" * 100)

                print("-" * 100)
                print(art5)
                print("-" * 100)
                country, region, city, latitude, longitude = get_domain_location(domain)
                print_location_info(country, region, city, latitude, longitude)
                #
                print("-" * 100)
                print(art6)
                print("-" * 100)
                print_url_safety(domain)

                print("=" * 100)
                print("=" * 100)
                print("\n")
                input("Press enter to continue: ")



            elif choice == "8":
                print("-" * 100)
                print(art8)
                print("-" * 100)
                generate_html(domain)
                print("=" * 100)
                print("=" * 100)
                print("\n")
                input("Press enter to continue: ")



            elif choice == "9":
                print("-" * 100)
                print(art9)
                print("-" * 100)
                print("Changing URL...")
                break

            elif choice == "0":
                print("-" * 100)
                print(art0)
                print("-" * 100)
                print("Exiting...")
                exit()

            else:
                print("Invalid choice. Please select a valid option.")
