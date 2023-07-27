from whois import get_whois_data, extract_whois_info
from nslookup import get_dns_records
from sslinfo import scan_website_ssl
from location import get_domain_location, print_location_info
from header import get_url_headers, print_headers
from safebrowsing import check_url_safety, print_url_safety
from Scooper_ML import mlScan
from htmlreport import generate_html
from domainvalidation import is_multi_line_input
from cliformat import optionheader, optionfooter, subheader

art = """
███████╗██╗████████╗███████╗    ███████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗██████╗ 
██╔════╝██║╚══██╔══╝██╔════╝    ██╔════╝██╔════╝██╔═══██╗██╔═══██╗██╔══██╗██╔════╝██╔══██╗
███████╗██║   ██║   █████╗      ███████╗██║     ██║   ██║██║   ██║██████╔╝█████╗  ██████╔╝
╚════██║██║   ██║   ██╔══╝      ╚════██║██║     ██║   ██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗
███████║██║   ██║   ███████╗    ███████║╚██████╗╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
╚══════╝╚═╝   ╚═╝   ╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
 """

artS = """
░█▀▀░█░█░█▀▄░█▀▄░█▀▀░█▀█░▀█▀░░░█▀▄░█▀█░█▄█░█▀█░▀█▀░█▀█░░░█░█░█░█▀▄░█░░░░░░
░█░░░█░█░█▀▄░█▀▄░█▀▀░█░█░░█░░░░█░█░█░█░█░█░█▀█░░█░░█░█░▄▀░░█░█░█▀▄░█░░░░▀░
░▀▀▀░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀░░▀░░░░▀▀░░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░▀▀▀░░▀░
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
░█▄█░█░░░░░█▀▀░█░█░█▀▀░█▀▀░█░█░█▀▀░█▀▄
░█░█░█░░░░░█░░░█▀█░█▀▀░█░░░█▀▄░█▀▀░█▀▄
░▀░▀░▀▀▀░░░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀
      """

art8 = """
░█▀█░█▀▄░▀█▀░█▀█░▀█▀░░░█▀█░█░░░█░░░░░█▀█░█▀█░▀█▀░▀█▀░█▀█░█▀█░█▀▀
░█▀▀░█▀▄░░█░░█░█░░█░░░░█▀█░█░░░█░░░░░█░█░█▀▀░░█░░░█░░█░█░█░█░▀▀█
░▀░░░▀░▀░▀▀▀░▀░▀░░▀░░░░▀░▀░▀▀▀░▀▀▀░░░▀▀▀░▀░░░░▀░░▀▀▀░▀▀▀░▀░▀░▀▀▀
      """

art9 = """
░█▀▀░█▀▀░█▀█░█▀▀░█▀▄░█▀█░▀█▀░▀█▀░█▀█░█▀▀░░░█░█░▀█▀░█▄█░█░░░░░█▀▄░█▀▀░█▀█░█▀█░█▀▄░▀█▀░░░░░░░░░
░█░█░█▀▀░█░█░█▀▀░█▀▄░█▀█░░█░░░█░░█░█░█░█░░░█▀█░░█░░█░█░█░░░░░█▀▄░█▀▀░█▀▀░█░█░█▀▄░░█░░░░░░░░░░
░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀░░░▀░▀░░▀░░▀░▀░▀▀▀░░░▀░▀░▀▀▀░▀░░░▀▀▀░▀░▀░░▀░░▀░░▀░░▀░
      """

art0 = """
░█▀▀░█░█░█▀█░█▀█░█▀▀░█▀▀░░░█▀▄░█▀█░█▄█░█▀█░▀█▀░█▀█░░░█░█░█░█▀▄░█░░
░█░░░█▀█░█▀█░█░█░█░█░█▀▀░░░█░█░█░█░█░█░█▀█░░█░░█░█░▄▀░░█░█░█▀▄░█░░
░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀▀▀░░░▀▀░░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░▀▀▀
      """

artx = """
░█▀▀░█▀█░█▀█░█▀▄░█▀▄░█░█░█▀▀░█
░█░█░█░█░█░█░█░█░█▀▄░░█░░█▀▀░▀
░▀▀▀░▀▀▀░▀▀▀░▀▀░░▀▀░░░▀░░▀▀▀░▀
      """


def display_menu():
    print("\n")
    print(artS)
    print("Now scooping: " + site)
    print("=" * 100)
    print("Choose an option to perform on Domain/URL:")
    print("1. WHOIS Information")
    print("2. DNSLOOKUP Information")
    print("3. SSL Information")
    print("4. Header Information")
    print("5. Location Information")
    print("6. Google Safe Browsing")
    print("7. Scooper ML Checker")
    print("8. Print All")
    print("9. Generate Report")
    print("0. Change Domain/URL")
    print("x. Exit")


if __name__ == "__main__":
    while True:
        print(art)
        site = input("Enter the URL to scan (e.g., example.com): ")
        if not site:
            print("Error: URL cannot be empty. Please try again.")
            continue

        if is_multi_line_input(site):
            print("Error: URL cannot be more than one line of input. Please try again.")
            continue

        # Remove any leading/trailing spaces from the input
        site = site.strip()

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

            choice = input("Enter your choice (1-9, 0 or x): ").strip()
            print("\n")

            if choice == "1":
                optionheader(art1)
                whois_raw_data = get_whois_data(site)
                whois_info = extract_whois_info(whois_raw_data)
                print(whois_info)
                optionfooter()

            elif choice == "2":
                optionheader(art2)
                dns_records = get_dns_records(site)
                print(get_dns_records(site))
                optionfooter()

            elif choice == "3":
                optionheader(art3)
                supported_versions, cert_info = scan_website_ssl(site)
                optionfooter()

            elif choice == "4":
                optionheader(art4)
                headers_dict = get_url_headers(site)
                print_headers(headers_dict)
                optionfooter()

            elif choice == "5":
                optionheader(art5)
                country, region, city, latitude, longitude = get_domain_location(site)
                print_location_info(country, region, city, latitude, longitude)
                optionfooter()

            elif choice == "6":
                optionheader(art6)
                check_url_safety(site)
                print_url_safety(site)
                optionfooter()

            elif choice == "7":
                optionheader(art7)
                mlScan(site)
                optionfooter()

            elif choice == "8":
                optionheader(art8)
                print("Generating...")

                # Option 1 Whois
                subheader(art1)
                whois_raw_data = get_whois_data(site)
                whois_info = extract_whois_info(whois_raw_data)
                print(whois_info)

                # Option 2 DNS Lookup
                subheader(art2)
                dns_records = get_dns_records(site)
                print(get_dns_records(site))

                # Option 3 SSL Scan
                subheader(art3)
                scan_website_ssl(site)
                print("-" * 100)

                # Option 4 Headers
                subheader(art4)
                headers = get_url_headers(site)
                print_headers(headers)
                print("-" * 100)

                # Option 5 Location
                subheader(art5)
                country, region, city, latitude, longitude = get_domain_location(site)
                print_location_info(country, region, city, latitude, longitude)

                # Option 6 Safe Browsing
                subheader(art6)
                print_url_safety(site)

                # # Option 7 Scooper ML
                # subheader(art7)
                # print_url_safety(site)
                # optionfooter()

            elif choice == "9":
                optionheader(art9)
                generate_html(site)
                optionfooter()

            elif choice == "0":
                optionheader(art0)
                print("Changing Site Domain/URL...")
                break

            elif choice == "x":
                optionheader(artx)
                print("Exiting...")
                exit()

            else:
                print("Invalid choice. Please select a valid option.")
