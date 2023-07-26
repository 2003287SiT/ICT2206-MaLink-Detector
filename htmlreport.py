from jinja2 import Environment, FileSystemLoader
from whois import get_whois_data, extract_whois_info
from nslookup import get_dns_records
from location import get_domain_location
from header import get_url_headers
from safebrowsing import check_url_safety
from sslinfo import scan_website_ssl
import os

if __name__ == "__main__":
    script_directory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_directory)  # Set the working directory to the script's

    domain = input("Enter the URL to scan (e.g., example.com):  ")

    print("Generating...")
    whois_raw_data = get_whois_data(domain)
    whois_info = extract_whois_info(whois_raw_data)

    # Capture SSL information in a string
    import io
    import sys
    old_stdout = sys.stdout
    sys.stdout = new_stdout = io.StringIO()
    scan_website_ssl(domain)
    sys.stdout = old_stdout
    ssl_info = new_stdout.getvalue()
    # Format the SSL information
    formatted_ssl_info = "\n".join(ssl_info.split())

    headers_info = get_url_headers(domain)
    formatted_headers_info = "\n".join(header + ":" for header in headers_info) if headers_info is not None else ""

    country, region, city, latitude, longitude = get_domain_location(domain)

    safe_browsing = check_url_safety(domain)

    dns_records = get_dns_records(domain)

    # Load the HTML template
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('template_report.html')

    # Render the template with collected data
    report = template.render(
        domain=domain,
        whois_info=whois_info,
        ssl_info=ssl_info,
        headers_info=formatted_headers_info,
        country=country,
        region=region,
        city=city,
        latitude=latitude,
        longitude=longitude,
        safe_browsing=safe_browsing,
        dns_records=dns_records
    )

    # Save the report to a file
    with open('scan_report.html', 'w') as report_file:
        report_file.write(report)

    print("Report generated successfully. Check 'scan_report.html'")
