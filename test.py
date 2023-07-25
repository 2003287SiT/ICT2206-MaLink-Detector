import re
import socket
import ssl
from datetime import datetime
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

response = None
# list of suspicious features/characteristics
sus_links = []

# list of legitimate features/characteristics
legit_links = []

url = "www.w3schools.com/html/html_iframe.asp"


# Add default scheme (https://) if missing
def add_default_scheme(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


# Check URL for IP address and hexadecimal)
# Example:
# http://123.12.12.321/phising.html will return -1
# https://0x7f123456/index.html will return -1
# https://www.google.com/index.html will return 1
# Regular expression to match an IP address
# print("Scanning for IP address in URL...")
#
# ip_regex = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
#
# # Regular expression to match a hexadecimal IP address
# hex_regex = r'^0x[0-9a-fA-F]{8}$'
#
# # Extract the domain from the URL
# domain_url = re.findall(r'(?<=://)[\w.-]+(?<=/)?', url)
#
# # Check if the domain is an IP address or a hexadecimal IP address
# if domain_url and (re.match(ip_regex, domain_url[0]) or re.match(hex_regex, domain_url[0])):
#     having_IP_Address = -1
#     sus_links.append('IP address detected in URL.')
#     print(having_IP_Address)
# else:
#     having_IP_Address = 1
#     legit_links.append('IP address not detected in URL.')
#     print(having_IP_Address)
#
# print("Scanning for any IP address in URL completed.\n")
#
# # check URL length
# # Example:
# # 54 <= length <= 75 will return 0
# # length > 75 return -1
# # length < 54 will return 1
#
# print("Scanning for length of URL...")
# if 54 <= len(url) <= 75:
#     URL_length = 0
#     sus_links.append(f'URL length {len(url)} detected in URL.')
#     print(URL_length)
# elif len(url) > 75:
#     URL_length = -1
#     sus_links.append(f'URL length {len(url)} detected in URL.')
#     print(URL_length)
# elif len(url) < 54:
#     URL_length = 1
#     legit_links.append(f'URL length {len(url)} detected in URL.')
#     print(URL_length)
#
#     print("Completed scanning for URL length.\n")
# #
# # check for URL is shortened
# # Example:
# # bit.ly/19DXSk4 will return -1
#
# # List of shortened domains
# shortened_domains = [
#     "bit.ly",
#     "t.co",
#     "ow.ly",
#     "tinyurl.com",
#     "is.gd",
#     "buff.ly",
#     "goo.gl",
#     "shrtco.de",
#     "adf.ly",
#     "soo.gd",
# ]
#
# print("Scanning for shortened domains in URL...")
#
# # Regular expression to match the pattern of a shortened URL
# shortened_url_regex = r'^https?:\/\/(?:www\.)?(' + '|'.join(
#     re.escape(domain) for domain in shortened_domains) + r')\/\S+$'
#
# # Check if the URL matches the pattern of a shortened URL
# if re.match(shortened_url_regex, url):
#     Shortening_Service = -1
#     sus_links.append("Shortened link detected in URL.")
#     print(Shortening_Service)
# else:
#     Shortening_Service = 1
#     legit_links.append("Shortened link not used in URL.")
#     print(Shortening_Service)
#
# print("Completed scanning URL for shortened service.\n")
#
# # check whether URL have @ symbol
# # Example:
# # https://google@youtube.com will return -1
#
# print("Scanning for @ symbol from URL.")
# if '@' not in url:
#     having_Symbol = 1
#     legit_links.append('@ is not detected from URL.')
#     print(having_Symbol)
#
# else:
#     having_Symbol = -1
#     sus_links.append('@ is detected from URL.')
#     print(having_Symbol)
#
# print("Completed scanning for @ symbol from URL.\n")
# #
# # check whether URL have “//” symbol
# # Example:
# # https://www.google.com//https://www.phising.com will return -1.
# # The url above maybe interpret as https://www.phising.com.
#
# print("Scanning for // symbol from URL.")
# if url.startswith("https://"):
#     base_url = url.replace("https://", "", 1)
# elif url.startswith("http://"):
#     base_url = url.replace("http://", "", 1)
# else:
#     base_url = url
#
# # Regular expression to match any consecutive slashes followed by any URL pattern
# consecutive_slashes_regex = r'\/\/(\S+)'
# # Search for the pattern in the URL
# match = re.search(consecutive_slashes_regex, base_url)
#
# if match:
#     detected_url = match.group(1)
#     double_slash_redirecting = -1
#     sus_links.append("// is detected.")
#     print(double_slash_redirecting)
# else:
#     double_slash_redirecting = 1
#     legit_links.append(("// is not detected."))
#     print(double_slash_redirecting)
#
# print("Completed scanning for // symbol from URL.\n")
#
# # check for '-' hyphen in URL
# # Example:
# # https://lazada-payment.com will return -1
#
# print("Scanning for - symbol from URL...")
#
# # Regular expression to match a hyphen "-"
# hyphen_regex = r'-'
#
# # Search for the hyphen in the URL
# if re.search(hyphen_regex, url):
#     Prefix_Suffix = -1
#     sus_links.append('Hyphen detected from URL.')
#     print(Prefix_Suffix)
# else:
#     Prefix_Suffix = 1
#     legit_links.append('Hyphen not detected from URL.')
#     print(Prefix_Suffix)
#
# print("Completed scanning for hyphen symbol from URL.\n")
# #
# # check the number of sub-domains from URL
# # After remove main domain and top level domain,
# # If 0 <= sub domain <= 1, return 1
# # If sub domain == 2, return 0
# # If sub-domain == 3, return -1
#
# # # Sample URL for testing
#
#
# print("Counting subdomains from URL...")
#
# # Regular expression to extract the subdomains from the URL
# subdomain_regex = r'((?:[a-zA-Z0-9-]+\.)+)[a-zA-Z]{2,}'
#
# # Search for subdomains in the URL using the regex pattern
# match = re.search(subdomain_regex, url)
#
# if match:
#     subdomains = match.group(1).strip('.').split('.')
#     num_subdomains = len(subdomains)
#
#     if num_subdomains <= 1:
#         having_SubDomain = 1
#         legit_links.append('Less than 2 sub-domains detected in URL.')
#         print(having_SubDomain)
#     elif num_subdomains == 2:
#         having_SubDomain = 0
#         sus_links.append('2 sub-domains detected in URL.')
#         print(having_SubDomain)
#     else:
#         having_SubDomain = -1
#         sus_links.append('More than 2 sub-domains detected in URL.')
#         print(having_SubDomain)
# else:
#     having_SubDomain = 1
#     legit_links.append('No sub-domains detected in URL.')
#     print(having_SubDomain)
#
# print("Finished counting subdomains in URL.\n")
# #
# # #
# # # check if CA is well known and trustworthy
# # # If CA is trusted and age of certificate >= 365 days, return 1
# # # If CA is trusted and age of certificate < 365 days, return 0
# # # If CA is not trusted, return 0
# # # Else, return -1
# #
# print("Checking for Certificate Authority...")
#
#
# def get_ssl_info(url):
#     context = ssl.create_default_context()
#     issuer = None
#     validity_days = None
#
#     try:
#         with socket.create_connection((url, 443)) as sock:
#             with context.wrap_socket(sock, server_hostname=url) as ssock:
#                 cert = ssock.getpeercert()
#
#                 # Extract issuer information and convert to a dictionary
#                 issuer = {}
#                 for field in cert['issuer']:
#                     if len(field) == 2:  # Check if the field has two elements (name and value)
#                         issuer[field[0]] = field[1]
#
#                 # Calculate certificate validity in days
#                 validity_end = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
#                 validity_days = (validity_end - datetime.now()).days
#                 print("CA registration duration:", validity_days, "days")
#
#     except (socket.gaierror, socket.timeout) as e:
#         print(f"Failed to establish a connection with {url}: {e}")
#     except ssl.SSLError as e:
#         print(f"SSL certificate information not available for {url}: {e}")
#     except Exception as e:
#         print(f"An error occurred while retrieving SSL information for {url}: {e}")
#
#     organization_name = issuer.get('organizationName') if issuer else None
#     return organization_name, validity_days
#
#
# # Example usage:
# issuer, validity_days = get_ssl_info(url)
#
# trusted_cert_authorities = ['Let\'s Encrypt', 'Google Trust Services LLC', 'IdenTrust', 'GeoTrust', 'Thawte',
#                             'Network Solutions', 'GoDaddy', 'Comodo', 'Entrust', 'Symantec', 'Verizon',
#                             'GlobalSign', 'DigiCert', 'Amazon', 'Microsoft', 'Apple', 'Cisco', 'DigiCert',
#                             'RapidSSL', 'SecureTrust', 'Trustwave', 'SSL.com', 'Sectigo', 'GlobalSign',
#                             'AlphaSSL', 'GeoTrust', 'GlobalSign', 'QuoVadis']
#
# if issuer in trusted_cert_authorities and validity_days >= 365:
#     SSLfinal_State = 1
#     legit_links.append('Trusted CA with validity of more than a year.')
#     print(SSLfinal_State)
# elif issuer in trusted_cert_authorities and validity_days < 365:
#     SSLfinal_State = 0
#     sus_links.append('Trusted CA with validity of less than a year.')
#     print(SSLfinal_State)
# elif issuer not in trusted_cert_authorities:
#     SSLfinal_State = 0
#     sus_links.append('CA not trusted.')
#     print(SSLfinal_State)
# else:
#     SSLfinal_State = -1
#     sus_links.append('CA not found.')
#     print(SSLfinal_State)
#
# print("Finished scanning for CA")

'''
Check domain registration duration of URL
If domain registration duration > 365 days, return 1
If domain registration duration is none(info not extracted), return 0
If domain registration duration <= 365 days, return -1
'''

print("Starting scanning for Domain registration duration")


def query_whois(domain, server="whois.iana.org", port=43):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server, port))
        query = f"{domain}\r\n"
        s.sendall(query.encode())

        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data

    return response.decode()


def extract_dates(whois_response):
    creation_date = None
    current_date = None

    date_field_labels = ["created", "changed"]  # Change the label to "changed"
    for line in whois_response.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            if key in date_field_labels:
                try:
                    date_format = "%Y-%m-%d"  # Format without time
                    if key == "created":
                        creation_date = datetime.strptime(value, date_format)
                    elif key == "changed":
                        current_date = datetime.strptime(value, date_format)
                except ValueError:
                    pass  # If date format does not match, continue searching

    return creation_date, current_date


def get_domain_reg_duration(url):
    try:
        whois_response = query_whois(url)

        creation_date, current_date = extract_dates(whois_response)

        if creation_date and current_date:
            duration = current_date - creation_date
            return duration.days
        else:
            return None

    except Exception as e:
        print(f"An error occurred while querying WHOIS information: {e}")
        return None


# Example usage:
reg_duration = get_domain_reg_duration(url)
if reg_duration is None:
    reg_duration = 0
reg_days = int(reg_duration)
print("Domain registration duration:", reg_days, "days")

if reg_days > 365:
    Domain_registration_length = 1
    legit_links.append('Domain registration duration more than a year.')
    print(Domain_registration_length)
elif 0 < reg_days <= 365:
    Domain_registration_length = -1
    sus_links.append('Domain registration duration less than a year.')
    print(Domain_registration_length)
else:
    Domain_registration_length = 0
    sus_links.append('Domain registration duration not found.')
    print(Domain_registration_length)

print("Finished scanning for registration duration length.")

'''
Check for uncommon ports opened by the website.
Common ports opened:
Port 21 (FTP),Port 22 (SSH),Port 25 (SMTP)
Port 80 (HTTP),Port 110 (POP3),Port 143 (IMAP),
Port 443 (HTTPS), Port 445(SMB), Port 1433(MSSQL)
Port 1521(ORACLE), Port 3306(MySQL), Port 3389(Remote Desktop)
Scan from port 1 to 600:
If uncommon_ports_count == 1, return 0
If uncommon_ports_count > 1, return -1
Else, return 
'''

print("Start analyzing ports")

# list of common ports used
website_ports = [21, 22, 25, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389]

try:
    ip_address = socket.gethostbyname(url)
    print("Scanning ports for", url, "(", ip_address, ")")

    uncommon_ports_count = 0

    for port in range(1, 11):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            if port not in website_ports:
                uncommon_ports_count += 1
        sock.close()

        # Print out progress message
        print("Scanned port", port, end="\r")

    if uncommon_ports_count == 1:
        port_status = 0
        sus_links.append('1 uncommon port found opened.')
        print(port_status)
    elif uncommon_ports_count > 1:
        port_status = -1
        sus_links.append('More than 1 uncommon ports found opened.')
        print(port_status)
    else:
        port_status = 1
        legit_links.append('Common ports found opened.')
        print(port_status)

except socket.gaierror as e:
    print(f"Error occurred while resolving URL: {e}")
    port_status = 0
    sus_links.append(f"Error occurred while resolving URL:{e}")
    print(port_status)

except Exception as e:
    print(f"An error occurred: {e}")
    port_status = 0

print("Finished analysing ports.")

'''
check favicon for URL
If favicon is loading from external domain, return -1
If favicon is loading from internal domain, return 1
Else, return 0
'''

print("Checking for Favicon")

try:
    url = add_default_scheme(url)
    response = requests.get(url)
    response.raise_for_status()

    favicon_url = None

    # Check response headers for favicon link
    favicon_link = response.headers.get('link', None)
    if favicon_link:
        if 'icon' in favicon_link.lower():
            favicon_url = favicon_link.split(';')[0].strip('<>')

    # If favicon link not found in headers, parse HTML to find it
    if not favicon_url:
        soup = BeautifulSoup(response.content, 'html.parser')
        favicon_link_tags = soup.find_all('link', rel=['icon', 'shortcut icon'])
        if favicon_link_tags:
            favicon_url = favicon_link_tags[0].get('href', None)

    if favicon_url:
        parsed_url = urlparse(url)
        parsed_favicon_url = urlparse(urljoin(url, favicon_url))

        if parsed_url.netloc != parsed_favicon_url.netloc:
            Favicon = -1
            sus_links.append('Favicon is loaded from an external domain.')
            print(Favicon)
        else:
            Favicon = 1
            legit_links.append('Favicon is loaded from the same domain as the main URL.')
            print(Favicon)
    else:
        Favicon = 0
        sus_links.append('Favicon not found.')
        print(Favicon)

except requests.exceptions.RequestException as e:
    Favicon = 0
    print(f"An error occurred while fetching the URL: {e}")
except Exception as e:
    Favicon = 0
    print(f"An error occurred during the favicon analysis: {e}")

print("Favicon analysis completed.")

'''
check if the tags in the webpage are loading from external domains.
If < 0.22 of tags loading in external domains, return 1
If 0.22 <= tags <= 0.61 loading in external domains, return 0
Else, return 1
'''

print("Scanning for tags...")

try:
    response = requests.get(url)
    if response.status_code == 200:
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')

        # Find all URLs in the content
        external_urls = [link.get('href') for link in soup.find_all('a', href=True)]
        parsed_url = urlparse(url)
        total_urls = len(external_urls)
        external_count = 0

        for external_url in external_urls:
            parsed_external_url = urlparse(external_url)
            if parsed_external_url.netloc != parsed_url.netloc:
                external_count += 1

    if external_count / total_urls < 0.22:
        Request_URL = 1
        legit_links.append('Most tags loaded internally.')
        print(Request_URL)
    elif 0.22 <= external_count / total_urls <= 0.61:
        Request_URL = 0
        sus_links.append('Significant number of tags loaded from external domains.')
        print(Request_URL)
    else:
        Request_URL = -1
        sus_links.append('Most tags loaded from external domains.')
        print(Request_URL)

except ZeroDivisionError:
    Request_URL = 0
    sus_links.append('No tags found.')
    print(Request_URL)

except:
    Request_URL = 0
    sus_links.append('Tags not determined.')
    print(Request_URL)

else:
    Request_URL = 0
    sus_links.append('Tags not determined.')
    print(Request_URL)

finally:
    print("Finished analysing tags.")

'''
# # Checking submitting information to email
# # if mail() or mailto: function detected return -1
# # else 1
'''

try:
    url = add_default_scheme(url)  # Add default scheme (https://) if missing
    response = requests.get(url)
    content = response.text

    if 'mail(' in content or 'mailto:' in content:
        email_submission = -1
        sus_links.append('Using "mail()" or "mailto:" function to submit user information.')
        print(email_submission)
    else:
        email_submission = 1
        legit_links.append('No evidence of using "mail()" or "mailto:" function to submit user information.')
        print(email_submission)

except requests.exceptions.RequestException as e:
    email_submission = 0
    sus_links.append('Error occurred during request: ' + str(e))
except Exception as e:
    email_submission = 0
    sus_links.append('Error occurred during analysis of email submission: ' + str(e))

print("Finished analyzing email submission.")

'''
check how many times the website is redirected
If the number of redirects <= 1, return 1
If the number of redirects >= 2 And < 4, return 0
Else, return -1
'''
redirect_count = 0
max_redirects = 5  # Set a maximum number of allowed redirects

url = add_default_scheme(url)

print("Looking at number of redirects...")
for _ in range(max_redirects):
    try:
        response = requests.get(url)
        if response.history:
            url = response.url
            redirect_count += 1
            print("redirect count:", redirect_count)
        else:
            break  # No more redirects, exit the loop
    except requests.exceptions.RequestException as e:
        print("Error occurred:", e)
        break  # Handle exceptions and exit the loop

if redirect_count <= 1:
    Redirect = 1
    sus_links.append('Less than 2 redirects detected.')
    print(Redirect)
elif 2 <= redirect_count < 4:
    Redirect = 0
    sus_links.append('More than 1 redirect detected.')
    print(Redirect)
else:
    Redirect = -1
    sus_links.append('More than 3 redirects detected.')
    print(Redirect)

print("Finished looking at redirects.")

'''
Check if right-click is disabled in the website
Look for event.button==2 in web source code
When right-click is disabled, return -1
Else, return 1
'''

print("Scanning for right-click events.")
try:
    html = response.text
    if "event.button==2" in html:
        RightClick = -1
        sus_links.append('Right-click event.button==2 found.')
        print(RightClick)
    else:
        RightClick = 1
        legit_links.append('Right-click event.button==2 not found.')
        print(RightClick)
except:
    RightClick = 0
    sus_links.append('Right-click event not detectable.')
    print(RightClick)

print("Finished scanning for right-click events.")

'''
Check if there is any popup windows in the website
If there is popups, return -1
Else, return 1
'''

print("Scanning for pop up events.")
try:
    soup = BeautifulSoup(response.content, 'html.parser')

    pop_up_functions = ['window.open', 'showModalDialog', 'showModelessDialog']
    pop_up_text = []

    for tag in soup.find_all(onclick=True):
        onclick = tag['onclick']
        for func in pop_up_functions:
            if func in onclick:
                pop_up_text.append(tag.text)
                break

    if pop_up_text:
        popUpWindow = -1
        sus_links.append('Pop-up windows detected.')
        print(popUpWindow)
    else:
        popUpWindow = 1
        legit_links.append('No pop-up windows detected.')
        print(popUpWindow)
except Exception as e:
    popUpWindow = 0
    sus_links.append('Error occurred during pop-up detection: ' + str(e))
    print(popUpWindow)
print("Finished scanning for pop-up events.")

'''
Check whether iframe tag is used to create an invisible frame
If iframe is used, return -1
Else, return 1
User might keep malicious invisible frame.
'''

print("scanning for iframe...")
try:
    url = add_default_scheme(url)
    response = requests.get(url)
    response.raise_for_status()  # Check for request success (HTTP status code 200)

    html = response.content
    soup = BeautifulSoup(html, 'html.parser')

    iframe_tags = soup.find_all('iframe')
    if iframe_tags:
        sus_links.append("Iframe tag(s) detected.")
        Iframe = -1
        print(Iframe)
    else:
        legit_links.append("No iframe tag detected.")
        Iframe = 1
        print(Iframe)

except requests.exceptions.RequestException as e:
    print(f"Error occurred during request: {e}")
    Iframe = 0
except Exception as e:
    print(f"Error occurred during iframe detection: {e}")
    Iframe = 0
print("Finished scanning for iframe")

print("Sus:", sus_links)
print("Legit:", legit_links)
