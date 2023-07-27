import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import learning_curve
from sklearn.model_selection import train_test_split

import re
import socket
import ssl
from datetime import datetime
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


def mlScan(site):
    # Reading in csv file
    df = pd.read_csv('Training.csv')

    data = df.drop(['Result'], axis=1)
    # check if the preprocessed data without the columns below is about 92-93% accuracy
    # which is about 4% lower with completed data
    # data = df.drop(
    #    ['Result', 'URL_of_Anchor', 'SFH', 'Abnormal_URL', 'on_mouseover', "age_of_domain", "DNSRecord", "web_traffic",
    #     "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"], axis=1)

    # remove the result columns is about 96-97%
    label = df['Result']
    data2 = df.drop(['Result'], axis=1)

    # split a dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(data2, label, test_size=0.2, random_state=42)
    clf = RandomForestClassifier().fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    # accuracy = clf.score(X_test, y_test)
    # print(f"Accuracy: {accuracy}")
    #
    # '''
    # [TN FP]
    # [FN TP]
    # '''
    #
    # print("\nConfusion Matrix: ")
    # cm = confusion_matrix(y_test, y_pred)
    #
    # plt.figure()  # Create a new figure
    # sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    # plt.xlabel('Predicted label')
    # plt.ylabel('True label')
    # plt.title('Confusion Matrix')
    # plt.savefig('cm.png')
    # print("Plotted Confusion Matrix check cm.png")
    #
    # # Plot feature importances
    # feature_importances = clf.feature_importances_
    # fi = plt
    # fi.figure()
    # fi.bar(data.columns, feature_importances)
    # fi.xticks(rotation=90)
    # fi.xlabel('Features')
    # fi.ylabel('Importance')
    # fi.title('Feature Importance')
    # fi.tight_layout()
    # fi.savefig('fi.png')
    # print("Plotted Feature Importance check fi.png")
    #
    # # Calculate ROC curve and AUC
    # fpr, tpr, _ = roc_curve(y_test, y_pred)
    # roc_auc = auc(fpr, tpr)
    #
    # # Plot ROC curve
    # plt.figure()
    # plt.plot(fpr, tpr, color='blue', lw=2, label='ROC curve (AUC = %0.2f)' % roc_auc)
    # plt.plot([0, 1], [0, 1], color='gray', linestyle='--')  # Random classifier line
    # plt.xlabel('False Positive Rate')
    # plt.ylabel('True Positive Rate')
    # plt.title('ROC Curve')
    # plt.legend(loc='lower right')
    # plt.savefig('roc.png')
    # print("Plotted ROC curve check roc.png")
    #
    # # Plot learning curve
    # train_sizes, train_scores, test_scores = learning_curve(clf, data2, label, cv=5)
    # lc = plt
    # lc.figure()
    # lc.plot(train_sizes, np.mean(train_scores, axis=1), label='Training score')
    # lc.plot(train_sizes, np.mean(test_scores, axis=1), label='Cross-validation score')
    # lc.xlabel('Number of Training Examples')
    # lc.ylabel('Accuracy Score')
    # lc.title('Learning Curve')
    # lc.legend()
    # lc.savefig('lc.png')
    # print("Plotted Learning Curve check lc.png")

    response = None
    sus_links = []
    legit_links = []

    # url = www.angel-magic.com (This is the url to scan)
    url = site

    # Add default scheme (https://) if missing
    def add_default_scheme(url):
        if not url.startswith(("http://", "https://")):
            return "https://" + url
        return url

    '''
    Check URL for IP address and hexadecimal
    Example:
    http://125.98.3.123/fake.html will return -1
    http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html will return -1
    https://www.google.com/index.html will return 1
    '''

    print("Scanning for IP address in URL...")

    ip_regex = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'

    # Regex matching hexadecimal IP address
    hex_regex = r'^0x[0-9a-fA-F]{8}$'

    # Extract domain from URL
    domain_url = re.findall(r'(?<=://)[\w.-]+(?<=/)?', url)

    # Check if domain is IP address or hexadecimal
    if domain_url and (re.match(ip_regex, domain_url[0]) or re.match(hex_regex, domain_url[0])):
        having_IP_Address = -1
        sus_links.append('IP address detected in URL.')
        # print(having_IP_Address)
    else:
        having_IP_Address = 1
        legit_links.append('IP address not detected in URL.')
        # print(having_IP_Address)

    print("Finished scanning for any IP address in URL\n")

    '''
    check URL length
    Example:
    54 <= length <= 75 will return 0
    length > 75 return -1
    length < 54 will return 1
    '''

    # Default value for URL_Length
    URL_Length = 0

    # check for URL length
    print("Scanning for length of URL...")
    if 54 <= len(url) <= 75:
        URL_Length = 0
        sus_links.append(f'URL length {len(url)} detected in URL.')
        # print(URL_Length)
    elif len(url) > 75:
        URL_Length = -1
        sus_links.append(f'URL length {len(url)} detected in URL.')
        # print(URL_Length)
    elif len(url) < 54:
        URL_Length = 1
        legit_links.append(f'URL length {len(url)} detected in URL.')
        # print(URL_Length)

    print("Finished scanning for URL length.\n")

    '''
    check for URL is shortened
    Example:
    “bit.ly/19DXSk4 will return -1
    '''

    # List of shortened domains
    shortened_domains = [
        "bit.ly",
        "t.co",
        "ow.ly",
        "tinyurl.com",
        "is.gd",
        "buff.ly",
        "goo.gl",
        "shrtco.de",
        "adf.ly",
        "soo.gd",
    ]

    print("Scanning for shortened domains in URL...")

    # Regex to match the pattern of a shortened URL
    shortened_url_regex = r'^https?:\/\/(?:www\.)?(' + '|'.join(
        re.escape(domain) for domain in shortened_domains) + r')\/\S+$'

    # Check if URL matches pattern of a shortened URL
    if re.match(shortened_url_regex, url):
        Shortining_Service = -1
        sus_links.append("Shortened link detected in URL.")
        # print(Shortining_Service)
    else:
        Shortining_Service = 1
        legit_links.append("Shortened link not used in URL.")
        # print(Shortining_Service)

    print("Finished scanning URL for shortened service.\n")

    '''
    # check if URL have @ symbol
    # Example:
    https://google@youtube.com will return -1
    '''

    print("Scanning for @ symbol from URL.")
    if '@' not in url:
        having_At_Symbol = 1
        legit_links.append('@ is not detected from URL.')
        print(having_At_Symbol)

    else:
        having_At_Symbol = -1
        sus_links.append('@ is detected from URL.')
        print(having_At_Symbol)

    print("Finished scanning for @ symbol from URL.\n")

    '''
    check if URL have “//” symbol
    Example:
    https://www.google.com//https://www.phising.com will return -1.
    The url above maybe interpret as https://www.phising.com.
    '''

    print("Scanning for // symbol from URL.")
    if url.startswith("https://"):
        base_url = url.replace("https://", "", 1)
    elif url.startswith("http://"):
        base_url = url.replace("http://", "", 1)
    else:
        base_url = url

    # Regex to match any consecutive slashes followed by any URL pattern
    consecutive_slashes_regex = r'\/\/(\S+)'
    # Search for pattern from the URL
    match = re.search(consecutive_slashes_regex, base_url)

    if match:
        detected_url = match.group(1)
        double_slash_redirecting = -1
        sus_links.append("// is detected.")
        # print(double_slash_redirecting)
    else:
        double_slash_redirecting = 1
        legit_links.append(("// is not detected."))
        # print(double_slash_redirecting)

    print("Finished scanning for // symbol from URL.\n")

    '''
    Check for '-' hyphen in URL
    Example:
    https://lazada-payment.com will return -1
    '''

    print("Scanning for - symbol from URL...")

    # Regex to match hyphen "-"
    hyphen_regex = r'-'

    # Search for hyphen in the URL
    if re.search(hyphen_regex, url):
        Prefix_Suffix = -1
        sus_links.append('Hyphen detected from URL.')
        # print(Prefix_Suffix)
    else:
        Prefix_Suffix = 1
        legit_links.append('Hyphen not detected from URL.')
        # print(Prefix_Suffix)

    print("Finished scanning for hyphen symbol from URL.\n")

    '''
    check the number of sub-domains from URL
    After remove main domain and top level domain,
    If 0 <= sub domain <= 1, return 1
    If sub domain == 2, return 0
    If sub-domain == 3, return -1
    '''

    print("Counting subdomains from URL...")

    # Regex to extract subdomains from the URL
    subdomain_regex = r'((?:[a-zA-Z0-9-]+\.)+)[a-zA-Z]{2,}'

    # Search subdomains in the URL using the regex pattern
    match = re.search(subdomain_regex, url)

    if match:
        subdomains = match.group(1).strip('.').split('.')
        num_subdomains = len(subdomains)

        if num_subdomains <= 1:
            having_Sub_Domain = 1
            legit_links.append('Less than 2 sub-domains detected in URL.')
            # print(having_Sub_Domain)
        elif num_subdomains == 2:
            having_Sub_Domain = 0
            sus_links.append('2 sub-domains detected in URL.')
            # print(having_Sub_Domain)
        else:
            having_Sub_Domain = -1
            sus_links.append('More than 2 sub-domains detected in URL.')
            # print(having_Sub_Domain)
    else:
        having_Sub_Domain = 1
        legit_links.append('No sub-domains detected in URL.')
        print(having_Sub_Domain)

    print("Finished counting subdomains in URL.\n")

    '''
    check if CA is well known and trustworthy
    If CA is trusted and age of certificate >= 365 days, return 1
    If CA is trusted and age of certificate < 365 days, return 0
    If CA is not trusted, return 0
    Else, return -1
    '''

    print("Scanning for Certificate Authority...")

    def get_ssl_info(url):
        context = ssl.create_default_context()
        issuer = None
        validity_days = None

        try:
            with socket.create_connection((url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=url) as ssock:
                    cert = ssock.getpeercert()

                    # Extract issuer info and change to a dictionary
                    issuer = {}
                    for field in cert['issuer']:
                        if len(field) == 2:  # Check if the field has two elements (name and value)
                            issuer[field[0]] = field[1]

                    # Calculate certificate validity in days
                    validity_end = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    validity_days = (validity_end - datetime.now()).days
                    print("CA registration duration:", validity_days, "days")

        except (socket.gaierror, socket.timeout) as e:
            print(f"Failed to establish a connection with {url}: {e}")
        except ssl.SSLError as e:
            print(f"SSL certificate information not available for {url}: {e}")
        except Exception as e:
            print(f"An error occurred while retrieving SSL information for {url}: {e}")

        organization_name = issuer.get('organizationName') if issuer else None
        return organization_name, validity_days

    # Example usage:
    issuer, validity_days = get_ssl_info(url)

    trusted_cert_authorities = ['Let\'s Encrypt', 'Google Trust Services LLC', 'IdenTrust', 'GeoTrust', 'Thawte',
                                'Network Solutions', 'GoDaddy', 'Comodo', 'Entrust', 'Symantec', 'Verizon',
                                'GlobalSign', 'DigiCert', 'Amazon', 'Microsoft', 'Apple', 'Cisco', 'DigiCert',
                                'RapidSSL', 'SecureTrust', 'Trustwave', 'SSL.com', 'Sectigo', 'GlobalSign',
                                'AlphaSSL', 'GeoTrust', 'GlobalSign', 'QuoVadis']

    if issuer in trusted_cert_authorities and validity_days >= 365:
        SSLfinal_State = 1
        legit_links.append('Trusted CA with validity of more than a year.')
        # print(SSLfinal_State)
    elif issuer in trusted_cert_authorities and validity_days < 365:
        SSLfinal_State = 0
        sus_links.append('Trusted CA with validity of less than a year.')
        # print(SSLfinal_State)
    elif issuer not in trusted_cert_authorities:
        SSLfinal_State = 0
        sus_links.append('CA not trusted.')
        # print(SSLfinal_State)
    else:
        SSLfinal_State = -1
        sus_links.append('CA not found.')
        # print(SSLfinal_State)

    print("Finished scanning for CA\n")

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
        Domain_registeration_length = 1
        legit_links.append('Domain registration duration more than a year.')
        # print(Domain_registration_length)
    elif 0 < reg_days <= 365:
        Domain_registeration_length = -1
        sus_links.append('Domain registration duration less than a year.')
        # print(Domain_registration_length)
    else:
        Domain_registeration_length = 0
        sus_links.append('Domain registration duration not found.')
        # print(Domain_registration_length)

    print("Finished scanning for registration duration length.\n")

    '''
    Check for uncommon ports opened.
    Common ports opened:
    Port 21 (FTP),Port 22 (SSH),Port 25 (SMTP)
    Port 80 (HTTP),Port 110 (POP3),Port 143 (IMAP),
    Port 443 (HTTPS), Port 445(SMB), Port 1433(MSSQL)
    Port 1521(ORACLE), Port 3306(MySQL), Port 3389(Remote Desktop)
    Scan from port 1 to 11: (To shorten the time needed)
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

            print("Scanned port", port, end="\r")

        if uncommon_ports_count == 1:
            port = 0
            sus_links.append('1 uncommon port found opened.')
            print(port)
        elif uncommon_ports_count > 1:
            port = -1
            sus_links.append('More than 1 uncommon ports found opened.')
            # print(port)
        else:
            port = 1
            legit_links.append('Common ports found opened.')
            # print(port)

    except socket.gaierror as e:
        print(f"Error occurred while resolving URL: {e}")
        port = 0
        sus_links.append(f"Error occurred while resolving URL:{e}")
        # print(port)

    except Exception as e:
        print(f"An error occurred: {e}")
        port = 0

    print("Finished analysing ports.\n")

    '''
    Check for 'https' token in URL
    If URL starts with https://, return 1
    If URL starts with http://, return -1
    '''

    HTTPS_token = 0  # Initialize HTTPS_token with a default value
    url = add_default_scheme(url)
    print(f"Scanning for https token.")
    try:
        response = requests.get(url, timeout=10)
        if response.url.startswith("https"):
            legit_links.append(f'HTTPS in use.')
        else:
            sus_links.append(f'HTTPS not used.')
    except requests.exceptions.RequestException as e:
        sus_links.append(f'{url} - Failed to connect or HTTPS not used. Error: {str(e)}')

    print("Finished checking https token.\n")

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
                # print(Favicon)
            else:
                Favicon = 1
                legit_links.append('Favicon is loaded from the same domain as the main URL.')
                # print(Favicon)
        else:
            Favicon = 0
            sus_links.append('Favicon not found.')
            # print(Favicon)

    except requests.exceptions.RequestException as e:
        Favicon = 0
        print(f"An error occurred while fetching the URL: {e}")
    except Exception as e:
        Favicon = 0
        print(f"An error occurred during the favicon analysis: {e}")

    print("Favicon analysis completed.\n")

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
                # print(Request_URL)
            elif 0.22 <= external_count / total_urls <= 0.61:
                Request_URL = 0
                sus_links.append('Significant number of tags loaded from external domains.')
                # print(Request_URL)
            else:
                Request_URL = -1
                sus_links.append('Most tags loaded from external domains.')
                # print(Request_URL)

    except:
        Request_URL = 0
        sus_links.append('Tags not determined.')
        # print(Request_URL)

    finally:
        print("Finished analysing tags.\n")

    '''
    # # Checking if submitting information to email
    # # if mail() or mailto: function detected return -1
    # # else 1
    '''

    try:
        url = add_default_scheme(url)  # Add default scheme (https://) if missing
        response = requests.get(url)
        content = response.text

        if 'mail(' in content or 'mailto:' in content:
            Submission_to_email = -1
            sus_links.append('Using "mail()" or "mailto:" function to submit user information.')
            # print(submitting_to_email)
        else:
            Submission_to_email = 1
            legit_links.append('No evidence of using "mail()" or "mailto:" function to submit user information.')
            # print(email_submission)

    except requests.exceptions.RequestException as e:
        Submission_to_email = 0
        sus_links.append('Error occurred during request: ' + str(e))
    except Exception as e:
        Submission_to_email = 0
        sus_links.append('Error occurred during analysis of email submission: ' + str(e))

    print("Finished analyzing email submission.\n")

    '''
    check how many times the website is redirected
    If the number of redirects <= 1, return 1
    If the number of redirects >= 2 And < 4, return 0
    Else, return -1
    '''
    redirect_count = 0
    max_redirects = 5  # Set a maximum number of allowed redirects

    url = add_default_scheme(url)

    print("Scanning  for number of redirects...")
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
        # print(Redirect)
    elif 2 <= redirect_count < 4:
        Redirect = 0
        sus_links.append('More than 1 redirect detected.')
        # print(Redirect)
    else:
        Redirect = -1
        sus_links.append('More than 3 redirects detected.')
        # print(Redirect)

    print("Finished looking at redirects.\n")

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
            # print(RightClick)
        else:
            RightClick = 1
            legit_links.append('Right-click event.button==2 not found.')
            # print(RightClick)
    except:
        RightClick = 0
        sus_links.append('Right-click event not detectable.')
        # print(RightClick)

    print("Finished scanning for right-click events.\n")

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
            popUpWidnow = -1
            sus_links.append('Pop-up windows detected.')
            # print(popUpWindow)
        else:
            popUpWidnow = 1
            legit_links.append('No pop-up windows detected.')
            # print(popUpWindow)
    except Exception as e:
        popUpWidnow = 0
        sus_links.append('Error occurred during pop-up detection: ' + str(e))
        # print(popUpWidnow)

    print("Finished scanning for pop-up events.\n")

    '''
    Check if iframe tag is used to create an invisible frame
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
            # print(Iframe)
        else:
            legit_links.append("No iframe tag detected.")
            Iframe = 1
            # print(Iframe)

    except requests.exceptions.RequestException as e:
        print(f"Error occurred during request: {e}")
        Iframe = 0
    except Exception as e:
        print(f"Error occurred during iframe detection: {e}")
        Iframe = 0
    print("Finished scanning for iframe.\n")

    data_dict = {
        'having_IP_Address': [having_IP_Address],
        'URL_Length': [URL_Length],
        'Shortining_Service': [Shortining_Service],
        'having_At_Symbol': [having_At_Symbol],
        'double_slash_redirecting': [double_slash_redirecting],
        'Prefix_Suffix': [Prefix_Suffix],
        'having_Sub_Domain': [having_Sub_Domain],
        'SSLfinal_State': [SSLfinal_State],
        'Domain_registeration_length': [Domain_registeration_length],
        'Favicon': [Favicon],
        'port': [port],
        'HTTPS_token': [HTTPS_token],
        'Request_URL': [Request_URL],
        'Submitting_to_email': [Submission_to_email],
        'Redirect': [Redirect],
        'RightClick': [RightClick],
        'popUpWidnow': [popUpWidnow],
        'Iframe': [Iframe]
    }

    urlData = pd.DataFrame(data_dict)

    print("\nSafe Attribute:")
    for link in legit_links:
        print(link)

    print("\nSuspicious Attribute:")
    for link in sus_links:
        print(link)

    prediction = clf.predict(urlData)
    if prediction[0] == 1:
        print(f"\nThe website {url} is " + "Safe.\n")
    else:
        print(f"\nThe website {url} is " + "Suspicious.\n")



