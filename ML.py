import datetime
import ssl
from urllib.parse import urljoin, urlparse
import re
import socket
import requests

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pythonwhois
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import learning_curve
from sklearn.model_selection import train_test_split


def MachineLearning(url):
    # Reading in csv file
    df = pd.read_csv('csv_file.csv')

    # Preprocess
    label = df['Result']
    data = df.drop(['Result'], axis=1)

    # split a dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(data, label, test_size=0.2, random_state=42)
    clf = RandomForestClassifier().fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    accuracy = clf.score(X_test, y_test)
    print(f"Accuracy: {accuracy}")

    '''
    [TN FP]
    [FN TP]
    '''

    print("\nConfusion Matrix: ")
    cm = confusion_matrix(y_test, y_pred)

    cm = plt
    cm.figure()
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    cm.xlabel('Predicted label')
    cm.ylabel('True label')
    cm.title('Confusion Matrix')
    cm.savefig('confusion_matrix.png')
    print("Plotting Confusion Matrix.")

    # Calculate ROC curve and AUC
    fpr, tpr, _ = roc_curve(y_test, y_pred)
    roc_auc = auc(fpr, tpr)

    # Plot ROC curve
    plt.figure()
    plt.plot(fpr, tpr, color='blue', lw=2, label='ROC curve (AUC = %0.2f)' % roc_auc)
    plt.plot([0, 1], [0, 1], color='gray', linestyle='--')  # Random classifier line
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend(loc='lower right')
    plt.savefig('roc.png')
    print("Plotting ROC curve.")

    # Plot feature importances
    feature_importances = clf.feature_importances_
    fi = plt
    fi.figure()
    fi.bar(data.columns, feature_importances)
    fi.xticks(rotation=90)
    fi.xlabel('Features')
    fi.ylabel('Importance')
    fi.title('Feature Importance')
    fi.tight_layout()
    fi.savefig('feature_importance.png')
    print("Plotting Feature Importance.")

    # Plot learning curve
    train_sizes, train_scores, test_scores = learning_curve(clf, data, label, cv=5)
    lc = plt
    lc.figure()
    lc.plot(train_sizes, np.mean(train_scores, axis=1), label='Training score')
    lc.plot(train_sizes, np.mean(test_scores, axis=1), label='Cross-validation score')
    lc.xlabel('Number of Training Examples')
    lc.ylabel('Accuracy Score')
    lc.title('Learning Curve')
    lc.legend()
    lc.savefig('learning_curve.png')
    print("Plotting Learning Curve.")

    # Data Preprocessing

    '''
    -1: Phishing,0: Suspicious,1: Legitimate
    '''

    # Get user input
    domain = url
    if domain.startswith("https://"):
        domain = domain[len("https://"):]
    elif domain.startswith("http://"):
        domain = domain[len("http://"):]
    if domain.startswith("www."):
        domain = domain[len("www."):]

    # Extracting the domain without any prefixes
    # For example, "https://www.example.com" will be converted to "example.com"

    response = None
    # list of suspicious features/characteristics
    sus_links = []

    # list of legitimate features/characteristics
    legit_links = []

    try:
        response = requests.get(url)
    except:
        pass

    # Check URL for IP address and hexadecimal)
    # Example:
    # http://123.12.12.321/phising.html will return -1
    # https://0x7f123456/index.html will return -1
    # https://www.google.com/index.html will return 1

    # try:
    print("Scanning IP address in URL...")

    # Regex to match a domain in a URL
    domain_regex = r'(?<=://)([^/]+)'

    # Extract the domain from the URL
    domain_match = re.search(domain_regex, url)
    if domain_match:
        domain_url = domain_match.group(1)

        # Regex to match an IP address
        ip_regex = r'^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[' \
                   r'01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$ '

        # Regex to match a hexadecimal
        hex_regex = r'^0x[0-9a-fA-F]{8}$'

        # Check if the domain is an IP address or a hexadecimal IP address
        if re.match(ip_regex, domain_url) or re.match(hex_regex, domain_url):
            having_IP_Address = -1
            sus_links.append('IP address detected from URL.')
        else:
            having_IP_Address = 1
            sus_links.append('IP address not detected from URL.')

        print("Scanning IP address in URL completed.")

        # check URL length
        # Example:
        # 54 <= length <= 75 will return 0
        # length > 75 return -1
        # length < 54 will return 1

        print("Looking at length of URL...")
        if 54 <= len(url) <= 75:
            URL_len = 0
            sus_links.append(f'URL length {len(url)} detected in URL.')
        elif len(url) > 75:
            URL_len = -1
            sus_links.append(f'URL length {len(url)} detected in URL.')
        elif len(url) < 54:
            URL_len = 1
            legit_links.append(f'URL length {len(url)} detected in URL.')

        print("Finished looking for URL length")

        # check for URL is shortened
        # Example:
        # https://bit.ly/2e4Sdsd will return -1

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

        print("Checking for shortened domains in URL...")
        has_shortened_domain = any(shorturl in url for shorturl in shortened_domains)
        if has_shortened_domain:
            Shortining_URL = -1
            sus_links.append('Shorten link detected in URL.')
        else:
            Shortining_URL = 1
            legit_links.append('Shorten link not used in URL.')

        print("Finished scanning URL for shortened service.")

        # check whether URL have @ symbol
        # Example:
        # https://google@youtube.com will return -1

        print("Scanning for @ symbol from URL.")
        if '@' not in url:
            having_Symbol = 1
            legit_links.append('@ is not detected from URL.')
        else:
            having_Symbol = -1
            sus_links.append('@ is detected from URL.')

        print("Finished scanning for @ symbol from URL.")

        # check whether URL have “//” symbol
        # Example:
        # https://www.google.com//https://www.phising.com will return -1.
        # The url above might interpret as https://www.phising.com.

        print("Scanning for // symbol from URL.")
        if url.startswith("https://"):
            base_url = url.replace("https://", "", 1)
        elif url.startswith("http://"):
            base_url = url.replace("http://", "", 1)
        else:
            base_url = url

        # Regular expression to match any consecutive slashes followed by any URL pattern
        consecutive_slashes_regex = r'\/\/(\S+)'
        # Search for the pattern in the URL
        match = re.search(consecutive_slashes_regex, base_url)

        if match:
            detected_url = match.group(1)
            double_slash_symbol = -1
        else:
            double_slash_symbol = 1

        print("Finished scanning for // symbol from URL.")

        # check for '-' hyphen in URL
        # Example:
        # https://lazada-payment.com will return -1

        print("Scanning for - symbol from URL...")

        # Regular expression to match a hyphen "-"
        hyphen_regex = r'-'

        # Search for the hyphen in the URL
        if re.search(hyphen_regex, url):
            Prefix_Suffix = -1
            sus_links.append('Hyphen detected from URL.')
        else:
            Prefix_Suffix = 1
            legit_links.append('Hyphen not detected from URL.')

        print("Finished scanning for hyphen symbol from URL.")

        # check the number of sub-domains from URL
        # After remove main domain and top level domain,
        # If 0 <= sub domain <= 1, return 1
        # If sub domain == 2, return 0
        # If sub-domain == 3, return -1

        # Sample URL for testing
        url = "https://www.subdomain1.subdomain2.example.com"

        print("Counting subdomains in URL...")

        # Regular expression to extract the subdomains from the URL
        subdomain_regex = r'((?:[a-zA-Z0-9-]+\.)+)[a-zA-Z]{2,}'

        # Search for subdomains in the URL using the regex pattern
        match = re.search(subdomain_regex, url)

        if match:
            subdomains = match.group(1).strip('.').split('.')
            num_subdomains = len(subdomains)

            if num_subdomains <= 1:
                having_SubDomain = 1
                legit_links.append('Less than 2 sub-domains detected in URL.')
            elif num_subdomains == 2:
                having_SubDomain = 0
                sus_links.append('2 sub-domains detected in URL.')
            else:
                having_SubDomain = -1
                sus_links.append('More than 2 sub-domains detected in URL.')
        else:
            having_SubDomain = 1
            legit_links.append('No sub-domains detected in URL.')

        print("Finished counting subdomains in URL.")

        # check whether CA is well known and trustworthy
        # If CA is trusted and age of certificate >= 365 days, return 1
        # If CA is trusted and age of certificate < 365 days, return 1
        # If CA is not trusted, return 1
        # Else, return -1

        print("Checking Certificate Authority...")

        def get_sslinfo(url):
            context = ssl.create_default_context()

            try:
                with socket.create_connection((url, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=url) as ssock:
                        cert = ssock.getpeercert()

                        # Extract issuer information and convert to a dictionary
                        issuer = {}
                        for item in cert['issuer']:
                            issuer[item[0]] = item[1]

                        # Calculate certificate validity in days
                        validity_end = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        validity_days = (validity_end - datetime.datetime.now()).days

                        return issuer.get('organizationName', None), validity_days

            except (socket.gaierror, socket.timeout):
                print(f"Failed to establish a connection with {url}.")
                return None, None

            except ssl.SSLError:
                print(f"SSL certificate information not available for {url}.")
                return None, None

            except Exception as e:
                print(f"An error occurred while retrieving SSL information: {e}")
                return None, None

        # # Test the function with a sample URL
        # url = "www.example.com"
        # organization_name, validity_days = get_ssl_info(url)
        # if organization_name and validity_days:
        #     print(f"Organization Name: {organization_name}")
        #     print(f"Validity Days: {validity_days}")
        # else:
        #     print("SSL information not available for the given URL.")

        issuer, validity_days = get_sslinfo('google.com')

        trusted_cert_authorities = ['DigiCert', 'GlobalSign', 'Comodo', 'GeoTrust', 'Entrust', 'GoDaddy', 'Let Encrypt',
                                    'Thawte', 'Symantec', 'Verisign',
                                    'Google Trust Services LLC']

        if issuer in trusted_cert_authorities and validity_days >= 365:
            SSL_State = 1
            legit_links.append('Trusted CA with validity of more than a year.')

        elif issuer in trusted_cert_authorities and validity_days <= 365:
            SSL_State = 0
            sus_links.append('Trusted CA with validity of less than a year.')

        elif issuer not in trusted_cert_authorities:
            SSL_State = 0
            sus_links.append('CA not trusted.')
        else:
            SSL_State = -1
            sus_links.append('CA not found.')

        # Check domain registration duration of URL
        # If domain registration duration > 365 days, return 1
        # If domain registration duration is none(info not extracted), return 0
        # If domain registration duration <= 365 days, return -1

        def get_domain_reg_duration(url):
            try:
                domain_info = pythonwhois.whois(url)

                # Extract creation and expiration dates
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                expiration_date = domain_info.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]

                # Calculate duration if both dates are available
                if creation_date and expiration_date:
                    duration = expiration_date - creation_date
                    return duration.days
                else:
                    return None  # Return None if either date is missing

            except Exception as e:
                print(f"An error occurred while querying WHOIS information: {e}")
                return None  # Return None for failed queries

        # # Test the function with a sample URL
        # url = "example.com"
        # registration_duration = get_domain_registration_duration(url)
        # if registration_duration is not None:
        #     print(f"Domain Registration Duration: {registration_duration} days")
        # else:
        #     print("Domain registration duration could not be determined.")

        try:
            reg_duration = get_domain_reg_duration(url)
            if reg_duration is None:
                reg_duration = 0
            reg_days = int(reg_duration)

            print("Domain registration duration:", reg_days, "days")
            if reg_days > 365:
                Domain_reg_length = 1
                legit_links.append('Domain registration duration more than a year.')
            elif 0 < reg_days <= 365:
                Domain_reg_length = -1
                sus_links.append('Domain registration duration less than a year.')
            else:
                Domain_reg_length = 0
                sus_links.append('Domain registration duration not found.')
        except:
            Domain_reg_length = 0
            sus_links.append('Domain registration duration not found.')

            # check favicon of URL
            # If favicon is loading from external domain, return -1
            # If favicon is loading from internal domain, return 1
            # Else, return 0

            try:
                response = requests.head(url)
                response.raise_for_status()  # Check for request success (HTTP status code 200)

                favicon_url = None
                favicon_link = response.headers.get('link', None)

                if favicon_link:
                    if 'icon' in favicon_link.lower():
                        favicon_url = favicon_link.split(';')[0].strip('<>')

                if favicon_url:
                    parsed_url = urlparse(url)
                    parsed_favicon_url = urlparse(urljoin(url, favicon_url))

                    if parsed_url.netloc != parsed_favicon_url.netloc:
                        Favicon = -1
                        print('Favicon is loaded from an external domain.')
                    else:
                        Favicon = 1
                        print('Favicon is loaded from the same domain as the main URL.')
                else:
                    Favicon = 0
                    print('Favicon not found in the response headers.')

            except requests.exceptions.RequestException as e:
                Favicon = 0
                print(f"An error occurred while fetching the URL: {e}")
            except Exception as e:
                Favicon = 0
                print(f"An error occurred during the favicon analysis: {e}")

            print("Favicon analysis completed.")
            return Favicon

        # # Test the function with a sample URL
        # url = "https://example.com"
        # favicon_result = analyze_favicon(url)

        # Check for uncommon ports opened by the website.
        # Common ports opened:
        # Port 21 (FTP),Port 22 (SSH),Port 25 (SMTP)
        # Port 80 (HTTP),Port 110 (POP3),Port 143 (IMAP),
        # Port 443 (HTTPS)
        # Scan from port 1 to 600:
        # If uncommon_ports_count == 1, return 0
        # If uncommon_ports_count > 1, return -1
        # Else, return 1

        import socket

        # list of common ports used
        website_ports = [21, 22, 25, 80, 110, 143, 443]

        # Get the IP address of the URL
        try:
            ip_address = socket.gethostbyname(url)
            print("Scanning ports for", url, "(", ip_address, ")")

            uncommon_ports_count = 0

            for port in range(1, 500):
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
            elif uncommon_ports_count > 1:
                port_status = -1
                sus_links.append('More than 1 uncommon ports found opened.')
            else:
                port_status = 1
                legit_links.append('Common ports found opened.')
        except:
            port_status = 0
            sus_links.append('Port scanning not executed on IP.')

        print("Finished analysing ports.")

        # check if the tags in the webpage are loading from external domains.
        # If < 0.22 of tags loading in external domains, return 1
        # If 0.22 <= tags <= 0.61 loading in external domains, return 0
        # Else, return 1

        print("Looking at tags...")
        try:
            response = requests.get(url)
            if response.status_code == 200:
                content = response.text

                # Regular expression to find external URLs in the content
                external_url_regex = r'(?<=href=["\'])(https?://\S+)|(?<=src=["\'])(https?://\S+)'

                external_urls = re.findall(external_url_regex, content)
                parsed_url = urlparse(url)
                total_urls = len(external_urls)
                external_count = 0

                for external_url in external_urls:
                    parsed_external_url = urlparse(external_url)
                    if parsed_external_url.netloc != parsed_url.netloc:
                        external_count += 1

                try:
                    if external_count / total_urls < 0.22:
                        Request_URL = 1
                        legit_links.append('Most tags loaded internally.')
                    elif 0.22 <= external_count / total_urls <= 0.61:
                        Request_URL = 0
                        sus_links.append('Significant number of tags loaded from external domains.')
                    else:
                        Request_URL = -1
                        sus_links.append('Most tags loaded from external domains.')
                except ZeroDivisionError:
                    Request_URL = 0
                    sus_links.append('No tags found.')
            else:
                Request_URL = 0
                sus_links.append('Tags not determined.')
        except:
            Request_URL = 0
            sus_links.append('Tags not determined.')

    print("Finished analysing tags.")

    # check how many times the website is redirected
    # If the number of redirects <= 1, return 1
    # If the number of redirects >= 2 And < 4, return 0
    # Else, return -1

    redirect_count = 0
    max_redirects = 5  # Set a maximum number of allowed redirects

    print("Looking at number of redirects...")
    for _ in range(max_redirects):
        try:
            response = requests.get(url)
            if response.history:
                url = response.url
                redirect_count += 1
                print("url:", url)
                print("redirect count:", redirect_count)
            else:
                break  # No more redirects, exit the loop
        except requests.exceptions.RequestException as e:
            print("Error occurred:", e)
            break  # Handle exceptions and exit the loop

    if redirect_count <= 1:
        Redirect = 1
        sus_links.append('Less than 2 redirects detected.')
    elif 2 <= redirect_count < 4:
        Redirect = 0
        sus_links.append('More than 1 redirect detected.')
    else:
        Redirect = -1
        sus_links.append('More than 3 redirects detected.')

    print("Finished looking at redirects.")

    # Check if right-click is disabled in the website
    # Look for event.button==2 in web source code
    # When right-click is disabled, return -1
    # Else, return 1

    print("Looking at right-click events.")
    try:
        html = response.text
        if "event.button==2" in html:
            RightClick = -1
            sus_links.append('Right-click event.button==2 found.')
        else:
            RightClick = 1
            legit_links.append('Right-click event.button==2 not found.')
    except:
        RightClick = 0
        sus_links.append('Right-click event not detectable.')

    print("Finished looking at right-click events.")

    # check if there is any popup windows in the website
    # If there is popups, return -1
    # Else, return 1

    print("Scanning for pop up events.")
    try:
        html = response.text
        pop_up_text = []

        # Find all occurrences of 'window.open' in the HTML source code
        matches = re.findall(r'window\.open\((.*?)\)', html)

        # Extract the text inside the tags where 'window.open' is found
        for match in matches:
            text_inside_tag = re.search(r'>(.*?)<', match)
            if text_inside_tag:
                pop_up_text.append(text_inside_tag.group(1))

        if pop_up_text:
            popUpWindow = -1
            sus_links.append('Pop up windows detected.')
        else:
            popUpWindow = 1
            legit_links.append('No pop up windows detected.')
    except:
        popUpWindow = 0
        sus_links.append('Pop up windows unable to be determined.')
    print("Finished scanning for popup events.")

    # Check whether iframe tag frameBorder attribute is used to create an invisible frame
    # If iframe is used, return -1
    # Else, return 1

    print("Looking at iframe...")
    try:
        html = response.text

        # Use regular expression to check for the <iframe> tag with 'frameborder' attribute
        iframe_pattern = compile(r'<iframe[^>]*\sframeborder\s*=', IGNORECASE)
        if iframe_pattern.search(html):
            Iframe = -1
            sus_links.append('iframe tag detected.')
        else:
            Iframe = 1
            legit_links.append('No iframe tag detected.')
    except:
        Iframe = 0
        sus_links.append('iframe tag unable to be detected.')
    print("Finished looking at iframe.")
