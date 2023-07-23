import pandas as pd
import numpy as np
import requests

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import seaborn as sns
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import learning_curve
import re


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

