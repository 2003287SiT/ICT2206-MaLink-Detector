import re
import socket


def is_multi_line_input(input_str):
    return input_str.count("\n") > 1

def is_valid_domain(domain):
    # Allow for a broader range of domain names and IP addresses
    pattern = r'^(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.)*(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
    return re.match(pattern, domain) is not None

def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
