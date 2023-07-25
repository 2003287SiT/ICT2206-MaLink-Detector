import re
import socket


def is_valid_domain(domain):
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$'
    return re.match(pattern, domain) is not None


def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
