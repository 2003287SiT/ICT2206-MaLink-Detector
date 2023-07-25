import socket


def get_whois_data(domain):
    try:
        whois_server = "whois.verisign-grs.com"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((whois_server, 43))
            s.sendall((domain + "\r\n").encode())
            whois_data = b""
            while True:
                data = s.recv(1024)
                if not data:
                    break
                whois_data += data
        return whois_data.decode()
    except socket.error as e:
        return f"WHOIS lookup failed: {e}"


def extract_whois_info(whois_raw_data):
    lines = whois_raw_data.splitlines()
    extracted_info = ""
    started = False  # To track if we have encountered the start of WHOIS information

    for line in lines:
        line = line.lstrip()  # Remove leading spaces
        if not started and "Domain Name:" in line:
            started = True  # Start capturing WHOIS information from this line
        if started:
            extracted_info += line + "\n"
            if "Last update of whois database" in line:
                break

    return extracted_info.strip()


