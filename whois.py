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
    lines = whois_raw_data.split("\n")
    extracted_info = ""
    for line in lines:
        extracted_info += line + "\n"
        if "Last update of whois database" in line:
            break
    return extracted_info.strip()


if __name__ == "__main__":
    print("-" * 100)
    domain = input("Enter the domain name you want to query: ")
    whois_raw_data = get_whois_data(domain)
    whois_info = extract_whois_info(whois_raw_data)
    print("WHOIS Information:")
    print(whois_info)
    print("-" * 100)


