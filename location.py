import socket
import requests


def get_ip_location(ip_address):
    api_token = "f14bc8c859dd64"
    url = f"https://ipinfo.io/{ip_address}/json"
    headers = {"Authorization": f"Bearer {api_token}"}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        # Extract relevant location information
        country = data.get("country", "")
        region = data.get("region", "")
        city = data.get("city", "")
        latitude = data.get("loc", "").split(",")[0]
        longitude = data.get("loc", "").split(",")[1]

        return country, region, city, latitude, longitude
    except requests.exceptions.RequestException as e:
        print(f"Error while fetching IP geolocation: {e}")
        return None, None, None, None, None


def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error while resolving domain: {e}")
        return None


def print_location_info(country, region, city, latitude, longitude):
    if country:

        print(f"Country: {country}")
        print(f"Region: {region}")
        print(f"City: {city}")
        print(f"Latitude: {latitude}")
        print(f"Longitude: {longitude}")

    else:
        print("Unable to retrieve location for the given domain name.")


def get_domain_location(domain):
    ip_address = resolve_domain_to_ip(domain)

    if ip_address:
        country, region, city, latitude, longitude = get_ip_location(ip_address)
        if country:
            return country, region, city, latitude, longitude
        else:
            print("Unable to retrieve location for the given domain name.")
    else:
        print("Unable to resolve domain to IP address.")
    return None, None, None, None, None



