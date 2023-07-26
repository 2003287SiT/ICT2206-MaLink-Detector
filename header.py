import requests


def get_url_headers(url):
    try:
        url = "https://www." + url

        response = requests.head(url)
        headers = response.headers

        header_info_list = [f"{header}: {value.split(':')[0]}" for header, value in headers.items()]
        return header_info_list  # Return a list of header names

    except requests.exceptions.RequestException as e:
        print(f"Error while making the request: {e}")
        return None


def print_headers(header_info_list):
    if header_info_list is not None:
        for header_info in header_info_list:
            print(header_info)
    else:
        print("No headers were retrieved.")
