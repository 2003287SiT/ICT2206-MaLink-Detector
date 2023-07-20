import requests
import colorama


def get_url_headers(url):
    try:
        url = "https://www." + url
        print("Headers for: " + url)
        print("-" * 50)

        response = requests.head(url)
        headers = response.headers

        headers_dict = {}

        for header, value in headers.items():
            # Format the Content-Security-Policy header to display each directive on a new line
            if header == "Content-Security-Policy":
                value = ', \n'.join(value.split())

            headers_dict[header] = value
            print(f"{header}: {value}")

        print("-" * 50)
        return headers_dict

    except requests.exceptions.RequestException as e:
        print(f"Error while making the request: {e}")
        return None


if __name__ == "__main__":

    url = input("Enter the URL to check headers: ")
    headers_dict = get_url_headers(url)
