import socket
import ssl
import re
import sys

# Function to check HTTP/2 support
def check_http2_support(host, port=443):
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return "h2" in tls.selected_alpn_protocol()
    except Exception as e:
        print(f"Error while checking HTTP/2 support: {e}")
        return False

# Function to send an HTTP request and receive the response
def send_http_request(host, path="/"):
    try:
        with socket.create_connection((host, 80)) as conn:
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            conn.sendall(request.encode())
            response = b""
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                response += data
            return response.decode(errors="ignore")
    except Exception as e:
        print(f"Error while sending HTTP request: {e}")
        return None

# Function to parse cookies from the HTTP response
def parse_cookies(response):
    cookies = []
    for match in re.finditer(r"Set-Cookie: ([^=]+)=([^;]+);(?:.*?domain=([^;]+))?;?(?:.*?expires=([^;]+))?", response, re.IGNORECASE):
        name, value, domain, expires = match.groups()
        cookies.append({"name": name, "value": value, "domain": domain, "expires": expires})
    return cookies

# Function to check for password protection
def check_password_protection(response):
    return "401 Unauthorized" in response or "login" in response.lower()

# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 WebTester.py <URL>")
        print("Please provide exactly one URL as an argument.")
        return

    url = sys.argv[1]
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    match = re.match(r"https?://([^/]+)(/.*)?", url)
    if not match:
        print("Invalid URL format. Ensure the URL is correctly formatted.")
        return

    host, path = match.groups()
    path = path or "/"

    print(f"website: {host}")

    # Check HTTP/2 support
    supports_http2 = check_http2_support(host)
    print(f"1. Supports http2: {'yes' if supports_http2 else 'no'}")

    # Send HTTP request and parse response
    response = send_http_request(host, path)
    if response:
        # Parse cookies
        cookies = parse_cookies(response)
        print("2. List of Cookies:")
        for cookie in cookies:
            print(f"   cookie name: {cookie['name']}, domain name: {cookie['domain'] or 'N/A'}, expires time: {cookie['expires'] or 'N/A'}")

        # Check password protection
        is_password_protected = check_password_protection(response)
        print(f"3. Password-protected: {'yes' if is_password_protected else 'no'}")
    else:
        print("Failed to retrieve HTTP response.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
