import socket
import ssl
import re
import sys
from html.parser import HTMLParser

class PasswordFormParser(HTMLParser):
    """HTML Parser to detect password input fields in forms."""
    def __init__(self):
        super().__init__()
        self.is_password_form = False

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            for attr_name, attr_value in attrs:
                if attr_name == "type" and attr_value == "password":
                    self.is_password_form = True


def check_http2_support(host, port=443):
    """Check if the server supports HTTP/2."""
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return "h2" in tls.selected_alpn_protocol()
    except Exception as e:
        print(f"Error while checking HTTP/2 support: {e}")
        return False

def send_http_request(host, path="/", use_https=False, max_redirects=5):
    """Send an HTTP or HTTPS request and handle redirects."""
    visited_urls = set()
    protocol = "https" if use_https else "http"

    try:
        for _ in range(max_redirects):
            full_url = f"{protocol}://{host}{path}"
            if full_url in visited_urls:
                print("Cyclic redirect detected. Stopping.")
                return None
            visited_urls.add(full_url)

            port = 443 if use_https else 80
            context = ssl.create_default_context() if use_https else None

            with socket.create_connection((host, port)) as conn:
                if use_https:
                    conn = context.wrap_socket(conn, server_hostname=host)

                request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                conn.sendall(request.encode())
                response = b""
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    response += data
                response_text = response.decode(errors="ignore")

                match = re.search(r"^Location: (.*?)\r\n", response_text, re.MULTILINE | re.IGNORECASE)
                if match:
                    new_url = match.group(1)
                    print(f"Redirecting to: {new_url}")
                    match = re.match(r"https?://([^/]+)(/.*)?", new_url)
                    if not match:
                        print("Invalid redirect URL.")
                        return None
                    host, path = match.groups()
                    path = path or "/"
                    protocol = "https" if new_url.startswith("https") else "http"
                    use_https = protocol == "https"
                else:
                    return response_text

        print("Too many redirects.")
        return None

    except Exception as e:
        print(f"Error while sending HTTP request: {e}")
        return None

def parse_cookies(response):
    """Parse cookies from the HTTP response."""
    cookie_headers = re.findall(r"Set-Cookie: (.*?)\r\n", response, re.IGNORECASE)
    cookies = []
    for match in re.finditer(r"Set-Cookie: ([^=]+)=([^;]+);(?:.*?domain=([^;]+))?;?(?:.*?expires=([^;]+))?", response, re.IGNORECASE):
        name, value, domain, expires = match.groups()
        cookies.append({"name": name, "value": value, "domain": domain, "expires": expires})
    return cookies

def check_password_protection(response):
    """Check if the page is password-protected."""
    if "401 Unauthorized" in response:
        return True

    parser = PasswordFormParser()
    parser.feed(response)
    return parser.is_password_form

def format_output(header, content):
    """Format the output for better readability."""
    output = f"\n{header}\n{'=' * len(header)}\n{content}"
    print(output)

def main():
    """Main function to handle input and execute functionality."""
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

    format_output("Website", host)

    supports_http2 = check_http2_support(host)
    format_output("HTTP/2 Support", f"{'Yes' if supports_http2 else 'No'}")

    use_https = url.startswith("https")
    response = send_http_request(host, path, use_https=use_https)
    if response:
        cookies = parse_cookies(response)
        cookies_output = "\n".join([
            f"Cookie Name: {cookie['name']}, Domain: {cookie['domain'] or 'N/A'}, Expires: {cookie['expires'] or 'N/A'}"
            for cookie in cookies
        ])
        format_output("Cookies", cookies_output or "No cookies found.")

        is_password_protected = check_password_protection(response)
        format_output("Password Protection", f"{'Yes' if is_password_protected else 'No'}")
    else:
        print("Failed to retrieve HTTP response.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
