import socket
import ssl
import re
import sys
from html.parser import HTMLParser
import json

class PasswordFormParser(HTMLParser):
    """HTML Parser to detect password input fields in forms."""
    def __init__(self):
        super().__init__()
        self.is_password_form = False
        self.forms_found = 0
        self.has_login_keyword = False

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            self.is_password_form |= any(attr == ("type", "password") for attr in attrs)
        if tag == "form":
            self.forms_found += 1
            self.has_login_keyword |= any(
                attr == ("action", value) and any(keyword in value.lower() for keyword in ["login", "auth", "signin"])
                for attr, value in attrs
            )

def is_valid_url(url):
    """Check if the given URL is valid."""
    pattern = (
        r'^https?://'  # Match http:// or https://
        r'('
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'  # Match domain names
        r'|'
        r'((\d{1,3}\.){3}\d{1,3})'  # Match IPv4 addresses
        r')'
    )
    return re.match(pattern, url) is not None

def check_http2_support(host, port=443):
    """Check if the server supports HTTP/2."""
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return "h2" in tls.selected_alpn_protocol()
    except Exception as e:
        print(f"Error checking HTTP/2 support: {e}")
        return False

def send_http_request(host, path="/", use_https=False, max_redirects=5):
    """Send an HTTP or HTTPS request and handle redirects."""
    visited_urls = set()
    protocol = "https" if use_https else "http"
    cookies = {}

    try:
        for _ in range(max_redirects):
            full_url = f"{protocol}://{host}{path}".rstrip("/")
            if full_url in visited_urls:
                print("Cyclic redirect detected.")
                return "Cyclic redirect detected"
            visited_urls.add(full_url)

            port = 443 if use_https else 80
            context = ssl.create_default_context() if use_https else None

            with socket.create_connection((host, port)) as conn:
                if use_https:
                    conn = context.wrap_socket(conn, server_hostname=host)

                cookie_header = "; ".join([f"{name}={value}" for name, value in cookies.items()])
                request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                if cookie_header:
                    request += f"Cookie: {cookie_header}\r\n"
                request += "\r\n"

                conn.sendall(request.encode())
                response = conn.recv(4096).decode(errors="ignore")

                cookies.update(parse_cookies(response))
                match = re.search(r"^Location: (.*?)\r\n", response, re.MULTILINE | re.IGNORECASE)
                if match:
                    new_url = match.group(1)
                    host, path = parse_url(new_url)
                    protocol = "https" if new_url.startswith("https") else "http"
                    use_https = protocol == "https"
                else:
                    return response

        return None
    except Exception as e:
        print(f"Error during HTTP request: {e}")
        return None

def parse_cookies(response):
    """Parse cookies from the HTTP response."""
    cookies = {}
    cookie_headers = re.findall(r"Set-Cookie: ([^;]+);", response, re.IGNORECASE)
    for cookie in cookie_headers:
        name, value = cookie.split("=", 1)
        cookies[name] = value
    return cookies

def check_password_protection(response):
    """Check if the page is password-protected."""
    if any(code in response for code in ["401 Unauthorized", "403 Forbidden", "WWW-Authenticate"]):
        return True

    parser = PasswordFormParser()
    parser.feed(response)
    return parser.is_password_form or parser.has_login_keyword

def format_output(header, content):
    """Format and print the output."""
    print(f"\n{header}\n{'=' * len(header)}\n{content}")

def parse_url(url):
    """Extract host and path from a URL."""
    match = re.match(r"https?://([^/]+)(/.*)?", url)
    if not match:
        raise ValueError("Invalid URL format")
    return match.group(1), match.group(2) or "/"

def main():
    """Main function to handle input and execute functionality."""
    if len(sys.argv) != 2:
        print("Usage: python3 WebTester.py <URL>")
        return

    raw_url = sys.argv[1]
    if not re.match(r"https?://", raw_url):
        raw_url = f"http://{raw_url}"

    if not is_valid_url(raw_url):
        print("Invalid URL format.")
        return

    host, path = parse_url(raw_url)
    format_output("Website", host)

    supports_http2 = check_http2_support(host)
    format_output("HTTP/2 Support", "Yes" if supports_http2 else "No")

    response = send_http_request(host, path, use_https=raw_url.startswith("https"))
    if response:
        format_output("Cookies", json.dumps(parse_cookies(response), indent=4))
        format_output("Password Protection", "Yes" if check_password_protection(response) else "No")
        print("\nResponse Body Preview:\n", response[:500])

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Unexpected error: {e}")
