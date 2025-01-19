import socket  # Import the socket module to establish network connections for HTTP requests.
import ssl  # Import the SSL module to support secure HTTPS connections.
import re  # Import the regular expressions module to parse and extract data from HTTP responses.
import sys  # Import the sys module to handle command-line arguments.
from html.parser import HTMLParser  # Import HTMLParser to detect password forms in HTML responses.
import json

class PasswordFormParser(HTMLParser):
    """HTML Parser to detect password input fields in forms."""
    def __init__(self):
        super().__init__()
        self.is_password_form = False  # Flag to indicate if a password form was detected.

    def handle_starttag(self, tag, attrs):
        # This method checks each HTML tag to identify input fields of type "password".
        if tag == "input":
            for attr_name, attr_value in attrs:
                if attr_name == "type" and attr_value == "password":
                    self.is_password_form = True  # Set the flag if a password field is found.


def check_http2_support(host, port=443):
    """Check if the server supports HTTP/2."""
    context = ssl.create_default_context()  # Create a default SSL context for secure connections.
    context.set_alpn_protocols(["h2", "http/1.1"])  # Specify ALPN protocols to check HTTP/2 support.
    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                # Check if "h2" (HTTP/2) is the selected protocol.
                return "h2" in tls.selected_alpn_protocol()
    except Exception as e:
        print(f"Error while checking HTTP/2 support: {e}")  # Handle errors gracefully.
        return False  # Return False if HTTP/2 support cannot be determined.


# def send_http_request(host, path="/", use_https=False, max_redirects=5):
#     """Send an HTTP or HTTPS request and handle redirects."""
#     visited_urls = set()  # Track visited URLs to detect cyclic redirects.
#     protocol = "https" if use_https else "http"  # Determine the protocol based on input.

#     try:
#         for _ in range(max_redirects):
#             full_url = f"{protocol}://{host}{path}"  # Construct the full URL.
#             if full_url in visited_urls:
#                 print("Cyclic redirect detected. Stopping.")
#                 return "Cyclic redirect detected"  # Return if cyclic redirects are found.
#             visited_urls.add(full_url)  # Add URL to visited set.

#             port = 443 if use_https else 80  # Set port based on protocol.
#             context = ssl.create_default_context() if use_https else None  # Create SSL context for HTTPS.

#             with socket.create_connection((host, port)) as conn:
#                 if use_https:
#                     conn = context.wrap_socket(conn, server_hostname=host)  # Wrap connection in SSL for HTTPS.

#                 # Send an HTTP GET request.
#                 request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
#                 conn.sendall(request.encode())
#                 response = b""
#                 while True:
#                     data = conn.recv(4096)  # Read response in chunks.
#                     if not data:
#                         break
#                     response += data
#                 response_text = response.decode(errors="ignore")  # Decode response to string.

#                 # Check for redirect headers.
#                 match = re.search(r"^Location: (.*?)\r\n", response_text, re.MULTILINE | re.IGNORECASE)
#                 if match:
#                     new_url = match.group(1)
#                     print(f"Redirecting to: {new_url}")
#                     match = re.match(r"https?://([^/]+)(/.*)?", new_url)
#                     if not match:
#                         print("Invalid redirect URL.")
#                         return None
#                     host, path = match.groups()  # Update host and path for the next request.
#                     path = path or "/"
#                     protocol = "https" if new_url.startswith("https") else "http"
#                     use_https = protocol == "https"
#                 else:
#                     return response_text  # Return final response if no redirect is found.

#         print("Too many redirects.")
#         return None  # Return None if maximum redirects exceeded.

#     except socket.error as e:
#         print(f"Network error: {e}")  # Handle network-related errors.
#         return None

#     except ssl.SSLError as e:
#         print(f"SSL error: {e}")  # Handle SSL-related errors.
#         return None

#     except Exception as e:
#         print(f"Unexpected error: {e}")  # Handle unexpected errors.
#         return None

def send_http_request(host, path="/", use_https=False, max_redirects=5):
    """Send an HTTP or HTTPS request and handle redirects."""
    visited_urls = set()
    protocol = "https" if use_https else "http"
    cookies = {}

    try:
        for _ in range(max_redirects):
            full_url = f"{protocol}://{host}{path}".rstrip("/")
            if full_url in visited_urls:
                print("Cyclic redirect detected. Stopping.")
                return "Cyclic redirect detected"
            visited_urls.add(full_url)

            port = 443 if use_https else 80
            context = ssl.create_default_context() if use_https else None

            with socket.create_connection((host, port)) as conn:
                if use_https:
                    conn = context.wrap_socket(conn, server_hostname=host)

                # Include cookies in the request
                cookie_header = "; ".join([f"{name}={value}" for name, value in cookies.items()])
                request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                if cookie_header:
                    request += f"Cookie: {cookie_header}\r\n"
                request += "\r\n"

                conn.sendall(request.encode())
                response = b""
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    response += data
                response_text = response.decode(errors="ignore")

                # Extract cookies from Set-Cookie headers
                cookie_headers = re.findall(r"Set-Cookie: (.*?)\r\n", response_text, re.IGNORECASE)
                for cookie in cookie_headers:
                    match = re.match(r"([^=]+)=([^;]+);", cookie)
                    if match:
                        name, value = match.groups()
                        cookies[name] = value

                # Check for redirect headers
                match = re.search(r"^Location: (.*?)\r\n", response_text, re.MULTILINE | re.IGNORECASE)
                if match:
                    new_url = match.group(1)
                    if new_url.startswith("/"):
                        new_url = f"{protocol}://{host}{new_url}"
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
        print(f"Unexpected error: {e}")
        return None


def parse_cookies(response):
    """Parse cookies from the HTTP response."""
    cookies = []
    
    # Extract cookies from Set-Cookie headers
    cookie_headers = re.findall(r"Set-Cookie: (.*?)\r\n", response, re.IGNORECASE)
    for cookie in cookie_headers:
        match = re.match(r"([^=]+)=([^;]+);", cookie)
        if match:
            name, value = match.groups()
            cookies.append({"name": name, "value": value, "domain": None, "expires": None})

    # Attempt to parse cookies from JSON body if available
    try:
        json_body = json.loads(response.split("\r\n\r\n", 1)[1])
        if "cookies" in json_body:
            for name, value in json_body["cookies"].items():
                cookies.append({"name": name, "value": value, "domain": None, "expires": None})
    except (json.JSONDecodeError, IndexError):
        pass  # Ignore if the body is not JSON or malformed

    return cookies

def check_password_protection(response):
    """Check if the page is password-protected."""
    # Look for authentication headers or 401 status code in the response.
    if "WWW-Authenticate" in response or "401 Unauthorized" in response:
        return True

    parser = PasswordFormParser()
    parser.feed(response)  # Parse the response HTML for password fields.
    return parser.is_password_form  # Return True if password form is found.


def format_output(header, content):
    """Format the output for better readability."""
    output = f"\n{header}\n{'=' * len(header)}\n{content}"  # Create a formatted section with a title and content.
    print(output)  # Print the formatted output.


def is_valid_url(url):
    """Check if the given URL is valid."""
    pattern = r'^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})'
    return re.match(pattern, url) is not None

def main():
    """Main function to handle input and execute functionality."""
    if len(sys.argv) != 2:
        print("Usage: python3 WebTester.py <URL>")
        print("Please provide exactly one URL as an argument.")
        return

    # Normalize the URL and add the scheme if missing
    raw_url = sys.argv[1]
    if not re.match(r"https?://", raw_url):
        raw_url = f"http://{raw_url}"  # Default to HTTP if no scheme is provided

    if not is_valid_url(raw_url):
        print("Invalid URL format")
        return

    # Extract host and path
    match = re.match(r"https?://([^/]+)(/.*)?", raw_url)
    if not match:
        print("Invalid URL format")
        return

    host, path = match.groups()
    path = path or "/"  # Default to root path if none is specified

    # Debugging: Log raw request and output
    print("---Request begin---")
    print(f"GET {raw_url} HTTP/1.1")
    print(f"Host: {host}")
    print("Connection: Keep-Alive")
    print("---Request end---\n")

    # Format and display output
    format_output("Website", host)

    supports_http2 = check_http2_support(host)  # Check HTTP/2 support
    format_output("HTTP/2 Support", f"{'Yes' if supports_http2 else 'No'}")

    use_https = raw_url.startswith("https")
    response = send_http_request(host, path, use_https=use_https)  # Fetch HTTP/HTTPS response
    if response:
        cookies = parse_cookies(response)
        cookies_output = "\n".join([
            f"Cookie Name: {cookie['name']}, Value: {cookie['value']}, Domain: {cookie['domain']}, Expires: {cookie['expires']}"
            for cookie in cookies
        ])
        format_output("Cookies", cookies_output or "No cookies found.")

        is_password_protected = check_password_protection(response)
        format_output("Password Protection", f"{'Yes' if is_password_protected else 'No'}")

        print("\n---Response body---\n")
        print(response[:500])  # Optional: Display first 500 characters of the response body
    else:
        print("Failed to retrieve HTTP response.")

if __name__ == "__main__":
    try:
        main()  # Run the main function when the script is executed.
    except Exception as e:
        print(f"An unexpected error occurred: {e}")