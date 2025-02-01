import socket  # Establish network connections for HTTP requests.
import ssl  # Support secure HTTPS connections.
import re  # Parse and extract data from HTTP responses using regular expressions.
import sys  # Handle command-line arguments.
from html.parser import HTMLParser  # Detect password forms in HTML responses.
import json  # Parse JSON data.

class PasswordFormParser(HTMLParser):
    """
    HTML Parser to detect password input fields in forms.

    Attributes:
        is_password_form (bool): Indicates if a password input field is detected.
        forms_found (int): Number of forms encountered in the HTML.
        has_login_keyword (bool): True if form action attributes contain login-related keywords.
    """
    def __init__(self):
        super().__init__()
        self.is_password_form = False
        self.forms_found = 0
        self.has_login_keyword = False

    def handle_starttag(self, tag, attrs):
        """
        Handles the start of an HTML tag.

        Args:
            tag (str): The name of the HTML tag.
            attrs (list): List of attributes and their values for the tag.
        """
        # Detect password input fields.
        if tag == "input":
            for attr_name, attr_value in attrs:
                if attr_name == "type" and attr_value == "password":
                    self.is_password_form = True

        # Track forms with potential login-related keywords.
        if tag == "form":
            self.forms_found += 1
            for attr_name, attr_value in attrs:
                if attr_name == "action" and any(
                    keyword in attr_value.lower() for keyword in ["login", "auth", "signin"]
                ):
                    self.has_login_keyword = True


def check_http2_support(host, port=443):
    """
    Check if the server supports HTTP/2.

    Args:
        host (str): The hostname or IP address of the server.
        port (int): The port to connect to (default: 443).

    Returns:
        bool: True if HTTP/2 is supported, False otherwise.
    """
    context = ssl.create_default_context()  # Create a default SSL context for secure connections.
    context.set_alpn_protocols(["h2", "http/1.1"])  # Specify ALPN protocols to check HTTP/2 support.
    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                # Check if "h2" (HTTP/2) is the selected protocol.
                return "h2" in tls.selected_alpn_protocol()
    except Exception as e:
        print(f"Error while checking HTTP/2 support: {e}")  # Handle errors gracefully.
        return False


def send_http_request(host, path="/", use_https=False, max_redirects=5):
    """
    Send an HTTP or HTTPS request and handle redirects.

    Args:
        host (str): Hostname or IP address of the server.
        path (str): URL path (default: "/").
        use_https (bool): Whether to use HTTPS (default: False).
        max_redirects (int): Maximum number of redirects to follow (default: 5).

    Returns:
        str: The HTTP response text or None if an error occurs.
    """
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

            response_text, cookies = make_request(host, path, use_https, cookies)
            if response_text is None:
                return None
            
            if "ERROR" in response_text:
                error_line = re.search(r".*ERROR.*", response_text)
                print(f"Error detected: {error_line.group(0)}")
                return None
            
            if "404 NOT FOUND" in response_text:
                error_line = re.search(r".*404 NOT FOUND.*", response_text)
                print(f"404 detected: {error_line.group(0)}")
                return None
            
            status_match = re.search(r"HTTP/\d\.\d (\d+)", response_text)

            if status_match:
                status_code = int(status_match.group(1))  # Extract status code
                handle_http_status(status_code)  # Handle the status code appropriately
            #     if status_code >= 400:  # If it's a client or server error, stop processing
            #         return None

            new_url, host, path, protocol, use_https = handle_redirect(response_text, host, path, protocol, use_https)
            if new_url is None:
                return response_text

        return None

    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def make_request(host, path, use_https, cookies):
    """
    Make an HTTP or HTTPS request and return the response text and cookies.

    Args:
        host (str): Hostname of the server.
        path (str): Path for the request.
        use_https (bool): Whether to use HTTPS.
        cookies (dict): Dictionary of cookies to include in the request.

    Returns:
        tuple: The response text and updated cookies.
    """
    port = 443 if use_https else 80
    context = ssl.create_default_context() if use_https else None

    with socket.create_connection((host, port)) as conn:
        if use_https:
            conn = context.wrap_socket(conn, server_hostname=host)

        # Include cookies in the request.
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

        # Extract cookies from Set-Cookie headers.
        cookie_headers = re.findall(r"Set-Cookie: (.*?)\r\n", response_text, re.IGNORECASE)
        for cookie in cookie_headers:
            match = re.match(r"([^=]+)=([^;]+);", cookie)
            if match:
                name, value = match.groups()
                cookies[name] = value

    return response_text, cookies


def handle_redirect(response_text, host, path, protocol, use_https):
    """
    Handle HTTP redirects and return the new URL components.

    Args:
        response_text (str): The HTTP response text.
        host (str): Current host.
        path (str): Current path.
        protocol (str): Current protocol ("http" or "https").
        use_https (bool): Whether HTTPS is being used.

    Returns:
        tuple: New URL, updated host, path, protocol, and HTTPS flag.
    """
    match = re.search(r"^Location: (.*?)\r\n", response_text, re.MULTILINE | re.IGNORECASE)
    if match:
        new_url = match.group(1)
        if new_url.startswith("/"):
            new_url = f"{protocol}://{host}{new_url}"
        match = re.match(r"https?://([^/]+)(/.*)?", new_url)
        if not match:
            print("Invalid redirect URL.")
            return None, host, path, protocol, use_https
        host, path = match.groups()
        path = path or "/"
        protocol = "https" if new_url.startswith("https") else "http"
        use_https = protocol == "https"
        print(f"Redirecting to {new_url}")
        return new_url, host, path, protocol, use_https
    else:
        return None, host, path, protocol, use_https

import re
import json

def parse_cookies(response):
    """
    Parse cookies from the HTTP response, including expiry dates and domain attributes.

    Args:
        response (str): The HTTP response text.

    Returns:
        list: A list of cookies as dictionaries with name, value, domain, and expires.
    """
    cookies = []

    # Split response into headers and body.
    if "\r\n\r\n" in response:
        headers, body = response.split("\r\n\r\n", 1)
    else:
        headers = response
        body = ""

    # Process headers for Set-Cookie.
    for line in headers.splitlines():
        if line.lower().startswith("set-cookie:"):
            cookie = line[len("Set-Cookie: "):].strip()

            # Extract name and value.
            match = re.match(r"([^=]+)=([^;]+)", cookie)
            if match:
                name, value = match.groups()

                # Extract the Expires attribute if present.
                expires_match = re.search(r"Expires=([^;]+)", cookie, re.IGNORECASE)
                expires = expires_match.group(1) if expires_match else None

                # Extract the Domain attribute if present.
                domain_match = re.search(r"Domain=([^;]+)", cookie, re.IGNORECASE)
                domain = domain_match.group(1) if domain_match else "Unknown"

                # Add the cookie with its details to the list.
                cookies.append({
                    "name": name.strip(),
                    "value": value.strip(),
                    "domain": domain.strip(),
                    "expires": expires.strip() if expires else None
                })

    # Optionally process JSON body for cookies.
    if "Content-Type: application/json" in headers:
        try:
            json_body = json.loads(body)
            if "cookies" in json_body:
                for name, value in json_body["cookies"].items():
                    cookies.append({
                        "name": name,
                        "value": value,
                        "domain": "Unknown",  # JSON does not typically include domains
                        "expires": None
                    })
        except json.JSONDecodeError:
            pass

    return cookies


def check_password_protection(response):
    """
    Check if the page is password-protected.

    Args:
        response (str): The HTTP response text.

    Returns:
        bool: True if password protection is detected, False otherwise.
    """
    # Check for HTTP status codes indicating restricted access.
    if "401 Unauthorized" in response or "403 Forbidden" in response:
        return True

    # Check for WWW-Authenticate header.
    if "WWW-Authenticate" in response or "403 Not authenticated." in response:
        return True

    # Parse the HTML response using PasswordFormParser.
    parser = PasswordFormParser()
    parser.feed(response)

    # Flag as password-protected if password input fields are detected.
    if parser.is_password_form:
        return True

    # Check for keywords in form action attributes.
    if parser.has_login_keyword:
        return True

    # Consider the overall response for strong indicators of login.
    keywords = ["login", "sign in", "authentication", "authenticate"]
    lower_response = response.lower()
    keyword_count = sum(keyword in lower_response for keyword in keywords)

    # Apply a scoring system to minimize false positives.
    if keyword_count > 2 and parser.forms_found > 0:
        return True

    return False  # Default to not password-protected.


def format_output(header, content):
    """
    Format the output for better readability.

    Args:
        header (str): Title or header for the output section.
        content (str): The content to be displayed under the header.

    Returns:
        None
    """
    output = f"\n{header}\n{'=' * len(header)}\n{content}"  # Create a formatted section with a title and content.
    print(output)  # Print the formatted output.


def is_valid_url(url):
    """
    Check if the given URL is valid.

    Args:
        url (str): The URL string to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    pattern = (
        r'^https?://'                   # Match http:// or https://
        r'('
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'  # Match domain names.
        r'|'
        r'((\d{1,3}\.){3}\d{1,3})'     # Match IPv4 addresses.
        r')'
    )
    return re.match(pattern, url) is not None


def print_usage():
    """
    Print usage instructions for the script.

    Returns:
        None
    """
    print("Usage: python3 WebTester.py <URL>")
    print("Please provide exactly one URL as an argument")
    print("\n Acceptable URL Formats:")
    print("  - https://example.com")
    print("  - http://example.com")
    print("  - https://www.google.com/search?q=python")
    print("  - http://localhost:8000")
    print("  - https://192.168.1.1")
    print("  - example.com (auto-normalized to http://example.com)")
    print("\n Invalid URL Formats:")
    print("  - ftp://example.com (unsupported protocol)")
    print("  - example_com (invalid domain)")
    print("  - //example.com (missing scheme)")
    print("  - htp://example.com (typo in protocol)")
    print("\nPlease provide a valid HTTP(S) URL as an argument.")


def normalize_url(raw_url):
    """
    Normalize the URL by adding a scheme if missing.

    Args:
        raw_url (str): The raw URL provided by the user.

    Returns:
        str: The normalized URL.
    """
    if not re.match(r"https?://", raw_url):
        raw_url = f"http://{raw_url}"  # Default to HTTP if no scheme is provided.
    return raw_url


def extract_host_and_path(raw_url):
    """
    Extract host and path from the given URL.

    Args:
        raw_url (str): The full URL.

    Returns:
        tuple: The host and path as separate strings.
    """
    match = re.match(r"https?://([^/]+)(/.*)?", raw_url)
    if not match:
        return None, None
    host, path = match.groups()
    path = path or "/"  # Default to root path if none is specified.
    return host, path


def log_request(raw_url, host):
    """
    Log the raw HTTP request for debugging purposes.

    Args:
        raw_url (str): The full URL being requested.
        host (str): The host of the request.

    Returns:
        None
    """
    print("---Request begin---")
    print(f"GET {raw_url} HTTP/1.1")
    print(f"Host: {host}")
    print("Connection: Keep-Alive")
    print("---Request end---\n")


def handle_response(response):
    """
    Handle the HTTP response by extracting cookies and checking password protection.

    Args:
        response (str): The HTTP response text.

    Returns:
        None
    """

    cookies = parse_cookies(response)
    cookies_output = "\n".join([
        f"Cookie Name: {cookie['name']}, Value: {cookie['value']}, Domain: {cookie['domain']}, Expires: {cookie['expires']}"
        for cookie in cookies
    ])
    format_output("Cookies", cookies_output or "No cookies found.")

    is_password_protected = check_password_protection(response)
    format_output("Password Protection", f"{'Yes' if is_password_protected else 'No'}")

    print("\n---Response body---\n")
    print(response[:500])  # Optional: Display the first 500 characters of the response body.

def handle_http_status(status_code):
    """
    Handle HTTP response status codes and print appropriate messages.

    Args:
        status_code (int): The HTTP status code.

    Returns:
        None
    """
    if status_code == 200:
        print("✅ 200 OK - Request was successful.")
    elif status_code == 201:
        print("✅ 201 Created - Resource was successfully created.")
    elif status_code == 204:
        print("✅ 204 No Content - Request successful but no content returned.")
    elif status_code == 301:
        print("🔄 301 Moved Permanently - Resource has moved to a new URL.")
    elif status_code == 302:
        print("🔄 302 Found - Temporary redirect.")
    elif status_code == 304:
        print("🛑 304 Not Modified - Cached response can be used.")
    elif status_code == 400:
        print("❌ 400 Bad Request - Invalid request sent by client.")
    elif status_code == 401:
        print("🔐 401 Unauthorized - Authentication required.")
    elif status_code == 403:
        print("⛔ 403 Forbidden - You don’t have permission to access this resource.")
    elif status_code == 404:
        print("❌ 404 Not Found - The requested resource does not exist.")
    elif status_code == 405:
        print("⚠️ 405 Method Not Allowed - The HTTP method is not supported for this resource.")
    elif status_code == 408:
        print("⏳ 408 Request Timeout - The server timed out waiting for the request.")
    elif status_code == 429:
        print("⚠️ 429 Too Many Requests - Rate limit exceeded.")
    elif status_code == 500:
        print("🔥 500 Internal Server Error - Server encountered an unexpected condition.")
    elif status_code == 502:
        print("🚧 502 Bad Gateway - Invalid response from upstream server.")
    elif status_code == 503:
        print("🚧 503 Service Unavailable - Server is overloaded or under maintenance.")
    elif status_code == 504:
        print("⏳ 504 Gateway Timeout - Upstream server did not respond in time.")
    else:
        print(f"⚠️ Unexpected HTTP status code received: {status_code}")


def main():
    """
    Main function to handle input, validate the URL, check HTTP/2 support,
    and process HTTP responses.

    Returns:
        None
    """
    if len(sys.argv) != 2:
        print_usage()
        return

    raw_url = normalize_url(sys.argv[1])
    if not is_valid_url(raw_url):
        print("Invalid URL format")
        print_usage()
        return

    host, path = extract_host_and_path(raw_url)
    if not host:
        print("Invalid URL format")
        return

    log_request(raw_url, host)
    format_output("Website", host)

    supports_http2 = check_http2_support(host)
    format_output("HTTP/2 Support", f"{'Yes' if supports_http2 else 'No'}")

    use_https = raw_url.startswith("https")
    response = send_http_request(host, path, use_https=use_https)

    if response:
        handle_response(response)
    else:
        print("Failed to retrieve HTTP response.")


if __name__ == "__main__":
    try:
        main()  # Run the main function when the script is executed.
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

