SmartClient: A Comprehensive Web Server Testing Tool
1. Overview
SmartClient is a Python-based tool designed to meet the requirements of the CSC361 assignment by:

Determining HTTP/2 Support: Uses ALPN (Application-Layer Protocol Negotiation) to identify if the target web server supports HTTP/2.
Handling HTTP Redirects: Automatically follows redirects (e.g., 301, 302) while preventing infinite loops.
Parsing Cookies: Extracts cookies from Set-Cookie headers and JSON bodies, providing details such as name, value, domain, and expiry.
Identifying Password Protection: Analyzes server responses for login forms, password fields, and authentication indicators.
The implementation adheres to socket programming principles to directly interact with web servers, ensuring minimal reliance on external libraries and full control over HTTP requests and responses.

3. How SmartClient Meets the Requirements
3.1 HTTP/2 Detection
Approach:
The tool uses Python's ssl library to create an SSL context that specifies ALPN protocols (h2 for HTTP/2 and http/1.1 for HTTP/1.1). By establishing a TLS connection to the server and inspecting the negotiated protocol, the tool determines if HTTP/2 is supported.

Why This Approach?
This low-level method ensures accuracy and directly interacts with the server's ALPN capabilities without relying on prebuilt HTTP client libraries.

3.2 Handling HTTP Redirects
Approach:
The tool tracks visited URLs to prevent infinite loops and follows redirects up to a maximum of 5 hops. Redirect handling is implemented by inspecting the Location header in server responses and making follow-up requests to the specified URL.

Key Features:

Supports both relative (/newpath) and absolute (https://example.com/newpath) URLs in the Location header.
Handles protocol changes (e.g., HTTP to HTTPS).
Stops execution if a cyclic redirect is detected.
Why This Approach?
Manually handling redirects allows full control over the redirection logic and ensures compliance with assignment requirements without external dependencies.

3.3 Cookie Parsing
Approach:

Cookies are extracted from Set-Cookie headers in the server response. The tool parses cookie attributes (e.g., Domain, Expires) and stores them in a structured format.
If the response body is JSON and contains a cookies field, the tool processes it for additional cookie information.
Key Features:

Handles malformed or incomplete cookie attributes gracefully.
Outputs all cookies with details such as name, value, domain, and expiry time (if available).
Why This Approach?
By directly parsing Set-Cookie headers, the tool aligns with the assignment's emphasis on low-level HTTP interaction. The optional handling of JSON cookie fields enhances functionality for modern APIs.

3.4 Password Protection
Approach:

The tool analyzes HTTP status codes (401 Unauthorized, 403 Forbidden) and headers (e.g., WWW-Authenticate) for signs of authentication requirements.
It uses an HTMLParser (PasswordFormParser) to scan for forms containing password input fields or login-related keywords in action attributes.
Key Features:

Scores the likelihood of password protection based on multiple indicators (e.g., status codes, login forms, keywords).
Avoids false positives by requiring multiple criteria to be met.
Why This Approach?
Combining status code analysis and HTML parsing ensures robust detection of password protection across a wide range of scenarios.

4. Key Implementation Details
Socket Programming
The tool directly uses Python's socket library to create and manage TCP connections for both HTTP and HTTPS requests. This allows fine-grained control over request headers, protocols, and connection behavior.

SSL/TLS Management
The ssl library is used to wrap socket connections for HTTPS support. By customizing SSL contexts, the tool ensures compatibility with modern servers while disabling insecure protocols (e.g., TLS 1.0, 1.1).

Error Handling
Detects and reports malformed URLs, unreachable hosts, and unsupported servers.
Includes safeguards against cyclic redirects and handles unexpected server responses gracefully.
5. How to Run
Prerequisites
Ensure Python 3.6+ is installed.
Upload SmartClient.py to the linux.csc.uvic.ca server for testing.
Execution
Run the tool using:

python3 SmartClient.py <URL>
Example:

python3 SmartClient.py https://www.google.com
6. Example Output
Input:

python3 SmartClient.py https://www.example.com

-----------------------------------------------
Output:

---Request begin---
GET https://www.example.com HTTP/1.1
Host: www.example.com
Connection: Keep-Alive
---Request end---

Website
=======
www.example.com

HTTP/2 Support
==============
Yes

Cookies
=======
Cookie Name: SESSIONID, Value: abc123, Domain: .example.com, Expires: Wed, 01 Jan 2025 12:34:56 GMT

Password Protection
===================
No

