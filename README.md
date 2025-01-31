# **SmartClient: A Web Server Testing Tool**

## **Overview**

`SmartClient` is a Python-based tool for analyzing web server behavior. It provides insights into server capabilities and security, specifically focusing on:

1. **HTTP/2 Support**: Determines if the server supports the HTTP/2 protocol.
2. **Redirect Handling**: Follows server redirects and prevents infinite loops.
3. **Cookie Analysis**: Extracts cookies, including details like name, value, domain, and expiry.
4. **Password Protection Detection**: Identifies if a webpage is password-protected using various indicators.

This tool leverages socket programming for direct interaction with web servers and ensures precise, low-level control over HTTP/HTTPS requests.

---

## **Features**

- **HTTP/2 Detection**: Utilizes ALPN (Application-Layer Protocol Negotiation) to identify server protocol support.
- **Redirect Handling**: Automatically follows up to 5 redirects, supporting both relative and absolute URLs.
- **Cookie Parsing**: Extracts cookies from headers and JSON responses, handling attributes like `Expires` and `Domain`.
- **Password Protection Analysis**: Scans responses for login forms, password fields, and authentication-related status codes.
- **Error Handling**: Detects malformed URLs, unreachable hosts, and cyclic redirects, providing clear error messages.

---

## **How to Run**

### **Prerequisites**

- Python 3.6+ must be installed.
- Ensure the required environment allows socket programming (e.g., a Linux or macOS system).

### **Execution**

Clone the repository:

```bash
git clone https://github.com/your-username/SmartClient.git
cd SmartClient
```

Run the tool:

```bash
python3 SmartClient.py <URL>
```

Replace `<URL>` with the target web server's URL. For example:

```bash
python3 SmartClient.py https://www.example.com
```

---

## **Output**

The tool provides detailed output, including:

1. **HTTP/2 Support**: Indicates whether the server supports HTTP/2.
2. **Redirects**: Tracks the redirect chain.
3. **Cookies**: Lists cookies with their attributes (name, value, domain, expiry).
4. **Password Protection**: Identifies if the page requires authentication.

Example:

```text
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
```

---

## **Running Tests**

The repository includes a test suite (`Test1.py`) to validate the functionality of the tool.

### **Test Features**

- **HTTP/2 Detection**: Ensures accurate protocol support detection.
- **Redirect Handling**: Tests the ability to handle various redirect scenarios.
- **Cookie Parsing**: Verifies extraction and display of cookie details.
- **Password Protection Detection**: Confirms identification of password-protected pages.
- **Error Handling**: Validates responses to malformed URLs and unreachable hosts.

### **How to Run Tests**

Use the following command to execute the tests:

```bash
python3 -m unittest Test1.py
```

Example test output:

```text
test_http2_support_google (Test1.TestWebTester) ... ok
test_cookie_with_expiry (Test1.TestWebTester) ... ok
test_password_protected_pages (Test1.TestWebTester) ... ok
...
----------------------------------------------------------------------
Ran 10 tests in 0.456s

OK
```

---

## **Contributing**

Contributions are welcome! Please fork the repository, create a branch for your feature or bug fix, and submit a pull request.

---

## **License**

This project is licensed under the MIT License. See the `LICENSE` file for details.
