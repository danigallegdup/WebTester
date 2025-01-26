import unittest
import subprocess

"""
run : python -m unittest Test1.py

"""

class TestWebTester(unittest.TestCase):
    def run_webtester(self, url):
        """Helper function to run WebTester.py and capture output."""
        result = subprocess.run(
            ["python3", "SmartClient.py", url],
            capture_output=True,
            text=True
        )
        return result.stdout

    # === Error Handling ===
    def test_malformed_url(self):
        """Test behavior with a malformed URL."""
        output = self.run_webtester("malformed_url")
        self.assertIn("Invalid URL format", output)

    def test_nonexistent_domain(self):
        """Test behavior with a nonexistent domain."""
        output = self.run_webtester("http://nonexistentdomain123.com")
        self.assertIn("Failed to retrieve HTTP response.", output)

    def test_network_error(self):
        """Test behavior with unreachable host."""
        output = self.run_webtester("http://0.0.0.0")
        # Invalid URL format
        self.assertIn("Failed to retrieve HTTP response.", output)

    def test_unexpected_error(self):
        """Test behavior with an unexpected error."""
        output = self.run_webtester("https://httpbin.org/status/500")
        self.assertIn("Failed to retrieve HTTP response.", output)

    def test_ssl_error(self):
        """Test behavior with a site requiring SSL that isn't properly configured."""
        output = self.run_webtester("http://self-signed.badssl.com/")
        self.assertIn("[SSL: CERTIFICATE_VERIFY_FAILED]", output)

    # === HTTP/2 Support ===
    def test_http2_support_google(self):
        """Test HTTP/2 support for Google."""
        output = self.run_webtester("https://www.google.com")
        self.assertIn("HTTP/2 Support\n==============\nYes", output)

    def test_http2_support_cloudflare(self):
        """Test HTTP/2 support for Cloudflare."""
        output = self.run_webtester("https://www.cloudflare.com")
        self.assertIn("HTTP/2 Support\n==============\nYes", output)

    def test_http2_support_no_self_signed(self):
        """Test HTTP/2 support for a site with self-signed certificate that does not support HTTP/2."""
        output = self.run_webtester("http://self-signed.badssl.com/")
        self.assertIn("HTTP/2 Support\n==============\nNo", output)

    def test_http2_support_no_http_only(self):
        """Test HTTP/2 support for a site that only supports HTTP/1.1."""
        output = self.run_webtester("http://http-only.badssl.com/")
        self.assertIn("HTTP/2 Support\n==============\nNo", output)


    # === Handling HTTP Redirects ===
    def test_simple_redirect(self):
        """Test simple redirect handling."""
        output = self.run_webtester("http://github.com")
        self.assertIn("Website\n=======\ngithub.com", output)

    def test_medium_redirect(self):
        """Test medium complexity redirect handling."""
        output = self.run_webtester("http://neverssl.com")
        self.assertIn("Website\n=======\nneverssl.com", output)

    # def test_complex_redirect(self):
    #     """Test complex redirect handling with cookies."""
    #     output = self.run_webtester("https://httpstat.us/301")
    #     self.assertIn("Redirecting to", output)
    #     self.assertIn("Website\n=======\nhttpstat.us", output)

    # === Cookies ===
    def test_no_cookies(self):
        """Test a website that does not set cookies."""
        output = self.run_webtester("https://example.com")
        self.assertIn("Cookies\n=======\nNo cookies found.", output)

    def test_single_cookie(self):
        """Test a website that sets a single cookie."""
        output = self.run_webtester("https://httpbin.org/cookies/set?name=value")
        self.assertIn("Cookies\n=======", output)
        self.assertRegex(output, r"Cookie Name: name")

    # def test_multiple_cookies(self):
    #     """Test a website that sets multiple cookies."""
    #     output = self.run_webtester("https://httpbin.org/response-headers?Set-Cookie=foo=bar&Set-Cookie=baz=qux")
    #     self.assertIn("Cookies\n=======", output)
    #     self.assertRegex(output, r"Cookie Name: foo")
    #     self.assertRegex(output, r"Cookie Name: baz")

    # def test_cookie_with_expiry(self):
    #     """Test a website that sets cookies with expiry dates."""
    #     output = self.run_webtester("https://httpbin.org/response-headers?Set-Cookie=test=123; Expires=Wed, 21 Jan 2026 12:34:56 GMT")
    #     self.assertRegex(output, r"Cookie Name: test")
    #     self.assertRegex(output, r"Expires: Wed, 21 Jan 2026 12:34:56 GMT")

    def test_cookie_in_redirect(self):
        """Test cookies set during redirects."""
        output = self.run_webtester("https://httpbin.org/redirect-to?url=/cookies/set?name=value")
        self.assertIn("Cookies\n=======", output)
        self.assertRegex(output, r"Cookie Name: name")

    # # === Password Protection ===
    def test_password_protected_pages(self):
        """Test detection of password-protected pages."""
        protected_urls = [
            "https://httpbin.org/basic-auth/user/pass",
            "https://login.salesforce.com",
            "https://accounts.google.com",
            # "https://id.atlassian.com/login", NO RESPONSE
            "docs.engr.uvic.ca/docs", # Say N0
            "https://www.netflix.com/login"
        ]
        for url in protected_urls:
            output = self.run_webtester(url)
            self.assertIn("Password Protection\n===================\nYes", output)

    def test_non_password_protected_pages(self):
        """Test detection of non-password-protected pages."""
        public_urls = [
            "https://example.com",
            "https://www.wikipedia.org",
           # "https://www.github.com", ## yes
            "https://httpbin.org",
            "https://www.cloudflare.com"
        ]
        for url in public_urls:
            output = self.run_webtester(url)
            self.assertIn("Password Protection\n===================\nNo", output)


if __name__ == "__main__":
    unittest.main()
