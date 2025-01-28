import unittest
import subprocess

"""
run : python -m unittest Test.py

"""


class TestWebTester(unittest.TestCase):
    def run_webtester(self, url):
        """Helper function to run WebTester.py and capture output."""
        result = subprocess.run([
            "python3", "SmartClient.py", url
        ], capture_output=True, text=True)
        return result.stdout

    def test_http2_support(self):
        """Test HTTP/2 support check for a known website."""
        output = self.run_webtester("https://www.google.com")
        self.assertIn("HTTP/2 Support\n==============\nYes", output)



    def test_redirect_handling(self):
        """Test proper handling of redirects."""
        output = self.run_webtester("http://github.com")
        self.assertIn("Website\n=======\ngithub.com", output)

    def test_password_protection(self):
        """Test detection of password protection."""
        output = self.run_webtester("https://httpbin.org/basic-auth/user/pass")
        self.assertIn("Password Protection\n===================\nYes", output)
    
    def test_no_password_protection(self):
        """Test detection of password protection."""
        output = self.run_webtester("https://httpbin.org/")
        self.assertIn("Password Protection\n===================\nNo", output)
    


    def test_no_cookies(self):
        """Test a website that does not set cookies."""
        output = self.run_webtester("https://example.com")
        self.assertIn("Cookies\n=======\nNo cookies found.", output)

    def test_multiple_cookies(self):
        """Test a website that sets multiple cookies."""
        output = self.run_webtester("https://httpbin.org/cookies/set?name=value")
        self.assertIn("Cookies\n=======", output)
        self.assertRegex(output, r"Cookie Name: name")

    def test_malformed_url(self):
        """Test behavior with a malformed URL."""
        output = self.run_webtester("malformed_url")
        self.assertIn("Invalid URL format", output)

    def test_nonexistent_domain(self):
        """Test behavior with a nonexistent domain."""
        output = self.run_webtester("http://nonexistentdomain123.com")
        self.assertIn("Failed to retrieve HTTP response.", output)

    def test_http_only(self):
        """Test a website that only supports HTTP."""
        output = self.run_webtester("http://http-only.badssl.com/")
        self.assertIn("HTTP/2 Support\n==============\nNo", output)

    def test_complex_redirect_with_cookies(self):
        """Test handling of redirects and cookies together."""
        output = self.run_webtester("https://www.reddit.com")
        self.assertIn("Cookies\n=======", output)

if __name__ == "__main__":
    unittest.main()
