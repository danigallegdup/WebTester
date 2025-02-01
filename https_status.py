import unittest

class TestHttpStatusCodes(unittest.TestCase):
    
    def run_webtester(self, url):
        """Helper function to simulate running SmartClient.py."""
        import subprocess
        result = subprocess.run(["python", "SmartClient.py", url], capture_output=True, text=True)
        return result.stdout

    # ✅ 200 OK
    def test_200(self):
        """Test successful request (200 OK)."""
        output = self.run_webtester("https://httpbin.org/status/200")
        self.assertIn("✅ 200 OK - Request was successful.", output)

    # ✅ 201 Created
    def test_201(self):
        """Test resource creation (201 Created)."""
        output = self.run_webtester("https://httpbin.org/status/201")
        self.assertIn("✅ 201 Created - Resource was successfully created.", output)

    # ✅ 204 No Content
    def test_204(self):
        """Test no content response (204 No Content)."""
        output = self.run_webtester("https://httpbin.org/status/204")
        self.assertIn("✅ 204 No Content - Request successful but no content returned.", output)

    # 🔄 301 Moved Permanently
    def test_301(self):
        """Test permanent redirect (301 Moved Permanently)."""
        output = self.run_webtester("https://httpbin.org/status/301")
        self.assertIn("🔄 301 Moved Permanently - Resource has moved to a new URL.", output)

    # 🔄 302 Found
    def test_302(self):
        """Test temporary redirect (302 Found)."""
        output = self.run_webtester("https://httpbin.org/status/302")
        self.assertIn("🔄 302 Found - Temporary redirect.", output)

    # 🛑 304 Not Modified
    def test_304(self):
        """Test response with cached content (304 Not Modified)."""
        output = self.run_webtester("https://httpbin.org/status/304")
        self.assertIn("🛑 304 Not Modified - Cached response can be used.", output)

    # ❌ 400 Bad Request
    def test_400(self):
        """Test client error (400 Bad Request)."""
        output = self.run_webtester("https://httpbin.org/status/400")
        self.assertIn("❌ 400 Bad Request - Invalid request sent by client.", output)

    # 🔐 401 Unauthorized
    def test_401(self):
        """Test authentication required (401 Unauthorized)."""
        output = self.run_webtester("https://httpbin.org/status/401")
        self.assertIn("🔐 401 Unauthorized - Authentication required.", output)

    # ⛔ 403 Forbidden
    def test_403(self):
        """Test access restriction (403 Forbidden)."""
        output = self.run_webtester("https://httpbin.org/status/403")
        self.assertIn("⛔ 403 Forbidden - You don’t have permission to access this resource.", output)

    # ❌ 404 Not Found
    def test_404(self):
        """Test resource not found (404 Not Found)."""
        output = self.run_webtester("https://httpbin.org/status/404")
        self.assertIn("❌ 404 Not Found - The requested resource does not exist.", output)

    # ⚠️ 405 Method Not Allowed
    def test_405(self):
        """Test unsupported HTTP method (405 Method Not Allowed)."""
        output = self.run_webtester("https://httpbin.org/status/405")
        self.assertIn("⚠️ 405 Method Not Allowed - The HTTP method is not supported for this resource.", output)

    # ⏳ 408 Request Timeout
    def test_408(self):
        """Test slow client request (408 Request Timeout)."""
        output = self.run_webtester("https://httpbin.org/status/408")
        self.assertIn("⏳ 408 Request Timeout - The server timed out waiting for the request.", output)

    # ⚠️ 429 Too Many Requests
    def test_429(self):
        """Test rate limiting (429 Too Many Requests)."""
        output = self.run_webtester("https://httpbin.org/status/429")
        self.assertIn("⚠️ 429 Too Many Requests - Rate limit exceeded.", output)

    # 🔥 500 Internal Server Error
    def test_500(self):
        """Test server-side failure (500 Internal Server Error)."""
        output = self.run_webtester("https://httpbin.org/status/500")
        self.assertIn("🔥 500 Internal Server Error - Server encountered an unexpected condition.", output)

    # 🚧 502 Bad Gateway
    def test_502(self):
        """Test upstream failure (502 Bad Gateway)."""
        output = self.run_webtester("https://httpbin.org/status/502")
        self.assertIn("🚧 502 Bad Gateway - Invalid response from upstream server.", output)

    # 🚧 503 Service Unavailable
    def test_503(self):
        """Test server overload (503 Service Unavailable)."""
        output = self.run_webtester("https://httpbin.org/status/503")
        self.assertIn("🚧 503 Service Unavailable - Server is overloaded or under maintenance.", output)

    # ⏳ 504 Gateway Timeout
    def test_504(self):
        """Test slow upstream server (504 Gateway Timeout)."""
        output = self.run_webtester("https://httpbin.org/status/504")
        self.assertIn("⏳ 504 Gateway Timeout - Upstream server did not respond in time.", output)

    # ⚠️ Unexpected Status Code (999)
    def test_unexpected_status(self):
        """Test an unexpected HTTP status code (e.g., 999)."""
        output = self.run_webtester("https://httpbin.org/status/999")
        self.assertIn("⚠️ Unexpected HTTP status code received: 999", output)

# Run the tests
if __name__ == '__main__':
    unittest.main()
