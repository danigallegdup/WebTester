import threading
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer


class CyclicRedirectHandler(BaseHTTPRequestHandler):
    """Handler to create cyclic redirects."""
    def do_GET(self):
        """Handle GET request with a redirect to the same URL."""
        self.send_response(301)  # HTTP status code for redirect
        self.send_header('Location', self.path)  # Redirect to the same path
        self.end_headers()


def start_cyclic_redirect_server():
    """Start the cyclic redirect server in a separate thread."""
    server_address = ('localhost', 8000)
    httpd = HTTPServer(server_address, CyclicRedirectHandler)

    def run_server():
        print("Starting cyclic redirect server on http://localhost:8000")
        httpd.serve_forever()

    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True  # Ensure the thread exits when the program does
    server_thread.start()
    return httpd, server_thread


def run_webtester():
    """Run WebTester.py with localhost:8000 and capture its output."""
    print("Running WebTester.py on http://localhost:8000...")
    result = subprocess.run(
        ["python", "WebTester.py", "http://localhost:8000"],
        capture_output=True,
        text=True
    )
    print("\n=== WebTester Output ===")
    print(result.stdout)
    print("\n=== WebTester Error Output ===")
    print(result.stderr)
    print("=========================")


def main():
    # Start the server in a separate thread
    httpd, server_thread = start_cyclic_redirect_server()

    try:
        # Run WebTester.py to test the cyclic redirect server
        run_webtester()
    finally:
        # Shut down the server after testing
        print("\nShutting down the server...")
        httpd.shutdown()
        server_thread.join()
        print("Server stopped.")


if __name__ == "__main__":
    main()
