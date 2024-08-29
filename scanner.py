import re
import requests
from urllib.parse import urlparse

class WebAppSecurityScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def scan_for_sql_injection(self, url):
        payloads = ["'", "\"", " OR 1=1", "' OR '1'='1", "\" OR \"1\"=\"1"]
        for payload in payloads:
            test_url = f"{url}{payload}"
            response = self.session.get(test_url)
            if "sql" in response.text.lower() or "error" in response.text.lower():
                return True, test_url
        return False, None

    def scan_for_xss(self, url):
        payloads = ["<script>alert('XSS')</script>", "\" onmouseover=\"alert('XSS')", "' onmouseover='alert('XSS')"]
        for payload in payloads:
            test_url = f"{url}{payload}"
            response = self.session.get(test_url)
            if payload in response.text:
                return True, test_url
        return False, None

    def scan_open_ports(self, hostname):
        open_ports = []
        common_ports = [21, 22, 23, 25, 80, 110, 443, 445, 1433, 3306, 3389]
        for port in common_ports:
            response = self._check_port(hostname, port)
            if response:
                open_ports.append(port)
        return open_ports

    def _check_port(self, hostname, port):
        import socket
        try:
            sock = socket.create_connection((hostname, port), timeout=1)
            sock.close()
            return True
        except socket.error:
            return False

    def run_all_scans(self):
        parsed_url = urlparse(self.base_url)
        results = {}

        print(f"Scanning for SQL Injection on {self.base_url}...")
        sql_result, sql_url = self.scan_for_sql_injection(self.base_url)
        results['sql_injection'] = {'found': sql_result, 'url': sql_url}

        print(f"Scanning for XSS on {self.base_url}...")
        xss_result, xss_url = self.scan_for_xss(self.base_url)
        results['xss'] = {'found': xss_result, 'url': xss_url}

        print(f"Scanning for open ports on {parsed_url.hostname}...")
        open_ports = self.scan_open_ports(parsed_url.hostname)
        results['open_ports'] = open_ports

        return results

# Usage example:
if __name__ == "__main__":
    scanner = WebAppSecurityScanner("http://example.com")
    scan_results = scanner.run_all_scans()
