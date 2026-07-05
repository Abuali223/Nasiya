"""Integratsiya testi: ataylab zaif server ishga tushirib, skanerni sinaydi."""

import http.server
import os
import socketserver
import sys
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# lokal ulanishlar proksisiz bo'lsin
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost")

from scanner.engine import Scanner  # noqa: E402
from scanner.http_client import HttpClient  # noqa: E402
from scanner.models import Severity  # noqa: E402


class _VulnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "TestServer/1.4.2")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        p = parsed.path
        if p == "/":
            self._send(
                "<html><head><title>T</title></head><body>"
                "<a href='/search?q=x'>s</a><a href='/item?id=1'>i</a>"
                "<a href='/go?url=/home'>g</a><a href='/admin'>a</a>"
                "<form method='post' action='/save'>"
                "<input name='name'><button>ok</button></form></body></html>",
                extra=[("Set-Cookie", "sid=abc; Path=/")],
            )
        elif p == "/search":
            self._send(f"<html><body>Natija: {qs.get('q', [''])[0]}</body></html>")
        elif p == "/item":
            i = qs.get("id", [""])[0]
            if any(c in i for c in "'\"\\"):
                self._send(
                    "You have an error in your SQL syntax; check the manual "
                    "that corresponds to your MySQL server version", code=500)
            else:
                self._send(f"<html><body>Mahsulot #{i}</body></html>")
        elif p == "/go":
            self._send("", code=302, extra=[("Location", qs.get("url", ["/"])[0])])
        elif p == "/admin":
            self._send("<html><body><form>"
                       "<input type='password' name='pw'></form></body></html>")
        elif p == "/.env":
            self._send("DB_PASSWORD=secret123\nAPI_KEY=x\n", ctype="text/plain")
        else:
            self._send("<html><body>404 Not Found</body></html>", code=404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self._send("<html><body>ok</body></html>")


class ScannerIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        socketserver.TCPServer.allow_reuse_address = True
        cls.httpd = socketserver.TCPServer(("127.0.0.1", 0), _VulnHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _scan(self, active=True):
        client = HttpClient(delay=0.0, verify_tls=False)
        scanner = Scanner(client=client, max_pages=20, active=active)
        return scanner.scan(f"http://127.0.0.1:{self.port}")

    def test_finds_expected_vulnerabilities(self):
        result = self._scan(active=True)
        checks = {f.check for f in result.findings}
        self.assertIn("SQL Injection", checks)
        self.assertIn("Reflected XSS", checks)
        self.assertIn("Maxfiy fayllar va panellar", checks)
        self.assertIn("CSRF himoyasi", checks)
        self.assertIn("Ochiq yo'naltirish (Open Redirect)", checks)
        self.assertIn("Clickjacking", checks)

        # .env kritik topilishi kerak
        env = [f for f in result.findings if "/.env" in f.url]
        self.assertTrue(env)
        self.assertEqual(env[0].severity, Severity.CRITICAL)

        # SQLi kritik
        sqli = [f for f in result.findings if f.check == "SQL Injection"]
        self.assertTrue(any(f.severity == Severity.CRITICAL for f in sqli))

    def test_passive_skips_active_payloads(self):
        result = self._scan(active=False)
        checks = {f.check for f in result.findings}
        self.assertNotIn("SQL Injection", checks)
        self.assertNotIn("Reflected XSS", checks)
        self.assertNotIn("Ochiq yo'naltirish (Open Redirect)", checks)
        # passiv rejimda ham sarlavha tekshiruvi ishlaydi
        self.assertIn("Xavfsizlik sarlavhalari", checks)

    def test_no_duplicate_findings(self):
        result = self._scan(active=True)
        keys = [f.key() for f in result.findings]
        self.assertEqual(len(keys), len(set(keys)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
