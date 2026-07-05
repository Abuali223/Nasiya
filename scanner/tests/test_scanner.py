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

from scanner.engine import Scanner, scan_many  # noqa: E402
from scanner.http_client import HttpClient  # noqa: E402
from scanner.models import Severity  # noqa: E402

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


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
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        p = u.path
        if p == "/":
            self._send(
                "<html><head><title>T</title></head><body>"
                "<a href='/search?q=x'>s</a><a href='/item?id=1'>i</a>"
                "<a href='/go?url=/home'>g</a><a href='/admin'>a</a>"
                "<a href='/read?file=a.txt'>r</a><a href='/ping?host=127.0.0.1'>p</a>"
                "<a href='/fetch?url=http://x'>f</a><a href='/login'>l</a>"
                "<form method='post' action='/save'>"
                "<input name='name'><button>ok</button></form></body></html>",
                extra=[("Set-Cookie", "sid=abc; Path=/")],
            )
        elif p == "/search":
            self._send(f"<html><body>Natija: {qs.get('q', [''])[0]}</body></html>")
        elif p == "/item":
            i = qs.get("id", [""])[0]
            if any(c in i for c in "'\"\\"):
                self._send("You have an error in your SQL syntax; check the manual "
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
        elif p == "/read":
            f = qs.get("file", [""])[0]
            if "etc/passwd" in f or "win.ini" in f:
                self._send(PASSWD, ctype="text/plain")
            else:
                self._send(f"<html><body>Fayl: {f}</body></html>")
        elif p == "/ping":
            host = qs.get("host", [""])[0]
            if any(c in host for c in [";", "|", "`", "$", "&"]) and "id" in host:
                self._send("uid=0(root) gid=0(root) groups=0(root)\n", ctype="text/plain")
            else:
                self._send(f"<html><body>Ping {host}</body></html>")
        elif p == "/fetch":
            url = qs.get("url", [""])[0]
            if "169.254.169.254" in url:
                self._send("ami-id\ninstance-id\niam/security-credentials/\n", ctype="text/plain")
            else:
                self._send(f"<html><body>Fetched {url}</body></html>")
        elif p == "/login":
            self._send("<html><body><form method='post' action='/login'>"
                       "<input name='username'><input type='password' name='password'>"
                       "</form></body></html>")
        else:
            self._send("<html><body>404 Not Found</body></html>", code=404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        u = urllib.parse.urlparse(self.path)
        if u.path == "/login":
            d = urllib.parse.parse_qs(body)
            if d.get("username", [""])[0] == "admin" and d.get("password", [""])[0] == "admin":
                self._send("<html><body>Xush kelibsiz, admin!</body></html>",
                           extra=[("Set-Cookie", "session=valid; Path=/")])
            else:
                self._send("<html><body><form method='post' action='/login'>"
                           "<input type='password' name='password'></form>Xato</body></html>")
        else:
            self._send("<html><body>ok</body></html>")


def _start_server():
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _VulnHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


class ScannerIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = _start_server()
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _scan(self, active=True, creds=False):
        client = HttpClient(delay=0.0, verify_tls=False)
        scanner = Scanner(client=client, max_pages=20, active=active,
                          check_default_creds=creds)
        return scanner.scan(self.base)

    def test_finds_core_vulnerabilities(self):
        result = self._scan(active=True)
        checks = {f.check for f in result.findings}
        for expected in (
            "SQL Injection", "Reflected XSS", "Maxfiy fayllar va panellar",
            "CSRF himoyasi", "Ochiq yo'naltirish (Open Redirect)", "Clickjacking",
            "Path Traversal / LFI", "Command Injection", "SSRF",
        ):
            self.assertIn(expected, checks, f"{expected} topilmadi")

    def test_critical_severities(self):
        result = self._scan(active=True)
        by_check = {}
        for f in result.findings:
            by_check.setdefault(f.check, []).append(f)
        self.assertTrue(any(f.severity == Severity.CRITICAL
                            for f in by_check["SQL Injection"]))
        self.assertTrue(any(f.severity == Severity.CRITICAL
                            for f in by_check["Path Traversal / LFI"]))
        self.assertTrue(any(f.severity == Severity.CRITICAL
                            for f in by_check["Command Injection"]))

    def test_ssrf_confirmed_not_reflection(self):
        result = self._scan(active=True)
        ssrf = [f for f in result.findings if f.check == "SSRF"]
        # /fetch?url= haqiqiy SSRF — tasdiqlangan (High) bo'lishi kerak
        confirmed = [f for f in ssrf if f.severity == Severity.HIGH]
        self.assertTrue(confirmed)
        self.assertTrue(any("fetch" in f.url for f in confirmed))
        # reflection'ga asoslangan soxta "High" tasdiq bo'lmasligi kerak
        for f in confirmed:
            self.assertIn("fetch", f.url)

    def test_default_credentials_optin(self):
        # creds o'chiq — topilmasligi kerak
        off = self._scan(active=True, creds=False)
        self.assertNotIn("Standart parollar", {f.check for f in off.findings})
        # creds yoqilgan — admin/admin topilishi kerak
        on = self._scan(active=True, creds=True)
        creds = [f for f in on.findings if f.check == "Standart parollar"]
        self.assertTrue(creds)
        self.assertEqual(creds[0].severity, Severity.CRITICAL)

    def test_passive_skips_active_payloads(self):
        result = self._scan(active=False)
        checks = {f.check for f in result.findings}
        for skipped in ("SQL Injection", "Reflected XSS", "Path Traversal / LFI",
                        "Command Injection", "SSRF"):
            self.assertNotIn(skipped, checks)
        self.assertIn("Xavfsizlik sarlavhalari", checks)

    def test_no_duplicate_findings(self):
        result = self._scan(active=True)
        keys = [f.key() for f in result.findings]
        self.assertEqual(len(keys), len(set(keys)))

    def test_scan_many_multiple_sites(self):
        httpd2 = _start_server()
        try:
            base2 = f"http://127.0.0.1:{httpd2.server_address[1]}"
            results = scan_many(
                [self.base, base2],
                concurrency=2,
                client_factory=lambda: HttpClient(delay=0.0, verify_tls=False),
                max_pages=15,
            )
            self.assertEqual(len(results), 2)
            targets = {r.target for r in results}
            self.assertEqual(targets, {self.base, base2})
            for r in results:
                self.assertTrue(r.findings)
        finally:
            httpd2.shutdown()
            httpd2.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
