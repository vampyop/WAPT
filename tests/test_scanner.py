from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse
import json
import unittest

from webscan.scanner import PageParser, Scanner, normalize_target, redact_url, to_json


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        pass

    def _send(self, status: int, body: bytes = b"", content_type: str = "text/html; charset=utf-8", extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "sessionid=fixture-secret; Path=/")
        if self.headers.get("Origin"):
            self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
            self.send_header("Access-Control-Allow-Credentials", "true")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        self.server.seen.append(("GET", self.path, self.headers.get("Cookie")))
        parsed = urlparse(self.path)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://outside.invalid/landing")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/swagger.json":
            self._send(200, b"{}", "application/json")
            return
        if parsed.path == "/headers":
            self._send(200, b"<html><body>ok</body></html>", extra={
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
                "Referrer-Policy": "unsafe-url",
            })
            return
        if parsed.path == "/db-error":
            self._send(500, b"<html>SQL syntax error near value in MySQL query</html><pre>Traceback (most recent call last):</pre>")
            return
        if parsed.path == "/search":
            value = parse_qs(parsed.query).get("q", [""])[0]
            if value == "'":
                body = b"<html>SQL syntax error near value in MySQL query</html>"
            else:
                body = f"<html><p>Query: {value}</p></html>".encode()
            self._send(200, body)
            return
        if parsed.path == "/":
            body = (
                b"<html><body><form method='GET' action='http://outside.invalid/login'><input name='password' type='password'></form>"
                b"<form method='POST' action='/save'><input name='comment'></form>"
                b"<img src='http://cdn.invalid/pixel.png'><a href='/search?q=hello'>search</a>"
                b"<a href='https://outside.invalid/'>external</a></body></html>"
            )
            self._send(200, body)
            return
        self._send(404, b"<html>not found</html>")

    def do_OPTIONS(self) -> None:
        self.server.seen.append(("OPTIONS", self.path, self.headers.get("Cookie")))
        self._send(204, b"", extra={"Allow": "GET, POST, DELETE, OPTIONS"})

    def do_POST(self) -> None:
        self.server.seen.append(("POST", self.path, self.headers.get("Cookie")))
        self._send(200, b"unexpected post")

    def do_DELETE(self) -> None:
        self.server.seen.append(("DELETE", self.path, self.headers.get("Cookie")))
        self._send(200, b"unexpected delete")


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.server.seen = []
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        self.server.seen.clear()

    def test_normalize_and_redact(self) -> None:
        self.assertEqual(normalize_target("example.com/path#fragment"), "https://example.com/path")
        with self.assertRaises(ValueError):
            normalize_target("ftp://example.com")
        self.assertEqual(redact_url("https://example.com/find?q=private&x=1"), "https://example.com/find?q=%5Bredacted%5D&x=%5Bredacted%5D")

    def test_parser_collects_links_forms_and_mixed_content(self) -> None:
        parser = PageParser()
        parser.feed("<form method='POST'><input name='csrf_token'><img src='http://cdn.invalid/a.png'><a href='/next'>next</a></form>")
        parser.close()
        self.assertEqual(parser.links, ["/next"])
        self.assertEqual(parser.forms[0].method, "POST")
        self.assertIn(("csrf_token", "input"), parser.forms[0].fields)
        self.assertEqual(parser.mixed_content, [("img", "http://cdn.invalid/a.png")])

    def test_scan_detects_wapt_signals_without_submitting_forms(self) -> None:
        result = Scanner(self.base, delay=0, max_requests=35, max_pages=5, active_probes=True).run()
        titles = {finding.title for finding in result.findings}
        self.assertIn("CORS reflects arbitrary origins with credentials", titles)
        self.assertIn("Risky HTTP methods advertised", titles)
        self.assertIn("Password field uses GET form method", titles)
        self.assertIn("Database error triggered by a quote probe", titles)
        self.assertIn("Unescaped test marker reflected in HTML response", titles)
        self.assertIn("Conventional metadata path responds: /swagger.json", titles)
        self.assertIn("POST form has no recognizable CSRF field", titles)
        self.assertIn("Cookie missing recommended attributes", titles)
        self.assertLessEqual(result.requests_made, 35)
        self.assertLessEqual(result.pages_crawled, 5)
        self.assertFalse(any(method in ("POST", "DELETE") for method, _, _ in self.server.seen))
        self.assertTrue(all(cookie is None for _, _, cookie in self.server.seen))
        self.assertTrue(all("fixture-secret" not in finding.evidence for finding in result.findings))
        json.loads(to_json(result))

    def test_passive_scan_does_not_send_injection_probes(self) -> None:
        Scanner(self.base, delay=0, max_requests=30, max_pages=3).run()
        paths = [path for _, path, _ in self.server.seen]
        self.assertTrue(any(path.startswith("/search?q=hello") for path in paths))
        self.assertFalse(any("wgprobe" in path or "q=%27" in path for path in paths))

    def test_headers_and_error_disclosures(self) -> None:
        header_result = Scanner(self.base + "/headers", delay=0, max_requests=1, max_pages=1).run()
        header_titles = {finding.title for finding in header_result.findings}
        self.assertIn("CSP contains unsafe script directives", header_titles)
        self.assertIn("Referrer-Policy exposes full URLs", header_titles)

        error_result = Scanner(self.base + "/db-error", delay=0, max_requests=1, max_pages=1).run()
        error_titles = {finding.title for finding in error_result.findings}
        self.assertIn("Database error details appear in response", error_titles)
        self.assertIn("Application stack trace appears in response", error_titles)

    def test_network_errors_are_reported(self) -> None:
        unused = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        port = unused.server_port
        unused.server_close()
        result = Scanner(f"http://127.0.0.1:{port}", timeout=0.2, delay=0, max_requests=1).run()
        self.assertEqual(result.requests_made, 1)
        self.assertEqual(len(result.errors), 1)

    def test_https_form_with_http_action_is_reported(self) -> None:
        scanner = Scanner("https://app.example", delay=0)
        parser = PageParser()
        parser.feed("<form method='POST' action='http://app.example/submit'><input type='password' name='password'></form>")
        parser.close()
        scanner.inspect_html("https://app.example/login", parser)
        self.assertIn("Form submits over cleartext HTTP", {finding.title for finding in scanner.findings})

    def test_https_page_with_http_resource_is_reported(self) -> None:
        scanner = Scanner("https://app.example", delay=0)
        parser = PageParser()
        parser.feed("<img src='http://cdn.example/image.png'>")
        parser.close()
        scanner.inspect_html("https://app.example/page", parser)
        self.assertIn("HTTP resource embedded in HTTPS page", {finding.title for finding in scanner.findings})

    def test_cross_origin_redirect_is_not_followed(self) -> None:
        result = Scanner(self.base + "/redirect", delay=0, max_requests=12, max_pages=1).run()
        self.assertTrue(any(finding.title == "Redirect not followed" for finding in result.findings))
        self.assertFalse(any("outside.invalid" in path for _, path, _ in self.server.seen))

    def test_global_request_limit_is_enforced(self) -> None:
        result = Scanner(self.base, delay=0, max_requests=2, max_pages=5).run()
        self.assertEqual(result.requests_made, 2)
        self.assertEqual(len(self.server.seen), 2)


if __name__ == "__main__":
    unittest.main()
