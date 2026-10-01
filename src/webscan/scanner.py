from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.message import Message
from html.parser import HTMLParser
import ssl
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import json
import re
import secrets
import time



BODY_LIMIT = 512 * 1024
MAX_ACTIVE_PARAMETERS = 8
DISCOVERY_PATHS = (
    "/robots.txt",
    "/.well-known/security.txt",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/swagger/",
)
SENSITIVE_PARAMETER_PARTS = ("token", "secret", "password", "passwd", "auth", "session", "csrf", "xsrf", "key", "code")
SKIP_PATH_PARTS = ("logout", "logoff", "signout", "delete", "destroy", "remove", "unsubscribe", "checkout", "purchase", "transfer")
STATIC_SUFFIXES = (".7z", ".avi", ".css", ".doc", ".docx", ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".js", ".mp3", ".mp4", ".pdf", ".png", ".ppt", ".pptx", ".rar", ".svg", ".tar", ".tgz", ".woff", ".woff2", ".xls", ".xlsx", ".zip")
SQL_ERROR_PATTERNS = (
    ("MySQL error", re.compile(r"SQL syntax.{0,80}MySQL|mysql_fetch_(?:array|assoc|row)|Warning:\s*mysql_", re.I)),
    ("PostgreSQL error", re.compile(r"PostgreSQL.{0,80}(?:ERROR|error)|pg_query\(\)|SQLSTATE\[\w+\]", re.I)),
    ("Oracle error", re.compile(r"ORA-\d{5}", re.I)),
    ("SQL Server error", re.compile(r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string", re.I)),
    ("SQLite error", re.compile(r"SQLite(?:3)?::|sqlite3?\.OperationalError", re.I)),
)
STACK_TRACE_PATTERNS = (
    ("Python traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("Java exception", re.compile(r"(?:Exception|Error) in thread [\"']|\bat [\w.$]+\([^)]*\.java:\d+\)")),
    (".NET stack trace", re.compile(r" at [\w.]+\([^\r\n]*\) in [^\r\n]+:\s*line \d+", re.I)),
)


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    url: str
    evidence: str
    remediation: str
    cwe: str = ""
    owasp: str = ""


@dataclass
class ScanResult:
    target: str
    scanned_at: str
    duration_seconds: float
    requests_made: int
    pages_crawled: int
    findings: list[Finding]
    errors: list[str]


@dataclass
class FormInfo:
    action: str
    method: str
    fields: list[tuple[str, str]]


class HttpResponse:
    def __init__(self, raw) -> None:
        self.raw = raw
        self.status_code = getattr(raw, "status", getattr(raw, "code", 0))
        self.headers = raw.headers
        self.url = raw.geturl()

    def read(self, limit: int) -> bytes:
        return self.raw.read(limit)

    def close(self) -> None:
        self.raw.close()


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PageParser(HTMLParser):
    """Collect navigation and form metadata without retaining page content or field values."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.mixed_content: list[tuple[str, str]] = []
        self.forms: list[FormInfo] = []
        self._form: FormInfo | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        tag = tag.lower()
        if tag == "form":
            self._finish_form()
            self._form = FormInfo(values.get("action") or "", (values.get("method") or "GET").upper(), [])
        elif self._form is not None and tag in ("input", "select", "textarea", "button"):
            self._form.fields.append((values.get("name") or "", (values.get("type") or tag).lower()))

        if tag in ("a", "area") and values.get("href"):
            self.links.append(values["href"] or "")

        resource = values.get("src")
        if tag == "link" and "stylesheet" in (values.get("rel") or "").lower().split():
            resource = values.get("href")
        if resource and tag in ("script", "iframe", "img", "audio", "video", "source", "link"):
            self.mixed_content.append((tag, resource))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._finish_form()

    def close(self) -> None:
        super().close()
        self._finish_form()

    def _finish_form(self) -> None:
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


class Scanner:
    """Bounded web assessment for explicitly authorized, same-origin targets."""

    def __init__(
        self,
        target: str,
        timeout: float = 8.0,
        delay: float = 0.35,
        max_requests: int = 50,
        max_pages: int = 10,
        active_probes: bool = False,
    ) -> None:
        self.target = normalize_target(target)
        self.origin = urlparse(self.target)
        self.base_url = self.origin._replace(query="", fragment="").geturl().rstrip("/")
        self.timeout = timeout
        self.delay = max(0.0, delay)
        self.max_requests = max(1, max_requests)
        self.max_pages = max(1, max_pages)
        self.active_probes = active_probes
        self.user_agent = "WebGuard-WAPT/0.3 (+authorized low-impact assessment)"
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.requests_made = 0
        self.pages_crawled = 0
        self._finding_keys: set[tuple[str, str, str]] = set()

    def same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        try:
            return (
                not parsed.username
                and not parsed.password
                and parsed.scheme == self.origin.scheme
                and parsed.hostname == self.origin.hostname
                and effective_port(parsed) == effective_port(self.origin)
            )
        except ValueError:
            return False

    def request(self, url: str, method: str = "GET", headers: dict[str, str] | None = None) -> HttpResponse | None:
        if self.requests_made >= self.max_requests or not self.same_origin(url):
            return None
        if self.requests_made and self.delay:
            time.sleep(self.delay)
        self.requests_made += 1
        request_headers = {"User-Agent": self.user_agent, **(headers or {})}
        request = urllib.request.Request(url, method=method, headers=request_headers)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        try:
            return HttpResponse(opener.open(request, timeout=self.timeout))
        except urllib.error.HTTPError as response_error:
            # Preserve status and headers for 3xx/4xx/5xx while never following redirects.
            return HttpResponse(response_error)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.errors.append(f"{redact_url(url)}: {type(exc).__name__}")
            return None

    @staticmethod
    def close_response(response: HttpResponse) -> None:
        response.close()

    def read_body(self, response: HttpResponse) -> str:
        try:
            body = response.read(BODY_LIMIT)
        except OSError as exc:
            self.errors.append(f"{redact_url(response.url)}: {type(exc).__name__} while reading response")
            body = b""
        content_type = Message()
        content_type["content-type"] = response.headers.get("Content-Type", "")
        return body.decode(content_type.get_content_charset() or "utf-8", errors="replace")

    def add(
        self,
        check: str,
        severity: str,
        title: str,
        url: str,
        evidence: str,
        remediation: str,
        cwe: str = "",
        owasp: str = "",
    ) -> None:
        report_url = redact_url(url)
        key = (check, title, report_url)
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            self.findings.append(Finding(check, severity, title, report_url, evidence[:300], remediation, cwe, owasp))

    def run(self) -> ScanResult:
        started = time.monotonic()
        if self.origin.scheme != "https":
            self.add("transport", "MEDIUM", "Target does not use HTTPS", self.target, "Target URL uses HTTP", "Serve the application over HTTPS and redirect HTTP to HTTPS.", "CWE-319", "A02:2021 Cryptographic Failures")
        queue = [self.target]
        queued = {canonical_url(self.target)}
        page_urls: list[str] = []

        while queue and self.pages_crawled < self.max_pages and self.requests_made < self.max_requests:
            url = queue.pop(0)
            response = self.request(url)
            if response is None:
                continue
            try:
                if 300 <= response.status_code < 400:
                    location = response.headers.get("Location", "")
                    destination = urljoin(url, location) if location else ""
                    note = "redirect response was not followed"
                    if destination and not self.same_origin(destination):
                        note = "cross-origin redirect was not followed"
                    self.add("redirect", "INFO", "Redirect not followed", url, f"HTTP {response.status_code}; {note}", "Review redirect destinations and assess each in-scope URL separately.")
                    continue
                self.inspect_headers(response)
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                    continue

                body = self.read_body(response)
                if response.status_code >= 400:
                    self.inspect_error_disclosures(url, body)
                    continue
                if response.status_code < 200:
                    continue
                self.pages_crawled += 1
                page_urls.append(url)
                parser = PageParser()
                try:
                    parser.feed(body)
                    parser.close()
                except Exception as exc:  # malformed HTML should not stop a scan
                    self.errors.append(f"{redact_url(url)}: HTML parse error: {type(exc).__name__}")
                self.inspect_html(url, parser)
                self.inspect_error_disclosures(url, body)
                self.discover_links(url, parser.links, queue, queued)
            finally:
                self.close_response(response)

        if self.requests_made < self.max_requests:
            self.inspect_cors()
        if self.requests_made < self.max_requests:
            self.inspect_methods()
        for path in DISCOVERY_PATHS:
            if self.requests_made >= self.max_requests:
                break
            url = urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))
            response = self.request(url)
            if response is None:
                continue
            try:
                if response.status_code in (200, 203):
                    self.add(
                        "public-path", "INFO", f"Conventional metadata path responds: {path}", url,
                        f"HTTP {response.status_code}; content-type={response.headers.get('Content-Type', 'unknown')}",
                        "Confirm the response contains only intended public information and restrict operational documentation where appropriate.",
                        "CWE-538", "A05:2021 Security Misconfiguration",
                    )
            finally:
                self.close_response(response)

        if self.active_probes:
            self.run_active_probes(page_urls)

        return ScanResult(
            target=redact_url(self.target),
            scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            duration_seconds=round(time.monotonic() - started, 2),
            requests_made=self.requests_made,
            pages_crawled=self.pages_crawled,
            findings=self.findings,
            errors=self.errors,
        )

    def inspect_headers(self, response: HttpResponse) -> None:
        headers = {key.lower(): value for key, value in response.headers.items()}
        url = response.url
        if urlparse(url).scheme == "https" and "strict-transport-security" not in headers:
            self.add("headers", "MEDIUM", "Missing Strict-Transport-Security", url, "HSTS header absent", "Enable HSTS after confirming all relevant subdomains support HTTPS.", "CWE-523", "A05:2021 Security Misconfiguration")
        csp = headers.get("content-security-policy", "")
        if not csp:
            self.add("headers", "MEDIUM", "Missing Content-Security-Policy", url, "CSP header absent", "Define a restrictive Content-Security-Policy and test it in report-only mode before enforcement.", "CWE-693", "A05:2021 Security Misconfiguration")
        elif "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower():
            self.add("headers", "LOW", "CSP contains unsafe script directives", url, "CSP includes unsafe-inline or unsafe-eval", "Remove unsafe script directives where possible; use nonces or hashes for required inline scripts.", "CWE-693", "A05:2021 Security Misconfiguration")

        for header, label, fix in (
            ("x-content-type-options", "X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."),
            ("referrer-policy", "Referrer-Policy", "Set an appropriate Referrer-Policy, such as strict-origin-when-cross-origin."),
        ):
            if header not in headers:
                self.add("headers", "LOW", f"Missing {label}", url, f"{label} header absent", fix, "CWE-693", "A05:2021 Security Misconfiguration")
        if "permissions-policy" not in headers:
            self.add("headers", "INFO", "Missing Permissions-Policy", url, "Permissions-Policy header absent", "Restrict browser features the application does not need.", "CWE-693", "A05:2021 Security Misconfiguration")
        if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
            self.add("headers", "LOW", "No clickjacking protection detected", url, "Neither X-Frame-Options nor CSP frame-ancestors was found", "Set CSP frame-ancestors to the intended embedding policy, or use X-Frame-Options for legacy clients.", "CWE-1021", "A05:2021 Security Misconfiguration")
        if headers.get("referrer-policy", "").lower() == "unsafe-url":
            self.add("headers", "LOW", "Referrer-Policy exposes full URLs", url, "Referrer-Policy: unsafe-url", "Use a policy that avoids sending full paths and query strings to other origins.", "CWE-200", "A04:2021 Insecure Design")

        for header in ("server", "x-powered-by"):
            if headers.get(header):
                self.add("disclosure", "INFO", f"{header} header disclosed", url, f"{header}: {headers[header][:160]}", "Remove or minimize unnecessary implementation and version details.", "CWE-200", "A05:2021 Security Misconfiguration")

        raw_cookies = response.headers.get_all("Set-Cookie", [])
        for raw in raw_cookies:
            cookie_name = raw.partition(";")[0].split("=", 1)[0].strip()
            attrs = raw.partition(";")[2].lower()
            missing = [flag for flag in ("Secure", "HttpOnly") if flag.lower() not in attrs]
            same_site_none = "samesite=none" in attrs
            if "samesite=" not in attrs:
                missing.append("SameSite")
            if same_site_none and "secure" not in attrs:
                self.add("cookies", "MEDIUM", "SameSite=None cookie lacks Secure", url, f"Cookie name={cookie_name}; SameSite=None without Secure", "Set Secure on cookies using SameSite=None.", "CWE-614", "A05:2021 Security Misconfiguration")
            if missing:
                session_like = any(word in cookie_name.lower() for word in ("session", "auth", "token", "sid"))
                severity = "MEDIUM" if session_like and ("Secure" in missing or "HttpOnly" in missing) else "LOW"
                self.add("cookies", severity, "Cookie missing recommended attributes", url, f"Cookie name={cookie_name or '(unnamed)'}; missing={', '.join(missing)}", "Set Secure, HttpOnly, and an appropriate SameSite attribute on session cookies.", "CWE-1004", "A05:2021 Security Misconfiguration")

    def inspect_html(self, page_url: str, parser: PageParser) -> None:
        for tag, resource in parser.mixed_content:
            absolute = urljoin(page_url, resource)
            if urlparse(page_url).scheme == "https" and urlparse(absolute).scheme == "http":
                severity = "MEDIUM" if tag in ("script", "iframe", "link") else "LOW"
                self.add("mixed-content", severity, "HTTP resource embedded in HTTPS page", page_url, f"{tag} resource uses HTTP: {redact_url(absolute)}", "Serve all embedded resources over HTTPS and use a restrictive CSP upgrade-insecure-requests policy where appropriate.", "CWE-311", "A05:2021 Security Misconfiguration")

        for form in parser.forms:
            action = urljoin(page_url, form.action or page_url)
            has_password = any(field_type == "password" for _, field_type in form.fields)
            if urlparse(page_url).scheme == "https" and urlparse(action).scheme == "http":
                severity = "HIGH" if has_password else "MEDIUM"
                self.add("forms", severity, "Form submits over cleartext HTTP", page_url, f"{form.method} form action: {redact_url(action)}", "Submit forms only to HTTPS endpoints and enforce HTTPS server-side.", "CWE-319", "A02:2021 Cryptographic Failures")
            if form.method == "GET" and has_password:
                self.add("forms", "HIGH", "Password field uses GET form method", page_url, "A password input is present in a GET form; values may appear in URLs and logs", "Use POST over HTTPS for credentials and avoid placing secrets in URLs.", "CWE-598", "A02:2021 Cryptographic Failures")
            if form.method == "POST":
                has_csrf_name = any(any(key in name.lower() for key in ("csrf", "xsrf", "authenticity", "requestverification")) for name, _ in form.fields)
                if not has_csrf_name:
                    self.add("forms", "INFO", "POST form has no recognizable CSRF field", page_url, "No common CSRF token field name found; this is a heuristic only", "Confirm state-changing requests use server-validated CSRF defenses such as tokens and SameSite cookies.", "CWE-352", "A01:2021 Broken Access Control")

    def inspect_error_disclosures(self, page_url: str, body: str) -> None:
        for label, pattern in SQL_ERROR_PATTERNS:
            if pattern.search(body):
                self.add("error-disclosure", "MEDIUM", "Database error details appear in response", page_url, f"A {label} signature was found in the response body", "Return generic client errors and keep database diagnostics in protected server logs.", "CWE-209", "A05:2021 Security Misconfiguration")
                break
        for label, pattern in STACK_TRACE_PATTERNS:
            if pattern.search(body):
                self.add("error-disclosure", "LOW", "Application stack trace appears in response", page_url, f"A {label} signature was found in the response body", "Disable debug output in production and return a generic error page.", "CWE-209", "A05:2021 Security Misconfiguration")
                break

    def discover_links(self, page_url: str, links: list[str], queue: list[str], queued: set[str]) -> None:
        for href in links:
            candidate = canonical_url(urljoin(page_url, href))
            parsed = urlparse(candidate)
            if not self.same_origin(candidate) or parsed.path.lower().endswith(STATIC_SUFFIXES):
                continue
            if any(
                any(secret_part in key.lower() for secret_part in SENSITIVE_PARAMETER_PARTS)
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            ):
                continue
            path_and_query = (parsed.path + "?" + parsed.query).lower()
            if any(part in path_and_query for part in SKIP_PATH_PARTS):
                continue
            key = canonical_url(candidate)
            if key not in queued and len(queued) < self.max_pages * 6:
                queued.add(key)
                queue.append(candidate)

    def inspect_cors(self) -> None:
        response = self.request(self.target, headers={"Origin": "https://webguard.invalid"})
        if response is None:
            return
        try:
            if response.status_code < 200 or response.status_code >= 400:
                return
            allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
            allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            if allow_origin == "https://webguard.invalid" and allow_credentials:
                self.add("cors", "HIGH", "CORS reflects arbitrary origins with credentials", self.target, "The test Origin was reflected with Access-Control-Allow-Credentials: true", "Validate the Origin against a strict allowlist before returning credentialed CORS headers.", "CWE-942", "A05:2021 Security Misconfiguration")
            elif allow_origin == "*":
                severity = "LOW" if allow_credentials else "MEDIUM"
                self.add("cors", severity, "CORS allows all origins", self.target, f"Access-Control-Allow-Origin: *; credentials={str(allow_credentials).lower()}", "Confirm public cross-origin access is intentional; use an allowlist for private or user-specific data.", "CWE-942", "A05:2021 Security Misconfiguration")
        finally:
            self.close_response(response)

    def inspect_methods(self) -> None:
        response = self.request(self.target, method="OPTIONS")
        if response is None:
            return
        try:
            if response.status_code < 200 or response.status_code >= 400:
                return
            methods = {item.strip().upper() for item in response.headers.get("Allow", "").split(",") if item.strip()}
            risky = sorted(methods.intersection({"TRACE", "PUT", "DELETE", "CONNECT"}))
            if risky:
                self.add("methods", "MEDIUM", "Risky HTTP methods advertised", self.target, f"Allow: {', '.join(sorted(methods))}; review: {', '.join(risky)}", "Disable methods the application does not require and enforce authorization for every write operation.", "CWE-749", "A05:2021 Security Misconfiguration")
        finally:
            self.close_response(response)

    def run_active_probes(self, page_urls: list[str]) -> None:
        tested = 0
        for page_url in page_urls:
            parsed = urlparse(page_url)
            parameters = parse_qsl(parsed.query, keep_blank_values=True)
            for index, (name, value) in enumerate(parameters):
                if tested >= MAX_ACTIVE_PARAMETERS or self.requests_made >= self.max_requests:
                    return
                if any(secret_part in name.lower() for secret_part in SENSITIVE_PARAMETER_PARTS):
                    continue
                tested += 1
                marker = f"wgprobe{secrets.token_hex(4)}"
                injection = f"<{marker}>\"'"
                probe_pairs = list(parameters)
                probe_pairs[index] = (name, injection)
                probe_url = urlunparse(parsed._replace(query=urlencode(probe_pairs)))
                response = self.request(probe_url)
                if response is not None:
                    try:
                        body = self.read_body(response)
                        if f"<{marker}>" in body:
                            self.add("active-reflection", "LOW", "Unescaped test marker reflected in HTML response", page_url, "A harmless angle-bracket marker was returned without being encoded; confirm whether it lands in an executable HTML context", "Contextually encode untrusted input and validate the exact rendering context. This signal is not proof of exploitable XSS.", "CWE-79", "A03:2021 Injection")
                    finally:
                        self.close_response(response)

                if self.requests_made >= self.max_requests:
                    return
                quote_pairs = list(parameters)
                quote_pairs[index] = (name, "'")
                quote_url = urlunparse(parsed._replace(query=urlencode(quote_pairs)))
                response = self.request(quote_url)
                if response is not None:
                    try:
                        body = self.read_body(response)
                        error_label = find_sql_error(body)
                        if error_label:
                            self.add("active-sqli-signal", "MEDIUM", "Database error triggered by a quote probe", page_url, f"A single quote in a query parameter was followed by a {error_label} signature; manually verify the code path", "Use parameterized queries and return generic client errors. This signal requires manual validation.", "CWE-89", "A03:2021 Injection")
                    finally:
                        self.close_response(response)


def normalize_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("Target is required")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Provide an http(s) URL without embedded credentials")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Target contains an invalid port") from exc
    # Fragments are client-side only and should not be included in HTTP requests.
    return parsed._replace(fragment="").geturl().rstrip("/")


def effective_port(parsed) -> int:
    return parsed.port or (443 if parsed.scheme == "https" else 80)


def canonical_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def redact_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.query:
        return urlunparse(parsed._replace(fragment=""))
    safe_query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunparse(parsed._replace(query=safe_query, fragment=""))


def find_sql_error(body: str) -> str | None:
    for label, pattern in SQL_ERROR_PATTERNS:
        if pattern.search(body):
            return label
    return None


def to_json(result: ScanResult) -> str:
    return json.dumps(asdict(result), indent=2)
