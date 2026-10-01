# WebGuard WAPT

WebGuard WAPT is a command-line web application security assessment tool for systems you own or are explicitly authorized to test. It makes real HTTP requests to the target you provide; it does not return canned findings or use sample scan data. It uses Python's standard library and has no runtime package dependencies.

It combines bounded same-origin crawling with passive checks and a small, opt-in set of non-destructive GET probes. Findings include severity, evidence, remediation, CWE, and OWASP Top 10 mapping where applicable.

## What it checks

- HTTPS response headers, HSTS, CSP, clickjacking defenses, referrer policy, and server banners.
- Cookie flags without printing cookie values.
- CORS behavior using a harmless test Origin and HTTP methods advertised by OPTIONS.
- Same-origin HTML links, insecure embedded resources, password forms using GET, cleartext form actions, and recognizable CSRF fields.
- Database errors and application stack traces visible in HTML responses.
- Conventional public metadata and API documentation paths.
- With `--active-probes`, reflection of a harmless angle-bracket marker and database error responses to a single quote in existing, nonsensitive query parameters.

## What it does not do

WebGuard does not submit forms, invoke advertised write methods, follow redirects, send credentials, reuse cookies, brute-force logins, download discovered documents, exploit vulnerabilities, or test authorization/business-logic workflows. It does not prove an XSS or SQL injection finding; active results are leads for manual confirmation. It is not a replacement for a full authenticated DAST assessment or penetration test.

## Install

Requires Python 3.10 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .
```

## Use

Passive, bounded scan:

```bash
webguard https://your-authorized-target.example --output report.json
```

Opt in to the limited active GET probes after confirming that query-string GET endpoints are safe to request:

```bash
webguard https://your-authorized-target.example --active-probes --max-pages 15 --max-requests 75 --delay 0.5 --output report.json
```

After installation, run `python -m webscan --help`. The scanner stays on the input scheme, host, and port, does not follow redirects, caps HTML reads at 512 KiB per page, defaults to 10 pages and 50 total HTTP requests, and pauses between requests. Tune limits to the engagement rules of engagement. Avoid running active probes against endpoints where GET may change server state.

Exit codes: `0` completed without high/critical findings, `1` high/critical finding present, `2` input, report-write, or network error. JSON reports redact query parameter values and never include response bodies or cookie values.

## Test

```bash
python -m unittest discover -s tests -v
```

The test suite uses a local HTTP fixture and does not contact external hosts. For real assessments, set the target to the explicitly authorized application and follow its rate limits and scope.

## Responsible use

Only scan systems for which you have explicit authorization. Keep request limits conservative, coordinate with the application owner, and manually validate findings before reporting them. See [SECURITY.md](SECURITY.md) and [docs/checks.md](docs/checks.md).
