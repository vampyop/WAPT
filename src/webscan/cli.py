from __future__ import annotations

import argparse
import sys

from .scanner import Scanner, to_json


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded web application security assessment for authorized targets.",
        epilog="Only scan systems you own or are explicitly authorized to assess. Active probes are opt-in.",
    )
    parser.add_argument("target", help="Target URL or host (HTTPS is assumed if the scheme is omitted)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds (default: 8)")
    parser.add_argument("--delay", type=float, default=0.35, help="Delay between requests in seconds (default: 0.35)")
    parser.add_argument("--max-requests", type=int, default=50, help="Maximum total HTTP requests (default: 50)")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum same-origin HTML pages to crawl (default: 10)")
    parser.add_argument(
        "--active-probes",
        action="store_true",
        help="Send harmless HTML-marker and single-quote GET probes to up to 8 nonsensitive query parameters",
    )
    parser.add_argument("--output", help="Write the JSON report to this path")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of the readable summary")
    args = parser.parse_args()

    if args.timeout <= 0 or args.delay < 0 or args.max_requests < 1 or args.max_pages < 1:
        parser.error("timeout must be > 0, delay >= 0, max-requests >= 1, and max-pages >= 1")

    try:
        result = Scanner(
            args.target,
            timeout=args.timeout,
            delay=args.delay,
            max_requests=args.max_requests,
            max_pages=args.max_pages,
            active_probes=args.active_probes,
        ).run()
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    report = to_json(result)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as report_file:
                report_file.write(report + "\n")
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(report)
    else:
        print(f"Target: {result.target}")
        print(f"Pages: {result.pages_crawled} | Requests: {result.requests_made} | Findings: {len(result.findings)} | Duration: {result.duration_seconds}s")
        for finding in result.findings:
            print(f"\n[{finding.severity}] {finding.title}\n  URL: {finding.url}\n  Evidence: {finding.evidence}\n  Fix: {finding.remediation}")
        if result.errors:
            print("\nScan errors:")
            for error in result.errors:
                print(f"- {error}")
    if any(finding.severity in ("HIGH", "CRITICAL") for finding in result.findings):
        return 1
    return 2 if result.errors else 0
