# -*- coding: utf-8 -*-
"""
SHARINGAN CLI - Command Line Interface
The Eye That Sees All Vulnerabilities.
"""

import argparse
import sys
import json
from pathlib import Path
from typing import Optional

from sharingan import __version__, __codename__


BANNER = r"""
   _____ _    _          _____  _____ _   _  _____          _   _
  / ____| |  | |   /\   |  __ \|_   _| \ | |/ ____|   /\   | \ | |
 | (___ | |__| |  /  \  | |__) | | | |  \| | |  __   /  \  |  \| |
  \___ \|  __  | / /\ \ |  _  /  | | | . ` | | |_ | / /\ \ | . ` |
  ____) | |  | |/ ____ \| | \ \ _| |_| |\  | |__| |/ ____ \| |\  |
 |_____/|_|  |_/_/    \_\_|  \_\_____|_| \_|\_____/_/    \_\_| \_|

              The Eye That Sees All Vulnerabilities
                     v{version} "{codename}"
"""


def print_banner():
    """Print the SHARINGAN banner."""
    print(BANNER.format(version=__version__, codename=__codename__))


def cmd_analyze_taint(args):
    """Analyze JavaScript for taint flows."""
    from sharingan.analyzers import TaintTracker

    if args.file:
        content = Path(args.file).read_text()
    else:
        content = sys.stdin.read()

    tracker = TaintTracker()
    flows = tracker.analyze(content)

    if args.json:
        print(tracker.to_json())
    else:
        summary = tracker.get_summary()
        print(f"\n[*] Taint Analysis Results")
        print(f"    Sources found: {summary['total_sources']}")
        print(f"    Sinks found: {summary['total_sinks']}")
        print(f"    Potential flows: {summary['total_flows']}")
        print(f"    Exploitable flows: {summary['exploitable_flows']}")

        if flows:
            print(f"\n[!] Exploitable Flows:")
            for flow in flows:
                if flow.exploitable:
                    print(f"    {flow.source.type.value} -> {flow.sink.type.value}")
                    print(f"    Severity: {flow.sink.severity.value}")
                    print(f"    Payload: {flow.payload_suggestion}")
                    print()


def cmd_analyze_postmessage(args):
    """Analyze JavaScript for postMessage vulnerabilities."""
    from sharingan.analyzers import PostMessageAnalyzer

    if args.file:
        content = Path(args.file).read_text()
    else:
        content = sys.stdin.read()

    analyzer = PostMessageAnalyzer()
    vulns = analyzer.analyze(content)

    if args.json:
        print(analyzer.to_json())
    else:
        summary = analyzer.get_summary()
        print(f"\n[*] postMessage Analysis Results")
        print(f"    Handlers found: {summary['handlers_found']}")
        print(f"    Senders found: {summary['senders_found']}")
        print(f"    Without origin check: {summary['handlers_without_origin_check']}")
        print(f"    Vulnerabilities: {summary['vulnerabilities_found']}")

        if vulns:
            print(f"\n[!] Vulnerabilities Found:")
            for vuln in vulns:
                print(f"    Type: {vuln.vuln_type.value}")
                print(f"    Severity: {vuln.severity}")
                print(f"    {vuln.description}")
                if args.poc:
                    print(f"\n    PoC:\n{analyzer.generate_exploit_poc(vuln)[:500]}...")
                print()


def cmd_analyze_websocket(args):
    """Analyze WebSocket traffic for vulnerabilities."""
    from sharingan.analyzers import WebSocketAnalyzer

    analyzer = WebSocketAnalyzer()

    if args.endpoint:
        analyzer.add_endpoint(args.endpoint)

    if args.json:
        print(analyzer.to_json())
    else:
        print(f"\n[*] WebSocket Analyzer Ready")
        print(f"    Use with traffic capture or provide messages via --messages")


def cmd_analyze_clobbering(args):
    """Analyze for DOM clobbering vulnerabilities."""
    from sharingan.analyzers import DOMClobberingDetector

    js_content = ""
    html_content = ""

    if args.js_file:
        js_content = Path(args.js_file).read_text()
    if args.html_file:
        html_content = Path(args.html_file).read_text()

    if not js_content and not html_content:
        print("[!] Provide --js-file or --html-file")
        return

    detector = DOMClobberingDetector()
    vulns = detector.analyze(html_content, js_content)

    if args.json:
        print(detector.to_json())
    else:
        summary = detector.get_summary()
        print(f"\n[*] DOM Clobbering Analysis Results")
        print(f"    Clobberable targets: {summary['clobberable_targets_found']}")
        print(f"    Exploitable: {summary['exploitable_targets']}")
        print(f"    Vulnerabilities: {summary['vulnerabilities_found']}")

        if vulns:
            print(f"\n[!] Clobbering Vulnerabilities:")
            for vuln in vulns:
                print(f"    Target: {vuln.target.name}")
                print(f"    Severity: {vuln.severity}")
                if vuln.vectors:
                    print(f"    Payload: {vuln.vectors[0].html_payload}")
                print()


def cmd_detect_waf(args):
    """Detect WAF from response."""
    from sharingan.handlers import WAFHandler

    handler = WAFHandler()

    headers = {}
    body = ""
    cookies = {}

    if args.headers_file:
        # Parse headers from file (Header: Value format)
        for line in Path(args.headers_file).read_text().splitlines():
            if ': ' in line:
                k, v = line.split(': ', 1)
                headers[k] = v

    if args.body_file:
        body = Path(args.body_file).read_text()

    result = handler.detect(headers, body, cookies, args.status_code or 200)

    if args.json:
        print(json.dumps({
            "detected": result.detected,
            "waf_type": result.waf_type.value if result.waf_type else None,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "bypass_suggestions": result.bypass_suggestions
        }, indent=2))
    else:
        if result.detected:
            print(f"\n[!] WAF Detected: {result.waf_type.value}")
            print(f"    Confidence: {result.confidence}%")
            print(f"    Evidence: {result.evidence}")
            print(f"\n[*] Bypass Suggestions:")
            for tip in result.bypass_suggestions:
                print(f"    - {tip}")
        else:
            print("\n[*] No WAF detected")


def cmd_report(args):
    """Generate HTML report from scan results."""
    from sharingan.utils.report import HTMLReportGenerator

    if not args.input:
        print("[!] Provide --input with JSON results file")
        return

    data = json.loads(Path(args.input).read_text())
    generator = HTMLReportGenerator()
    html = generator.generate(data, title=args.title or "SHARINGAN Scan Report")

    output = args.output or "sharingan_report.html"
    Path(output).write_text(html)
    print(f"[*] Report generated: {output}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sharingan",
        description="SHARINGAN - The Eye That Sees All Vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-v", "--version", action="version",
                       version=f"SHARINGAN v{__version__} \"{__codename__}\"")
    parser.add_argument("--no-banner", action="store_true",
                       help="Don't print banner")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Taint analysis
    taint_parser = subparsers.add_parser("taint", help="Analyze taint flows in JavaScript")
    taint_parser.add_argument("-f", "--file", help="JavaScript file to analyze")
    taint_parser.add_argument("--json", action="store_true", help="Output as JSON")
    taint_parser.set_defaults(func=cmd_analyze_taint)

    # postMessage analysis
    pm_parser = subparsers.add_parser("postmessage", help="Analyze postMessage handlers")
    pm_parser.add_argument("-f", "--file", help="JavaScript file to analyze")
    pm_parser.add_argument("--json", action="store_true", help="Output as JSON")
    pm_parser.add_argument("--poc", action="store_true", help="Generate PoC exploits")
    pm_parser.set_defaults(func=cmd_analyze_postmessage)

    # WebSocket analysis
    ws_parser = subparsers.add_parser("websocket", help="Analyze WebSocket traffic")
    ws_parser.add_argument("-e", "--endpoint", help="WebSocket endpoint URL")
    ws_parser.add_argument("--json", action="store_true", help="Output as JSON")
    ws_parser.set_defaults(func=cmd_analyze_websocket)

    # DOM Clobbering
    clob_parser = subparsers.add_parser("clobbering", help="Detect DOM clobbering")
    clob_parser.add_argument("--js-file", help="JavaScript file")
    clob_parser.add_argument("--html-file", help="HTML file")
    clob_parser.add_argument("--json", action="store_true", help="Output as JSON")
    clob_parser.set_defaults(func=cmd_analyze_clobbering)

    # WAF detection
    waf_parser = subparsers.add_parser("waf", help="Detect WAF from response")
    waf_parser.add_argument("--headers-file", help="Response headers file")
    waf_parser.add_argument("--body-file", help="Response body file")
    waf_parser.add_argument("--status-code", type=int, help="HTTP status code")
    waf_parser.add_argument("--json", action="store_true", help="Output as JSON")
    waf_parser.set_defaults(func=cmd_detect_waf)

    # Report generation
    report_parser = subparsers.add_parser("report", help="Generate HTML report")
    report_parser.add_argument("-i", "--input", help="JSON results file")
    report_parser.add_argument("-o", "--output", help="Output HTML file")
    report_parser.add_argument("-t", "--title", help="Report title")
    report_parser.set_defaults(func=cmd_report)

    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    if args.command is None:
        parser.print_help()
        return

    if hasattr(args, 'func'):
        args.func(args)


if __name__ == "__main__":
    main()
