# -*- coding: utf-8 -*-
"""
SHARINGAN - HTML Report Generator
Generate beautiful vulnerability reports.
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class Finding:
    """Represents a security finding."""
    title: str
    severity: str
    vuln_type: str
    url: Optional[str]
    description: str
    evidence: str
    recommendations: List[str]
    payload: Optional[str] = None


class HTMLReportGenerator:
    """Generate HTML reports from scan results."""

    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745",
        "info": "#17a2b8",
    }

    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

    def __init__(self):
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding):
        """Add a finding to the report."""
        self.findings.append(finding)

    def generate(self, data: Dict[str, Any], title: str = "SHARINGAN Security Report") -> str:
        """
        Generate HTML report from scan data.

        Args:
            data: Dictionary containing scan results
            title: Report title

        Returns:
            HTML string
        """
        # Parse findings from data
        self._parse_findings(data)

        # Calculate statistics
        stats = self._calculate_stats()

        # Generate HTML
        return self._render_html(title, stats)

    def _parse_findings(self, data: Dict[str, Any]):
        """Parse findings from scan data."""
        self.findings = []

        # Parse taint tracking results
        if "flows" in data:
            for flow in data["flows"]:
                if flow.get("exploitable"):
                    self.findings.append(Finding(
                        title=f"DOM XSS: {flow['source_type']} -> {flow['sink_type']}",
                        severity=flow.get("sink_severity", "medium"),
                        vuln_type="dom_xss",
                        url=data.get("url"),
                        description=f"Tainted data flows from {flow['source_type']} to {flow['sink_type']}",
                        evidence=str(flow.get("transformations", [])),
                        recommendations=["Sanitize user input", "Use safe DOM APIs"],
                        payload=flow.get("payload")
                    ))

        # Parse postMessage vulnerabilities
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                self.findings.append(Finding(
                    title=vuln.get("description", vuln.get("type", "Unknown")),
                    severity=vuln.get("severity", "medium"),
                    vuln_type=vuln.get("type", "unknown"),
                    url=vuln.get("endpoint") or vuln.get("url"),
                    description=vuln.get("description", ""),
                    evidence=str(vuln.get("evidence", {})),
                    recommendations=vuln.get("recommendations", []),
                    payload=vuln.get("payload")
                ))

        # Parse WebSocket vulnerabilities
        if "ws_vulnerabilities" in data:
            for vuln in data["ws_vulnerabilities"]:
                self.findings.append(Finding(
                    title=f"WebSocket: {vuln.get('type', 'Unknown')}",
                    severity=vuln.get("severity", "medium"),
                    vuln_type="websocket",
                    url=vuln.get("endpoint"),
                    description=vuln.get("description", ""),
                    evidence=str(vuln.get("evidence", {})),
                    recommendations=vuln.get("recommendations", [])
                ))

        # Parse DOM clobbering
        if "clobbering" in data:
            for vuln in data["clobbering"]:
                self.findings.append(Finding(
                    title=f"DOM Clobbering: {vuln.get('target_name', 'Unknown')}",
                    severity=vuln.get("severity", "medium"),
                    vuln_type="dom_clobbering",
                    url=data.get("url"),
                    description=vuln.get("description", ""),
                    evidence=str(vuln.get("vectors", [])),
                    recommendations=vuln.get("recommendations", [])
                ))

    def _calculate_stats(self) -> Dict[str, Any]:
        """Calculate report statistics."""
        stats = {
            "total": len(self.findings),
            "by_severity": {s: 0 for s in self.SEVERITY_ORDER},
            "by_type": {},
        }

        for finding in self.findings:
            sev = finding.severity.lower()
            if sev in stats["by_severity"]:
                stats["by_severity"][sev] += 1

            vuln_type = finding.vuln_type
            stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1

        return stats

    def _render_html(self, title: str, stats: Dict[str, Any]) -> str:
        """Render the HTML report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sort findings by severity
        sorted_findings = sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER.index(f.severity.lower())
            if f.severity.lower() in self.SEVERITY_ORDER else 99
        )

        findings_html = self._render_findings(sorted_findings)
        stats_html = self._render_stats(stats)

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #e94560;
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            padding: 40px 20px;
            text-align: center;
            border-bottom: 3px solid var(--accent);
        }}

        .logo {{
            font-size: 3em;
            font-weight: bold;
            color: var(--accent);
            text-shadow: 0 0 20px rgba(233, 69, 96, 0.5);
        }}

        .tagline {{
            color: var(--text-secondary);
            font-style: italic;
        }}

        .timestamp {{
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-top: 10px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}

        .stat-card {{
            background: var(--bg-card);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid var(--accent);
        }}

        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
        }}

        .stat-label {{
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.8em;
        }}

        .severity-critical {{ border-left-color: var(--critical); }}
        .severity-critical .stat-number {{ color: var(--critical); }}
        .severity-high {{ border-left-color: var(--high); }}
        .severity-high .stat-number {{ color: var(--high); }}
        .severity-medium {{ border-left-color: var(--medium); }}
        .severity-medium .stat-number {{ color: var(--medium); }}
        .severity-low {{ border-left-color: var(--low); }}
        .severity-low .stat-number {{ color: var(--low); }}

        .findings {{
            margin-top: 30px;
        }}

        .finding {{
            background: var(--bg-secondary);
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.1);
        }}

        .finding-header {{
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}

        .finding-title {{
            font-weight: bold;
        }}

        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: var(--critical); }}
        .badge-high {{ background: var(--high); color: #000; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); }}
        .badge-info {{ background: var(--info); }}

        .finding-body {{
            padding: 20px;
            background: var(--bg-card);
            border-top: 1px solid rgba(255,255,255,0.1);
        }}

        .finding-section {{
            margin-bottom: 15px;
        }}

        .finding-section h4 {{
            color: var(--accent);
            margin-bottom: 5px;
            font-size: 0.9em;
            text-transform: uppercase;
        }}

        .code-block {{
            background: var(--bg-primary);
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Consolas', monospace;
            font-size: 0.9em;
        }}

        .recommendations ul {{
            list-style: none;
            padding-left: 0;
        }}

        .recommendations li {{
            padding: 5px 0;
            padding-left: 20px;
            position: relative;
        }}

        .recommendations li::before {{
            content: "→";
            position: absolute;
            left: 0;
            color: var(--accent);
        }}

        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            border-top: 1px solid rgba(255,255,255,0.1);
            margin-top: 50px;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="logo">SHARINGAN</div>
        <div class="tagline">The Eye That Sees All Vulnerabilities</div>
        <div class="timestamp">Generated: {timestamp}</div>
    </header>

    <div class="container">
        <h2 style="margin: 30px 0 10px;">Executive Summary</h2>
        {stats_html}

        <h2 style="margin: 30px 0 10px;">Findings</h2>
        <div class="findings">
            {findings_html}
        </div>
    </div>

    <footer>
        <p>SHARINGAN Security Report | For authorized use only</p>
        <p style="margin-top: 10px; font-size: 0.8em;">
            Generated by SHARINGAN v1.0.0 "Mangekyou"
        </p>
    </footer>

    <script>
        // Toggle finding details
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const body = header.nextElementSibling;
                body.style.display = body.style.display === 'none' ? 'block' : 'none';
            }});
        }});
    </script>
</body>
</html>'''

    def _render_stats(self, stats: Dict[str, Any]) -> str:
        """Render statistics section."""
        cards = []

        cards.append(f'''
            <div class="stat-card">
                <div class="stat-number">{stats["total"]}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        ''')

        for severity in self.SEVERITY_ORDER:
            count = stats["by_severity"].get(severity, 0)
            if count > 0 or severity in ["critical", "high"]:
                cards.append(f'''
                    <div class="stat-card severity-{severity}">
                        <div class="stat-number">{count}</div>
                        <div class="stat-label">{severity.title()}</div>
                    </div>
                ''')

        return f'<div class="stats-grid">{"".join(cards)}</div>'

    def _render_findings(self, findings: List[Finding]) -> str:
        """Render findings section."""
        if not findings:
            return '<p style="color: var(--text-secondary);">No findings to display.</p>'

        html_parts = []

        for i, finding in enumerate(findings):
            severity = finding.severity.lower()
            badge_class = f"badge-{severity}"

            recs_html = ""
            if finding.recommendations:
                recs_list = "".join(f"<li>{rec}</li>" for rec in finding.recommendations)
                recs_html = f'''
                    <div class="finding-section recommendations">
                        <h4>Recommendations</h4>
                        <ul>{recs_list}</ul>
                    </div>
                '''

            payload_html = ""
            if finding.payload:
                payload_html = f'''
                    <div class="finding-section">
                        <h4>Payload</h4>
                        <div class="code-block">{self._escape_html(finding.payload)}</div>
                    </div>
                '''

            html_parts.append(f'''
                <div class="finding">
                    <div class="finding-header">
                        <span class="finding-title">{self._escape_html(finding.title)}</span>
                        <span class="severity-badge {badge_class}">{severity}</span>
                    </div>
                    <div class="finding-body" style="display: {'block' if i < 5 else 'none'};">
                        <div class="finding-section">
                            <h4>Description</h4>
                            <p>{self._escape_html(finding.description)}</p>
                        </div>
                        {f'<div class="finding-section"><h4>URL</h4><p>{self._escape_html(finding.url)}</p></div>' if finding.url else ''}
                        <div class="finding-section">
                            <h4>Evidence</h4>
                            <div class="code-block">{self._escape_html(finding.evidence)}</div>
                        </div>
                        {payload_html}
                        {recs_html}
                    </div>
                </div>
            ''')

        return "".join(html_parts)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))
