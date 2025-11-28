# -*- coding: utf-8 -*-
"""
SHARINGAN - Nuclei Integration
Run Nuclei templates on discovered endpoints.
"""

import subprocess
import json
import os
import tempfile
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import shutil


class NucleiSeverity(Enum):
    """Nuclei severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class NucleiResult:
    """Represents a Nuclei scan result."""
    template_id: str
    template_name: str
    severity: NucleiSeverity
    host: str
    matched_at: str
    matcher_name: Optional[str] = None
    extracted: List[str] = field(default_factory=list)
    curl_command: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    reference: List[str] = field(default_factory=list)


class TemplateMatcher:
    """
    Automatically select Nuclei templates based on detected technologies.
    """

    # Technology to template tag mapping
    TECH_TEMPLATES = {
        # Frameworks
        "react": ["react", "javascript"],
        "angular": ["angular", "javascript"],
        "vue": ["vue", "javascript"],
        "django": ["django", "python"],
        "flask": ["flask", "python"],
        "rails": ["rails", "ruby"],
        "laravel": ["laravel", "php"],
        "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
        "drupal": ["drupal"],
        "joomla": ["joomla"],

        # Servers
        "nginx": ["nginx"],
        "apache": ["apache"],
        "iis": ["iis"],
        "tomcat": ["tomcat"],

        # Cloud
        "aws": ["aws", "amazon"],
        "azure": ["azure", "microsoft"],
        "gcp": ["gcp", "google"],

        # Databases
        "mysql": ["mysql"],
        "postgres": ["postgres"],
        "mongodb": ["mongodb"],
        "redis": ["redis"],

        # APIs
        "graphql": ["graphql"],
        "swagger": ["swagger", "openapi"],
        "rest": ["api"],

        # Auth
        "oauth": ["oauth"],
        "jwt": ["jwt", "token"],
        "saml": ["saml"],
    }

    # Vulnerability type to template mapping
    VULN_TEMPLATES = {
        "xss": ["xss"],
        "sqli": ["sqli", "sql-injection"],
        "ssrf": ["ssrf"],
        "lfi": ["lfi", "local-file-inclusion"],
        "rfi": ["rfi", "remote-file-inclusion"],
        "rce": ["rce", "remote-code-execution"],
        "xxe": ["xxe"],
        "ssti": ["ssti", "template-injection"],
        "idor": ["idor"],
        "redirect": ["open-redirect", "redirect"],
        "cve": ["cve"],
        "exposure": ["exposure", "config"],
        "misconfig": ["misconfig", "misconfiguration"],
    }

    def get_templates_for_tech(self, technologies: List[str]) -> Set[str]:
        """Get template tags for detected technologies."""
        tags = set()
        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in self.TECH_TEMPLATES:
                tags.update(self.TECH_TEMPLATES[tech_lower])
        return tags

    def get_templates_for_vulns(self, vuln_types: List[str]) -> Set[str]:
        """Get template tags for vulnerability types."""
        tags = set()
        for vuln in vuln_types:
            vuln_lower = vuln.lower()
            if vuln_lower in self.VULN_TEMPLATES:
                tags.update(self.VULN_TEMPLATES[vuln_lower])
        return tags


class NucleiEngine:
    """
    Nuclei integration for SHARINGAN.

    Features:
    - Run Nuclei templates on targets
    - Auto-select templates based on tech stack
    - Parse and structure results
    - Custom template support
    """

    def __init__(self, nuclei_path: Optional[str] = None,
                 templates_path: Optional[str] = None):
        """
        Initialize Nuclei engine.

        Args:
            nuclei_path: Path to nuclei binary (auto-detect if None)
            templates_path: Path to nuclei templates directory
        """
        self.nuclei_path = nuclei_path or self._find_nuclei()
        self.templates_path = templates_path or self._find_templates()
        self.matcher = TemplateMatcher()
        self.results: List[NucleiResult] = []

    def _find_nuclei(self) -> Optional[str]:
        """Find nuclei binary in PATH."""
        return shutil.which("nuclei")

    def _find_templates(self) -> Optional[str]:
        """Find nuclei templates directory."""
        # Common locations
        locations = [
            Path.home() / "nuclei-templates",
            Path.home() / ".nuclei-templates",
            Path("/opt/nuclei-templates"),
            Path("/usr/share/nuclei-templates"),
        ]

        for loc in locations:
            if loc.exists():
                return str(loc)

        return None

    def is_available(self) -> bool:
        """Check if Nuclei is available."""
        return self.nuclei_path is not None

    def scan(self, targets: List[str], tags: List[str] = None,
             severity: List[str] = None, rate_limit: int = 150,
             timeout: int = 300, custom_templates: List[str] = None) -> List[NucleiResult]:
        """
        Run Nuclei scan on targets.

        Args:
            targets: List of URLs to scan
            tags: Template tags to use (e.g., ["xss", "sqli"])
            severity: Severity levels to include (e.g., ["critical", "high"])
            rate_limit: Requests per second
            timeout: Scan timeout in seconds
            custom_templates: Paths to custom template files

        Returns:
            List of NucleiResult findings
        """
        if not self.is_available():
            raise RuntimeError("Nuclei binary not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

        self.results = []

        # Create temp file for targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        try:
            cmd = [
                self.nuclei_path,
                "-l", targets_file,
                "-json",
                "-rate-limit", str(rate_limit),
                "-timeout", str(timeout),
                "-silent",
            ]

            # Add templates path
            if self.templates_path:
                cmd.extend(["-t", self.templates_path])

            # Add custom templates
            if custom_templates:
                for tpl in custom_templates:
                    cmd.extend(["-t", tpl])

            # Add tags filter
            if tags:
                cmd.extend(["-tags", ",".join(tags)])

            # Add severity filter
            if severity:
                cmd.extend(["-severity", ",".join(severity)])

            # Run nuclei
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 60  # Extra buffer
            )

            # Parse JSON output (one JSON object per line)
            for line in process.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        result = self._parse_result(data)
                        if result:
                            self.results.append(result)
                    except json.JSONDecodeError:
                        continue

        finally:
            # Cleanup temp file
            os.unlink(targets_file)

        return self.results

    def scan_with_auto_templates(self, targets: List[str],
                                  technologies: List[str] = None,
                                  vuln_types: List[str] = None,
                                  **kwargs) -> List[NucleiResult]:
        """
        Scan with auto-selected templates based on tech stack.

        Args:
            targets: List of URLs to scan
            technologies: Detected technologies (e.g., ["wordpress", "nginx"])
            vuln_types: Vulnerability types to focus on
            **kwargs: Additional arguments for scan()

        Returns:
            List of NucleiResult findings
        """
        tags = set()

        if technologies:
            tags.update(self.matcher.get_templates_for_tech(technologies))

        if vuln_types:
            tags.update(self.matcher.get_templates_for_vulns(vuln_types))

        # Default to common web vulns if nothing specified
        if not tags:
            tags = {"xss", "sqli", "ssrf", "lfi", "rce", "exposure"}

        return self.scan(targets, tags=list(tags), **kwargs)

    def _parse_result(self, data: Dict[str, Any]) -> Optional[NucleiResult]:
        """Parse Nuclei JSON output to NucleiResult."""
        try:
            info = data.get("info", {})

            severity_str = info.get("severity", "unknown").lower()
            try:
                severity = NucleiSeverity(severity_str)
            except ValueError:
                severity = NucleiSeverity.UNKNOWN

            return NucleiResult(
                template_id=data.get("template-id", ""),
                template_name=info.get("name", ""),
                severity=severity,
                host=data.get("host", ""),
                matched_at=data.get("matched-at", data.get("host", "")),
                matcher_name=data.get("matcher-name"),
                extracted=data.get("extracted-results", []),
                curl_command=data.get("curl-command"),
                description=info.get("description"),
                tags=info.get("tags", []),
                reference=info.get("reference", []),
            )
        except Exception:
            return None

    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary."""
        severity_counts = {s.value: 0 for s in NucleiSeverity}

        for result in self.results:
            severity_counts[result.severity.value] += 1

        return {
            "total_findings": len(self.results),
            "severity_breakdown": severity_counts,
            "unique_templates": len(set(r.template_id for r in self.results)),
            "unique_hosts": len(set(r.host for r in self.results)),
        }

    def to_json(self) -> str:
        """Export results to JSON."""
        return json.dumps([
            {
                "template_id": r.template_id,
                "template_name": r.template_name,
                "severity": r.severity.value,
                "host": r.host,
                "matched_at": r.matched_at,
                "matcher_name": r.matcher_name,
                "extracted": r.extracted,
                "curl_command": r.curl_command,
                "description": r.description,
                "tags": r.tags,
                "reference": r.reference,
            }
            for r in self.results
        ], indent=2)

    def to_findings(self) -> List[Dict[str, Any]]:
        """Convert results to SHARINGAN finding format."""
        findings = []

        for result in self.results:
            findings.append({
                "title": f"[Nuclei] {result.template_name}",
                "severity": result.severity.value,
                "vuln_type": f"nuclei_{result.template_id}",
                "url": result.matched_at,
                "description": result.description or f"Nuclei template {result.template_id} matched",
                "evidence": {
                    "template_id": result.template_id,
                    "extracted": result.extracted,
                    "matcher_name": result.matcher_name,
                },
                "recommendations": [
                    f"Review: {ref}" for ref in result.reference[:3]
                ] if result.reference else ["Review Nuclei template for remediation guidance"],
                "payload": result.curl_command,
            })

        return findings
