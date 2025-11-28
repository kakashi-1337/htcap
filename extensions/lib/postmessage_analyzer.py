# -*- coding: utf-8 -*-

"""
HTCAP Extensions - postMessage Analyzer
Detect and analyze postMessage vulnerabilities.

For AUTHORIZED penetration testing only.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class PMVulnType(Enum):
    """postMessage vulnerability types."""
    MISSING_ORIGIN_CHECK = "missing_origin_check"
    WEAK_ORIGIN_CHECK = "weak_origin_check"
    WILDCARD_TARGET = "wildcard_target_origin"
    SENSITIVE_DATA_LEAK = "sensitive_data_leak"
    DOM_MANIPULATION = "dom_manipulation"
    EVAL_MESSAGE = "eval_message_data"
    XSS_VIA_MESSAGE = "xss_via_message"
    PROTOTYPE_POLLUTION = "prototype_pollution_via_message"


class OriginCheckStrength(Enum):
    """Strength of origin validation."""
    NONE = "none"
    WEAK = "weak"
    PARTIAL = "partial"
    STRONG = "strong"


@dataclass
class MessageHandler:
    """Represents a postMessage event handler."""
    location: str
    code: str
    has_origin_check: bool = False
    origin_check_strength: OriginCheckStrength = OriginCheckStrength.NONE
    origin_pattern: Optional[str] = None
    uses_eval: bool = False
    uses_innerhtml: bool = False
    uses_location: bool = False
    vulnerable_patterns: List[str] = field(default_factory=list)


@dataclass
class MessageSender:
    """Represents a postMessage sender."""
    location: str
    code: str
    target_origin: str = "*"
    is_wildcard: bool = False
    data_sources: List[str] = field(default_factory=list)


@dataclass
class PMVulnerability:
    """Represents a postMessage vulnerability."""
    vuln_type: PMVulnType
    location: str
    description: str
    severity: str
    code_snippet: str
    exploit_scenario: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


class PostMessageAnalyzer:
    """
    Analyze JavaScript code for postMessage vulnerabilities.

    Detects:
    - Missing or weak origin validation
    - Wildcard targetOrigin in postMessage calls
    - Dangerous data handling (eval, innerHTML, etc.)
    - XSS via postMessage
    - Sensitive data in messages
    """

    # Pattern to find message event listeners
    LISTENER_PATTERNS = [
        r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(\w+|\([^)]*\)\s*=>|function\s*\([^)]*\))',
        r'onmessage\s*=\s*(\w+|function\s*\([^)]*\)|\([^)]*\)\s*=>)',
        r'window\.onmessage\s*=',
    ]

    # Pattern to find postMessage calls
    SENDER_PATTERNS = [
        r'\.postMessage\s*\(\s*([^,]+)\s*,\s*(["\'][^"\']*["\']|\*)',
        r'parent\.postMessage\s*\(',
        r'opener\.postMessage\s*\(',
        r'top\.postMessage\s*\(',
        r'frames\[\d+\]\.postMessage\s*\(',
    ]

    # Origin check patterns (ordered by strength)
    ORIGIN_CHECK_PATTERNS = {
        OriginCheckStrength.STRONG: [
            r'event\.origin\s*===\s*["\']https?://[^"\']+["\']',
            r'e\.origin\s*===\s*["\']https?://[^"\']+["\']',
            r'allowedOrigins\.includes\s*\(\s*(?:event|e)\.origin\s*\)',
            r'whitelist\.indexOf\s*\(\s*(?:event|e)\.origin\s*\)',
        ],
        OriginCheckStrength.PARTIAL: [
            r'(?:event|e)\.origin\.endsWith\s*\(',
            r'(?:event|e)\.origin\.startsWith\s*\(',
            r'(?:event|e)\.origin\.match\s*\(',
            r'new\s+URL\s*\(\s*(?:event|e)\.origin\s*\)',
        ],
        OriginCheckStrength.WEAK: [
            r'(?:event|e)\.origin\.indexOf\s*\(',
            r'(?:event|e)\.origin\.includes\s*\(',
            r'(?:event|e)\.origin\s*[!=]=',  # Non-strict comparison
        ],
    }

    # Dangerous sink patterns in message handlers
    DANGEROUS_SINKS = {
        'eval': (r'\beval\s*\(\s*(?:event|e)\.data', PMVulnType.EVAL_MESSAGE, 'critical'),
        'Function': (r'new\s+Function\s*\([^)]*(?:event|e)\.data', PMVulnType.EVAL_MESSAGE, 'critical'),
        'innerHTML': (r'\.innerHTML\s*=\s*[^;]*(?:event|e)\.data', PMVulnType.XSS_VIA_MESSAGE, 'high'),
        'outerHTML': (r'\.outerHTML\s*=\s*[^;]*(?:event|e)\.data', PMVulnType.XSS_VIA_MESSAGE, 'high'),
        'document.write': (r'document\.write\s*\([^)]*(?:event|e)\.data', PMVulnType.XSS_VIA_MESSAGE, 'high'),
        'location': (r'location(?:\.href)?\s*=\s*[^;]*(?:event|e)\.data', PMVulnType.DOM_MANIPULATION, 'high'),
        'src': (r'\.src\s*=\s*[^;]*(?:event|e)\.data', PMVulnType.DOM_MANIPULATION, 'high'),
        'jQuery.html': (r'\$\([^)]*\)\.html\s*\([^)]*(?:event|e)\.data', PMVulnType.XSS_VIA_MESSAGE, 'high'),
        'Object.assign': (r'Object\.assign\s*\([^,]*,\s*(?:event|e)\.data', PMVulnType.PROTOTYPE_POLLUTION, 'medium'),
        'spread': (r'\{\s*\.\.\.(?:event|e)\.data', PMVulnType.PROTOTYPE_POLLUTION, 'medium'),
    }

    def __init__(self):
        self.handlers: List[MessageHandler] = []
        self.senders: List[MessageSender] = []
        self.vulnerabilities: List[PMVulnerability] = []

    def analyze(self, js_code: str) -> List[PMVulnerability]:
        """
        Analyze JavaScript code for postMessage vulnerabilities.

        Args:
            js_code: JavaScript source code

        Returns:
            List of detected vulnerabilities
        """
        self.handlers = []
        self.senders = []
        self.vulnerabilities = []

        # Find message handlers
        self._find_handlers(js_code)

        # Find postMessage senders
        self._find_senders(js_code)

        # Analyze handlers for vulnerabilities
        for handler in self.handlers:
            self._analyze_handler(handler)

        # Analyze senders for issues
        for sender in self.senders:
            self._analyze_sender(sender)

        return self.vulnerabilities

    def _find_handlers(self, code: str):
        """Find all message event handlers."""
        for pattern in self.LISTENER_PATTERNS:
            for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                # Get the handler function body
                start = match.start()
                handler_code = self._extract_function_body(code, start)

                handler = MessageHandler(
                    location=f"offset:{start}",
                    code=handler_code
                )

                # Check for origin validation
                self._check_origin_validation(handler)

                # Check for dangerous sinks
                self._check_dangerous_sinks(handler)

                self.handlers.append(handler)

    def _find_senders(self, code: str):
        """Find all postMessage senders."""
        pattern = r'(\w+(?:\.\w+)*)\.postMessage\s*\(\s*([^,]+)\s*,\s*(["\'][^"\']*["\']|\w+)\s*\)'

        for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
            target = match.group(1)
            data = match.group(2)
            origin = match.group(3).strip('"\'')

            start = match.start()
            context = code[max(0, start-50):min(len(code), start+150)]

            sender = MessageSender(
                location=f"offset:{start}",
                code=context,
                target_origin=origin,
                is_wildcard=(origin == '*'),
                data_sources=self._identify_data_sources(data, code)
            )
            self.senders.append(sender)

    def _extract_function_body(self, code: str, start: int) -> str:
        """Extract function body starting from position."""
        # Find the opening brace
        brace_pos = code.find('{', start)
        if brace_pos == -1:
            # Arrow function without braces
            arrow_pos = code.find('=>', start)
            if arrow_pos != -1:
                # Single expression arrow function
                end = min(code.find(';', arrow_pos), code.find('\n', arrow_pos + 50))
                if end == -1:
                    end = arrow_pos + 200
                return code[start:end]
            return code[start:start+200]

        # Count braces to find matching closing brace
        depth = 1
        pos = brace_pos + 1
        while pos < len(code) and depth > 0:
            if code[pos] == '{':
                depth += 1
            elif code[pos] == '}':
                depth -= 1
            pos += 1

        return code[start:pos]

    def _check_origin_validation(self, handler: MessageHandler):
        """Check if handler validates message origin."""
        code = handler.code

        # Check for origin checks in order of strength
        for strength, patterns in self.ORIGIN_CHECK_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, code, re.IGNORECASE)
                if match:
                    handler.has_origin_check = True
                    handler.origin_check_strength = strength
                    handler.origin_pattern = match.group()
                    return

        # Check for any reference to origin at all
        if re.search(r'(?:event|e)\.origin', code):
            # Origin is referenced but not properly checked
            handler.has_origin_check = True
            handler.origin_check_strength = OriginCheckStrength.WEAK
        else:
            handler.has_origin_check = False
            handler.origin_check_strength = OriginCheckStrength.NONE

    def _check_dangerous_sinks(self, handler: MessageHandler):
        """Check for dangerous sinks in handler."""
        code = handler.code

        for sink_name, (pattern, vuln_type, severity) in self.DANGEROUS_SINKS.items():
            if re.search(pattern, code, re.IGNORECASE):
                handler.vulnerable_patterns.append(sink_name)

                if 'eval' in sink_name.lower():
                    handler.uses_eval = True
                elif 'html' in sink_name.lower():
                    handler.uses_innerhtml = True
                elif 'location' in sink_name.lower():
                    handler.uses_location = True

    def _identify_data_sources(self, data_expr: str, code: str) -> List[str]:
        """Identify sources of data being sent via postMessage."""
        sources = []

        sensitive_patterns = [
            ('token', 'authentication token'),
            ('auth', 'authentication data'),
            ('password', 'password'),
            ('secret', 'secret'),
            ('key', 'API key'),
            ('session', 'session data'),
            ('cookie', 'cookie'),
            ('localStorage', 'localStorage'),
            ('sessionStorage', 'sessionStorage'),
        ]

        for pattern, desc in sensitive_patterns:
            if pattern.lower() in data_expr.lower():
                sources.append(desc)

        return sources

    def _analyze_handler(self, handler: MessageHandler):
        """Analyze a message handler for vulnerabilities."""
        # Check for missing origin validation
        if not handler.has_origin_check:
            self.vulnerabilities.append(PMVulnerability(
                vuln_type=PMVulnType.MISSING_ORIGIN_CHECK,
                location=handler.location,
                description="Message handler does not validate event.origin",
                severity="high",
                code_snippet=handler.code[:300],
                exploit_scenario=(
                    "An attacker can host a malicious page that opens or iframes "
                    "the vulnerable page and sends crafted messages that will be "
                    "processed without verification."
                ),
                recommendations=[
                    "Always validate event.origin against a whitelist",
                    "Use strict equality (===) for origin comparison",
                    "Validate origin before processing any message data"
                ]
            ))
        elif handler.origin_check_strength == OriginCheckStrength.WEAK:
            self.vulnerabilities.append(PMVulnerability(
                vuln_type=PMVulnType.WEAK_ORIGIN_CHECK,
                location=handler.location,
                description=f"Weak origin validation: {handler.origin_pattern}",
                severity="medium",
                code_snippet=handler.code[:300],
                exploit_scenario=(
                    "indexOf/includes checks can be bypassed with subdomains. "
                    "e.g., 'evil.com'.indexOf('example.com') fails, but "
                    "'example.com.evil.com'.indexOf('example.com') succeeds."
                ),
                recommendations=[
                    "Use strict equality with full origin",
                    "Use URL parsing to extract and compare hostname",
                    "Consider using a whitelist array with exact matches"
                ]
            ))

        # Check for dangerous sinks
        for pattern in handler.vulnerable_patterns:
            sink_info = self.DANGEROUS_SINKS.get(pattern)
            if sink_info:
                _, vuln_type, severity = sink_info

                self.vulnerabilities.append(PMVulnerability(
                    vuln_type=vuln_type,
                    location=handler.location,
                    description=f"Dangerous sink '{pattern}' with message data",
                    severity=severity,
                    code_snippet=handler.code[:300],
                    exploit_scenario=self._get_exploit_scenario(vuln_type),
                    recommendations=self._get_recommendations(vuln_type)
                ))

    def _analyze_sender(self, sender: MessageSender):
        """Analyze a postMessage sender for vulnerabilities."""
        if sender.is_wildcard:
            self.vulnerabilities.append(PMVulnerability(
                vuln_type=PMVulnType.WILDCARD_TARGET,
                location=sender.location,
                description="postMessage uses '*' as targetOrigin",
                severity="medium",
                code_snippet=sender.code,
                exploit_scenario=(
                    "Messages sent with '*' targetOrigin can be received by "
                    "any window, including malicious pages if the target "
                    "window is navigated away."
                ),
                recommendations=[
                    "Specify exact origin instead of '*'",
                    "Use '/' for same-origin messages",
                    "If dynamic, validate target before sending"
                ]
            ))

        # Check for sensitive data being sent
        if sender.data_sources:
            self.vulnerabilities.append(PMVulnerability(
                vuln_type=PMVulnType.SENSITIVE_DATA_LEAK,
                location=sender.location,
                description=f"Potentially sensitive data in postMessage: {', '.join(sender.data_sources)}",
                severity="high" if 'password' in str(sender.data_sources).lower() else "medium",
                code_snippet=sender.code,
                exploit_scenario=(
                    "Sensitive data sent via postMessage could be intercepted "
                    "if the target window is controlled by an attacker or if "
                    "using wildcard targetOrigin."
                ),
                recommendations=[
                    "Avoid sending sensitive data via postMessage",
                    "Use one-time tokens instead of credentials",
                    "Encrypt sensitive payloads"
                ]
            ))

    def _get_exploit_scenario(self, vuln_type: PMVulnType) -> str:
        """Get exploit scenario description for vulnerability type."""
        scenarios = {
            PMVulnType.EVAL_MESSAGE: (
                "Attacker sends: postMessage('alert(document.cookie)'). "
                "The eval() executes the payload, leading to XSS."
            ),
            PMVulnType.XSS_VIA_MESSAGE: (
                "Attacker sends: postMessage('<img src=x onerror=alert(1)>'). "
                "The payload is inserted into DOM via innerHTML."
            ),
            PMVulnType.DOM_MANIPULATION: (
                "Attacker sends: postMessage('javascript:alert(1)'). "
                "The location/src is set to the attacker's payload."
            ),
            PMVulnType.PROTOTYPE_POLLUTION: (
                "Attacker sends: postMessage({__proto__: {polluted: true}}). "
                "Object spread/assign pollutes the prototype chain."
            ),
        }
        return scenarios.get(vuln_type, "Manual exploitation required.")

    def _get_recommendations(self, vuln_type: PMVulnType) -> List[str]:
        """Get recommendations for vulnerability type."""
        recs = {
            PMVulnType.EVAL_MESSAGE: [
                "Never use eval() with message data",
                "Parse JSON safely with JSON.parse()",
                "Validate and sanitize all input"
            ],
            PMVulnType.XSS_VIA_MESSAGE: [
                "Never use innerHTML with untrusted data",
                "Use textContent for text insertion",
                "Use DOMPurify to sanitize HTML",
                "Implement Content Security Policy"
            ],
            PMVulnType.DOM_MANIPULATION: [
                "Validate URLs before assignment",
                "Whitelist allowed URL schemes",
                "Block javascript: URLs"
            ],
            PMVulnType.PROTOTYPE_POLLUTION: [
                "Validate object structure before merging",
                "Use Object.create(null) for dictionaries",
                "Filter __proto__, constructor, prototype keys"
            ],
        }
        return recs.get(vuln_type, ["Implement proper input validation"])

    def generate_exploit_poc(self, vulnerability: PMVulnerability) -> str:
        """
        Generate a proof-of-concept exploit HTML page.

        Args:
            vulnerability: The vulnerability to exploit

        Returns:
            HTML code for PoC page
        """
        poc_template = '''<!DOCTYPE html>
<html>
<head>
    <title>postMessage PoC - {vuln_type}</title>
</head>
<body>
    <h1>postMessage Exploit PoC</h1>
    <p>Vulnerability: {description}</p>

    <button onclick="exploit()">Send Exploit</button>

    <iframe id="target" src="TARGET_URL_HERE" style="width:100%;height:400px;"></iframe>

    <script>
    function exploit() {{
        var target = document.getElementById('target').contentWindow;
        var payload = {payload};

        // Send malicious message
        target.postMessage(payload, '*');

        console.log('Payload sent:', payload);
    }}

    // Auto-exploit after iframe loads
    document.getElementById('target').onload = function() {{
        setTimeout(exploit, 1000);
    }};
    </script>
</body>
</html>'''

        payloads = {
            PMVulnType.EVAL_MESSAGE: "'alert(document.domain)'",
            PMVulnType.XSS_VIA_MESSAGE: "'<img src=x onerror=alert(document.domain)>'",
            PMVulnType.DOM_MANIPULATION: "'javascript:alert(document.domain)'",
            PMVulnType.PROTOTYPE_POLLUTION: '{"__proto__": {"polluted": "true"}}',
            PMVulnType.MISSING_ORIGIN_CHECK: '{"action": "test", "data": "from_attacker"}',
            PMVulnType.WILDCARD_TARGET: '"intercepted_message"',
        }

        payload = payloads.get(vulnerability.vuln_type, '"test_payload"')

        return poc_template.format(
            vuln_type=vulnerability.vuln_type.value,
            description=vulnerability.description,
            payload=payload
        )

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        return {
            "handlers_found": len(self.handlers),
            "senders_found": len(self.senders),
            "handlers_without_origin_check": len([h for h in self.handlers
                                                   if not h.has_origin_check]),
            "handlers_with_dangerous_sinks": len([h for h in self.handlers
                                                   if h.vulnerable_patterns]),
            "wildcard_senders": len([s for s in self.senders if s.is_wildcard]),
            "vulnerabilities_found": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
        }

    def to_json(self) -> str:
        """Export analysis results to JSON."""
        return json.dumps({
            "handlers": [
                {
                    "location": h.location,
                    "has_origin_check": h.has_origin_check,
                    "origin_check_strength": h.origin_check_strength.value,
                    "vulnerable_patterns": h.vulnerable_patterns,
                }
                for h in self.handlers
            ],
            "senders": [
                {
                    "location": s.location,
                    "target_origin": s.target_origin,
                    "is_wildcard": s.is_wildcard,
                    "data_sources": s.data_sources
                }
                for s in self.senders
            ],
            "vulnerabilities": [
                {
                    "type": v.vuln_type.value,
                    "location": v.location,
                    "description": v.description,
                    "severity": v.severity,
                    "exploit_scenario": v.exploit_scenario,
                    "recommendations": v.recommendations
                }
                for v in self.vulnerabilities
            ],
            "summary": self.get_summary()
        }, indent=2)
