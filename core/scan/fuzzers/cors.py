# -*- coding: utf-8 -*-

"""
HTCAP - CORS Misconfiguration Fuzzer
Detects Cross-Origin Resource Sharing misconfigurations.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from core.scan.base_fuzzer import BaseFuzzer
from core.constants import VULNTYPE_CORS


class CORSFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting CORS Misconfiguration vulnerabilities.

    Detects:
    - Wildcard origin reflection
    - Null origin acceptance
    - Origin reflection without validation
    - Subdomain wildcard issues
    - Credentials with wildcard
    - Pre-domain/post-domain bypass
    """

    def init(self):
        """Initialize the fuzzer with CORS-specific configurations."""
        self.name = "CORS Misconfiguration"
        self.description = "Detects CORS Misconfiguration vulnerabilities"

    def _generate_test_origins(self, target_domain: str) -> List[Dict[str, Any]]:
        """Generate various malicious origins to test."""
        return [
            {
                'origin': 'https://evil.com',
                'type': 'arbitrary_origin',
                'severity': 'high',
                'description': 'Arbitrary origin accepted'
            },
            {
                'origin': 'null',
                'type': 'null_origin',
                'severity': 'high',
                'description': 'Null origin accepted (sandboxed iframe bypass)'
            },
            {
                'origin': f'https://{target_domain}.evil.com',
                'type': 'post_domain',
                'severity': 'high',
                'description': 'Post-domain bypass (domain used as subdomain of attacker)'
            },
            {
                'origin': f'https://evil{target_domain}',
                'type': 'pre_domain',
                'severity': 'high',
                'description': 'Pre-domain bypass (attacker domain prefixed)'
            },
            {
                'origin': f'https://evil.com.{target_domain}',
                'type': 'subdomain_injection',
                'severity': 'medium',
                'description': 'Subdomain injection bypass'
            },
            {
                'origin': f'https://{target_domain}%60.evil.com',
                'type': 'backtick_bypass',
                'severity': 'high',
                'description': 'Backtick encoding bypass'
            },
            {
                'origin': f'https://{target_domain}%2f.evil.com',
                'type': 'encoded_slash_bypass',
                'severity': 'medium',
                'description': 'Encoded slash bypass'
            },
            {
                'origin': f'http://{target_domain}',
                'type': 'http_downgrade',
                'severity': 'medium',
                'description': 'HTTP protocol downgrade accepted'
            },
            {
                'origin': f'https://sub.{target_domain}',
                'type': 'subdomain',
                'severity': 'low',
                'description': 'Subdomain origin accepted (verify if intentional)'
            },
            {
                'origin': f'https://{target_domain}:8080',
                'type': 'port_variation',
                'severity': 'low',
                'description': 'Different port accepted'
            },
        ]

    def _parse_cors_headers(self, response) -> Dict[str, Optional[str]]:
        """Extract CORS-related headers from response."""
        headers = {}

        if hasattr(response, 'headers'):
            resp_headers = response.headers
        elif hasattr(response, 'body'):
            # Try to extract from raw response
            resp_headers = {}
        else:
            return headers

        # Normalize header access
        def get_header(name):
            if isinstance(resp_headers, dict):
                # Case-insensitive lookup
                for k, v in resp_headers.items():
                    if k.lower() == name.lower():
                        return v
            return None

        headers['access-control-allow-origin'] = get_header('Access-Control-Allow-Origin')
        headers['access-control-allow-credentials'] = get_header('Access-Control-Allow-Credentials')
        headers['access-control-allow-methods'] = get_header('Access-Control-Allow-Methods')
        headers['access-control-allow-headers'] = get_header('Access-Control-Allow-Headers')
        headers['access-control-expose-headers'] = get_header('Access-Control-Expose-Headers')
        headers['access-control-max-age'] = get_header('Access-Control-Max-Age')

        return headers

    def _check_header_from_body(self, response_body: str, header_name: str) -> Optional[str]:
        """Try to find header value from raw response body."""
        pattern = rf'{header_name}:\s*([^\r\n]+)'
        match = re.search(pattern, response_body, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """
        Execute CORS misconfiguration detection.

        Args:
            request: The request object to fuzz
            params: Additional parameters

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Get target domain
        parsed = urlparse(request.url)
        target_domain = parsed.hostname
        if not target_domain:
            return vulnerabilities

        # Generate test origins
        test_origins = self._generate_test_origins(target_domain)

        # Test each origin
        for test in test_origins:
            try:
                # Send request with Origin header
                extra_headers = {'Origin': test['origin']}
                if hasattr(request, 'extra_headers') and request.extra_headers:
                    extra_headers.update(request.extra_headers)

                response = self.send_request(request, extra_headers=extra_headers)

                if not response:
                    continue

                # Parse CORS headers
                cors_headers = self._parse_cors_headers(response)

                # Also try to extract from body if headers not available
                if not cors_headers.get('access-control-allow-origin'):
                    acao = self._check_header_from_body(
                        response.body,
                        'access-control-allow-origin'
                    )
                    if acao:
                        cors_headers['access-control-allow-origin'] = acao

                    acac = self._check_header_from_body(
                        response.body,
                        'access-control-allow-credentials'
                    )
                    if acac:
                        cors_headers['access-control-allow-credentials'] = acac

                acao = cors_headers.get('access-control-allow-origin')
                acac = cors_headers.get('access-control-allow-credentials')

                if not acao:
                    continue

                # Check for vulnerabilities
                is_vulnerable = False
                vuln_description = ""

                # Check if origin is reflected
                if acao == test['origin']:
                    is_vulnerable = True
                    vuln_description = (
                        f"CORS {test['description']}. "
                        f"Origin '{test['origin']}' is reflected in "
                        f"Access-Control-Allow-Origin header."
                    )

                    # Credentials make it much worse
                    if acac and acac.lower() == 'true':
                        vuln_description += (
                            " CRITICAL: Access-Control-Allow-Credentials is true, "
                            "allowing credential theft!"
                        )
                        test['severity'] = 'critical'

                # Check for wildcard
                elif acao == '*':
                    if test['type'] == 'arbitrary_origin':
                        is_vulnerable = True
                        vuln_description = (
                            "CORS Wildcard origin (*) configured. "
                            "Any website can read responses."
                        )
                        if acac and acac.lower() == 'true':
                            vuln_description += (
                                " Note: Browsers block credentials with wildcard, "
                                "but this is still a misconfiguration."
                            )

                if is_vulnerable:
                    vulnerabilities.append({
                        'type': VULNTYPE_CORS,
                        'severity': test['severity'],
                        'description': vuln_description,
                        'details': {
                            'tested_origin': test['origin'],
                            'acao_header': acao,
                            'acac_header': acac,
                            'bypass_type': test['type']
                        }
                    })

            except Exception:
                pass

        # Test preflight (OPTIONS) request
        try:
            extra_headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'PUT',
                'Access-Control-Request-Headers': 'X-Custom-Header'
            }

            # Note: This would need the ability to send OPTIONS request
            # For now, we just document the finding if ACAO was reflected above

        except Exception:
            pass

        return vulnerabilities
