# -*- coding: utf-8 -*-

"""
HTCAP - Host Header Injection Fuzzer
Detects Host Header Injection vulnerabilities.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import random
import string
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from core.scan.base_fuzzer import BaseFuzzer


class HostHeaderFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting Host Header Injection vulnerabilities.

    Detects:
    - Password reset poisoning
    - Web cache poisoning via Host header
    - Server-side request forgery
    - Virtual host routing bypass
    - Arbitrary URL generation
    """

    def init(self):
        """Initialize the fuzzer."""
        self.name = "Host Header Injection"
        self.description = "Detects Host Header Injection vulnerabilities"

    def _generate_canary(self, length: int = 8) -> str:
        """Generate a random canary string."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """Execute Host Header Injection detection."""
        vulnerabilities = []

        parsed = urlparse(request.url)
        original_host = parsed.hostname
        canary = self._generate_canary()
        evil_host = f"evil-{canary}.com"

        # Test cases for Host Header manipulation
        test_cases = [
            # Direct Host header override
            {
                'headers': {'Host': evil_host},
                'description': 'Direct Host header injection',
                'check': evil_host
            },
            # X-Forwarded-Host
            {
                'headers': {'X-Forwarded-Host': evil_host},
                'description': 'X-Forwarded-Host injection',
                'check': evil_host
            },
            # X-Host
            {
                'headers': {'X-Host': evil_host},
                'description': 'X-Host injection',
                'check': evil_host
            },
            # X-Original-Host
            {
                'headers': {'X-Original-Host': evil_host},
                'description': 'X-Original-Host injection',
                'check': evil_host
            },
            # Forwarded header
            {
                'headers': {'Forwarded': f'host={evil_host}'},
                'description': 'Forwarded header injection',
                'check': evil_host
            },
            # Duplicate Host header (first wins/last wins)
            {
                'headers': {'Host': f'{original_host}\r\nHost: {evil_host}'},
                'description': 'Duplicate Host header injection',
                'check': evil_host
            },
            # Host with port
            {
                'headers': {'Host': f'{evil_host}:443'},
                'description': 'Host with port injection',
                'check': evil_host
            },
            # Absolute URL
            {
                'headers': {'Host': evil_host},
                'modify_url': f'http://{original_host}{parsed.path}',
                'description': 'Absolute URL with different Host',
                'check': evil_host
            },
            # @ symbol bypass
            {
                'headers': {'Host': f'{original_host}@{evil_host}'},
                'description': 'Host header @ bypass',
                'check': evil_host
            },
            # Space injection
            {
                'headers': {'Host': f'{original_host} {evil_host}'},
                'description': 'Host header space injection',
                'check': evil_host
            },
        ]

        for test in test_cases:
            try:
                extra_headers = test['headers'].copy()
                if hasattr(request, 'extra_headers') and request.extra_headers:
                    extra_headers.update(request.extra_headers)

                modified_url = test.get('modify_url', request.url)
                response = self.send_request(request, modified_url=modified_url,
                                           extra_headers=extra_headers)

                if response and test['check'] in response.body:
                    vulnerabilities.append({
                        'type': 'host_header_injection',
                        'description': f"{test['description']} detected. "
                                     f"Injected host '{test['check']}' appears in response. "
                                     f"This could enable password reset poisoning, "
                                     f"cache poisoning, or SSRF attacks."
                    })

            except Exception:
                pass

        # Test for password reset poisoning specifically
        reset_paths = ['/reset', '/forgot', '/password', '/recover', '/auth/reset']
        for path in reset_paths:
            if path in request.url.lower():
                vulnerabilities.append({
                    'type': 'host_header_password_reset',
                    'description': f"Password reset endpoint detected at {request.url}. "
                                 f"If Host header injection succeeded, this could enable "
                                 f"password reset link poisoning attacks.",
                    'severity': 'high'
                })
                break

        return vulnerabilities
