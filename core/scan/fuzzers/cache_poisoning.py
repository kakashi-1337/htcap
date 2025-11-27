# -*- coding: utf-8 -*-

"""
HTCAP - Web Cache Poisoning Detector
Detects web cache poisoning and cache deception vulnerabilities.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import json
import random
import string
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote
from core.scan.base_fuzzer import BaseFuzzer


class CachePoisoningFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting Web Cache Poisoning vulnerabilities.

    Detects:
    - Unkeyed header injection (X-Forwarded-Host, X-Original-URL, etc.)
    - Cache deception attacks
    - Parameter cloaking
    - Fat GET requests
    - Unkeyed port/scheme
    """

    def init(self):
        """Initialize the fuzzer with cache poisoning configurations."""
        self.name = "Web Cache Poisoning"
        self.description = "Detects Web Cache Poisoning vulnerabilities"

        # Headers commonly unkeyed by caches
        self.unkeyed_headers = [
            ('X-Forwarded-Host', 'evil-{canary}.com'),
            ('X-Forwarded-Scheme', 'nothttps'),
            ('X-Forwarded-Proto', 'nothttps'),
            ('X-Original-URL', '/evil-{canary}'),
            ('X-Rewrite-URL', '/evil-{canary}'),
            ('X-Host', 'evil-{canary}.com'),
            ('X-Forwarded-Server', 'evil-{canary}.com'),
            ('X-HTTP-Host-Override', 'evil-{canary}.com'),
            ('Forwarded', 'host=evil-{canary}.com'),
            ('X-Forwarded-Port', '1337'),
            ('X-Original-Host', 'evil-{canary}.com'),
            ('X-Custom-IP-Authorization', '127.0.0.1'),
            ('X-Originating-IP', '127.0.0.1'),
            ('X-Remote-IP', '127.0.0.1'),
            ('X-Client-IP', '127.0.0.1'),
            ('X-Real-IP', '127.0.0.1'),
            ('True-Client-IP', '127.0.0.1'),
            ('CF-Connecting-IP', '127.0.0.1'),
        ]

        # Cache deception file extensions
        self.cacheable_extensions = [
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif',
            '.ico', '.svg', '.woff', '.woff2', '.ttf',
        ]

        # Cache indicators in response
        self.cache_hit_indicators = [
            r'x-cache:\s*hit',
            r'cf-cache-status:\s*hit',
            r'x-varnish-cache:\s*hit',
            r'x-cache-status:\s*hit',
            r'x-proxy-cache:\s*hit',
            r'age:\s*[1-9]',
            r'x-served-by',
            r'x-cache:\s*hit',
            r'fastly-stats',
        ]

        self.cache_miss_indicators = [
            r'x-cache:\s*miss',
            r'cf-cache-status:\s*miss',
            r'x-cache-status:\s*miss',
            r'age:\s*0',
        ]

    def _generate_canary(self, length: int = 8) -> str:
        """Generate a random canary string for detection."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _check_cache_headers(self, response_headers: str) -> Dict[str, bool]:
        """Analyze response headers for caching indicators."""
        result = {'is_cached': False, 'is_cacheable': False}

        headers_lower = response_headers.lower()

        # Check for cache hit
        for pattern in self.cache_hit_indicators:
            if re.search(pattern, headers_lower):
                result['is_cached'] = True
                break

        # Check for cacheability
        if 'cache-control' in headers_lower:
            if 'no-store' not in headers_lower and 'private' not in headers_lower:
                result['is_cacheable'] = True
        elif 'expires' in headers_lower:
            result['is_cacheable'] = True

        return result

    def _header_reflected_in_response(self, response_body: str, canary: str) -> bool:
        """Check if the canary appears in the response."""
        return canary in response_body

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """
        Execute cache poisoning detection.

        Args:
            request: The request object to fuzz
            params: Additional parameters

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Test unkeyed headers
        for header_name, header_value_template in self.unkeyed_headers:
            canary = self._generate_canary()
            header_value = header_value_template.replace('{canary}', canary)

            # Add cache buster to ensure fresh request
            cache_buster = f"cb={self._generate_canary()}"
            test_url = request.url
            if '?' in test_url:
                test_url += f"&{cache_buster}"
            else:
                test_url += f"?{cache_buster}"

            try:
                # First request with poisoned header
                extra_headers = {header_name: header_value}
                if hasattr(request, 'extra_headers') and request.extra_headers:
                    extra_headers.update(request.extra_headers)

                response1 = self.send_request(request, modified_url=test_url,
                                             extra_headers=extra_headers)

                if response1 and self._header_reflected_in_response(response1.body, canary):
                    # Header is reflected - check if it gets cached

                    # Wait a bit for cache to store
                    time.sleep(0.5)

                    # Second request without the header
                    response2 = self.send_request(request, modified_url=test_url)

                    if response2 and self._header_reflected_in_response(response2.body, canary):
                        vulnerabilities.append({
                            'type': 'cache_poisoning',
                            'description': f"Web Cache Poisoning detected via '{header_name}' header. "
                                         f"The header value '{header_value}' was reflected and cached. "
                                         f"An attacker could poison the cache to serve malicious content."
                        })
                        break  # One finding per header type is enough

            except Exception:
                pass

        # Test cache deception
        parsed = urlparse(request.url)
        if not parsed.path.endswith(tuple(self.cacheable_extensions)):
            for ext in self.cacheable_extensions[:3]:
                deception_url = request.url.rstrip('/') + f"/..%2f{ext}"
                canary = self._generate_canary()

                try:
                    response = self.send_request(request, modified_url=deception_url)

                    if response:
                        cache_info = self._check_cache_headers(str(response.headers) if hasattr(response, 'headers') else '')

                        # Check if sensitive content might be cached
                        sensitive_patterns = [
                            r'user.*id', r'email', r'token', r'session',
                            r'password', r'account', r'balance'
                        ]

                        for pattern in sensitive_patterns:
                            if re.search(pattern, response.body, re.IGNORECASE):
                                vulnerabilities.append({
                                    'type': 'cache_deception',
                                    'description': f"Potential Web Cache Deception detected. "
                                                 f"URL '{deception_url}' may cache sensitive data. "
                                                 f"Detected sensitive pattern: {pattern}"
                                })
                                break

                except Exception:
                    pass

        # Test parameter cloaking
        try:
            canary = self._generate_canary()

            # Different parameter separators that might be ignored by cache
            separators = [';', '%00', '%0a', '%0d']

            for sep in separators:
                cloaked_url = f"{request.url}{sep}evil={canary}"

                response = self.send_request(request, modified_url=cloaked_url)

                if response and canary in response.body:
                    vulnerabilities.append({
                        'type': 'cache_parameter_cloaking',
                        'description': f"Parameter cloaking detected using separator '{sep}'. "
                                     f"Cache may ignore parameters after this separator, "
                                     f"allowing cache poisoning attacks."
                    })
                    break

        except Exception:
            pass

        # Test fat GET request (body in GET)
        if request.method == 'GET':
            try:
                canary = self._generate_canary()
                fat_body = f"evil={canary}"

                response = self.send_request(request, data=fat_body)

                if response and canary in response.body:
                    vulnerabilities.append({
                        'type': 'cache_fat_get',
                        'description': f"Fat GET request vulnerability detected. "
                                     f"The server processes body in GET requests, "
                                     f"but cache may not key on the body, enabling poisoning."
                    })

            except Exception:
                pass

        return vulnerabilities
