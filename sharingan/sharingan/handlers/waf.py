# -*- coding: utf-8 -*-

"""
HTCAP Extensions - WAF Detection & Bypass Handler
Detects and provides techniques to work with Web Application Firewalls.

For AUTHORIZED penetration testing only.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import time
import random
import string
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
from urllib.parse import urlparse, quote


class WAFType(Enum):
    """Known WAF types."""
    CLOUDFLARE = "cloudflare"
    IMPERVA = "imperva"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    SUCURI = "sucuri"
    MODSECURITY = "modsecurity"
    F5_BIG_IP = "f5_bigip"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    CITRIX_NETSCALER = "citrix_netscaler"
    CLOUDFRONT = "cloudfront"
    FASTLY = "fastly"
    STACKPATH = "stackpath"
    WORDFENCE = "wordfence"
    UNKNOWN = "unknown"
    NONE = "none"


@dataclass
class WAFDetectionResult:
    """Result of WAF detection."""
    detected: bool
    waf_type: WAFType
    confidence: int  # 0-100
    evidence: List[str] = field(default_factory=list)
    bypass_suggestions: List[str] = field(default_factory=list)


class WAFHandler:
    """
    Handles WAF detection and provides bypass techniques for authorized testing.

    Features:
    - Detect WAF presence from headers, cookies, and response patterns
    - Provide WAF-specific bypass suggestions
    - Rate limiting detection
    - Request throttling to avoid blocks
    """

    def __init__(self):
        self._init_signatures()
        self._init_bypass_techniques()

    def _init_signatures(self):
        """Initialize WAF detection signatures."""
        self.signatures = {
            WAFType.CLOUDFLARE: {
                'headers': [
                    (r'cf-ray', 90),
                    (r'cf-cache-status', 80),
                    (r'cf-request-id', 85),
                    (r'server:\s*cloudflare', 95),
                    (r'cf-mitigated', 95),
                ],
                'cookies': [
                    (r'__cf_bm', 90),
                    (r'__cfduid', 85),
                    (r'cf_clearance', 95),
                    (r'__cfruid', 80),
                ],
                'body': [
                    (r'cloudflare', 70),
                    (r'ray\s*id', 60),
                    (r'enable\s*javascript.*cloudflare', 90),
                    (r'attention\s*required.*cloudflare', 95),
                    (r'checking\s*your\s*browser', 85),
                ],
                'status_codes': [403, 503, 429],
            },
            WAFType.IMPERVA: {
                'headers': [
                    (r'x-iinfo', 90),
                    (r'x-cdn:\s*imperva', 95),
                    (r'x-cdn:\s*incapsula', 95),
                ],
                'cookies': [
                    (r'incap_ses_', 95),
                    (r'visid_incap_', 95),
                    (r'nlbi_', 85),
                    (r'___utmvc', 80),
                ],
                'body': [
                    (r'incapsula', 90),
                    (r'imperva', 85),
                    (r'request\s*unsuccessful.*incapsula', 95),
                    (r'incident\s*id', 70),
                ],
                'status_codes': [403, 501],
            },
            WAFType.AKAMAI: {
                'headers': [
                    (r'x-akamai-', 90),
                    (r'akamai-origin-hop', 85),
                    (r'server:\s*akamai', 90),
                    (r'x-akamai-transformed', 85),
                ],
                'cookies': [
                    (r'akamai', 80),
                    (r'ak_bmsc', 90),
                    (r'bm_sv', 85),
                    (r'bm_sz', 85),
                ],
                'body': [
                    (r'akamai', 70),
                    (r'access\s*denied.*akamai', 95),
                    (r'reference\s*#\d+\.\w+', 75),
                ],
                'status_codes': [403],
            },
            WAFType.AWS_WAF: {
                'headers': [
                    (r'x-amzn-requestid', 70),
                    (r'x-amz-cf-', 80),
                    (r'x-amz-apigw-id', 75),
                ],
                'cookies': [
                    (r'awsalb', 85),
                    (r'awsalbcors', 85),
                ],
                'body': [
                    (r'aws\s*waf', 90),
                    (r'request\s*blocked', 60),
                ],
                'status_codes': [403],
            },
            WAFType.SUCURI: {
                'headers': [
                    (r'x-sucuri-id', 95),
                    (r'x-sucuri-cache', 90),
                    (r'server:\s*sucuri', 95),
                ],
                'cookies': [
                    (r'sucuri', 90),
                ],
                'body': [
                    (r'sucuri', 85),
                    (r'access\s*denied.*sucuri', 95),
                    (r'sucuri\s*website\s*firewall', 95),
                ],
                'status_codes': [403],
            },
            WAFType.MODSECURITY: {
                'headers': [
                    (r'server:.*mod_security', 95),
                    (r'x-mod-security', 90),
                ],
                'cookies': [],
                'body': [
                    (r'mod_security', 90),
                    (r'modsecurity', 90),
                    (r'not\s*acceptable.*security', 80),
                    (r'rules?.*triggered', 75),
                ],
                'status_codes': [403, 406],
            },
            WAFType.F5_BIG_IP: {
                'headers': [
                    (r'x-wa-info', 85),
                    (r'server:.*big-?ip', 90),
                ],
                'cookies': [
                    (r'bigipserver', 95),
                    (r'ts[a-z0-9]+', 60),
                    (r'f5_cspm', 90),
                ],
                'body': [
                    (r'f5\s*networks', 85),
                    (r'big-?ip', 80),
                    (r'request\s*rejected', 60),
                ],
                'status_codes': [403],
            },
            WAFType.CLOUDFRONT: {
                'headers': [
                    (r'x-amz-cf-pop', 90),
                    (r'x-amz-cf-id', 90),
                    (r'via:.*cloudfront', 85),
                ],
                'cookies': [],
                'body': [
                    (r'cloudfront', 75),
                    (r'generated\s*by\s*cloudfront', 90),
                ],
                'status_codes': [403],
            },
            WAFType.FASTLY: {
                'headers': [
                    (r'x-fastly-request-id', 90),
                    (r'fastly-stats', 85),
                    (r'via:.*fastly', 85),
                    (r'x-served-by:.*cache', 70),
                ],
                'cookies': [],
                'body': [
                    (r'fastly\s*error', 90),
                ],
                'status_codes': [403, 503],
            },
            WAFType.WORDFENCE: {
                'headers': [],
                'cookies': [
                    (r'wfvt_', 90),
                    (r'wordfence', 95),
                ],
                'body': [
                    (r'wordfence', 90),
                    (r'blocked\s*by\s*wordfence', 95),
                    (r'generated\s*by\s*wordfence', 95),
                ],
                'status_codes': [403, 503],
            },
        }

    def _init_bypass_techniques(self):
        """Initialize WAF bypass techniques."""
        self.bypass_techniques = {
            WAFType.CLOUDFLARE: [
                "Use real IP (check DNS history, Censys, Shodan)",
                "Try origin IP via SSL certificate lookup",
                "Use IPv6 if available",
                "Add header 'CF-Connecting-IP: 127.0.0.1'",
                "Slow down requests (1 req/2-3 sec)",
                "Rotate User-Agents",
                "Use residential proxies",
                "Try different HTTP methods",
                "URL encode payloads multiple times",
                "Use Unicode/UTF-8 encoding variations",
            ],
            WAFType.IMPERVA: [
                "Find origin IP via DNS records/history",
                "Use header manipulation (X-Originating-IP)",
                "Try HPP (HTTP Parameter Pollution)",
                "Encode payloads with Unicode",
                "Use chunked transfer encoding",
                "Try case variation in payloads",
                "Add null bytes in parameters",
                "Use multipart/form-data instead of urlencoded",
            ],
            WAFType.AKAMAI: [
                "Use Pragma: akamai-x-cache-on header",
                "Try parameter pollution",
                "Use URL encoding variations",
                "Split payloads across parameters",
                "Use HTTP/2 if supported",
                "Try path traversal variations",
            ],
            WAFType.AWS_WAF: [
                "Check for WAF rules via fuzzing",
                "Use encoding bypass (double URL encode)",
                "Try Unicode normalization bypass",
                "Use HTTP verb tampering",
                "Try parameter name variations",
            ],
            WAFType.MODSECURITY: [
                "Check paranoia level via fuzzing",
                "Use SQL comment bypass (/*!50000*/)",
                "Try encoding variations",
                "Use multiline payloads",
                "Try case variations",
                "Use /**//**/ comment patterns",
            ],
        }

        # Generic bypass techniques
        self.generic_bypass = [
            "Use different encodings (URL, double URL, Unicode, Base64)",
            "Try HTTP method override (X-HTTP-Method-Override)",
            "Use chunked transfer encoding",
            "Add random parameters as noise",
            "Try case variations in payloads",
            "Split payloads across multiple parameters",
            "Use HTTP Parameter Pollution (HPP)",
            "Try JSON/XML format switching",
            "Use multipart/form-data",
            "Add whitespace/comments in payloads",
            "Use IP rotation/residential proxies",
            "Implement request delays (2-5 seconds)",
            "Rotate User-Agent strings",
        ]

    def detect(self, response_headers: str, response_body: str,
               cookies: str = "", status_code: int = 200) -> WAFDetectionResult:
        """
        Detect WAF from HTTP response.

        Args:
            response_headers: HTTP response headers
            response_body: HTTP response body
            cookies: Cookie string
            status_code: HTTP status code

        Returns:
            WAFDetectionResult with detection details
        """
        best_match = WAFDetectionResult(
            detected=False,
            waf_type=WAFType.NONE,
            confidence=0
        )

        for waf_type, sig in self.signatures.items():
            confidence = 0
            evidence = []

            # Check headers
            for pattern, weight in sig.get('headers', []):
                if re.search(pattern, response_headers, re.IGNORECASE):
                    confidence += weight
                    evidence.append(f"Header: {pattern}")

            # Check cookies
            for pattern, weight in sig.get('cookies', []):
                if re.search(pattern, cookies, re.IGNORECASE):
                    confidence += weight
                    evidence.append(f"Cookie: {pattern}")

            # Check body
            for pattern, weight in sig.get('body', []):
                if re.search(pattern, response_body, re.IGNORECASE):
                    confidence += weight
                    evidence.append(f"Body: {pattern}")

            # Check status code
            if status_code in sig.get('status_codes', []):
                confidence += 30
                evidence.append(f"Status: {status_code}")

            # Normalize confidence
            confidence = min(confidence, 100)

            if confidence > best_match.confidence:
                best_match = WAFDetectionResult(
                    detected=confidence >= 50,
                    waf_type=waf_type,
                    confidence=confidence,
                    evidence=evidence,
                    bypass_suggestions=self.get_bypass_techniques(waf_type)
                )

        return best_match

    def get_bypass_techniques(self, waf_type: WAFType) -> List[str]:
        """Get bypass techniques for a specific WAF."""
        specific = self.bypass_techniques.get(waf_type, [])
        return specific + self.generic_bypass

    def detect_rate_limiting(self, response_headers: str, response_body: str,
                            status_code: int) -> Dict[str, Any]:
        """Detect rate limiting from response."""
        result = {
            'detected': False,
            'type': None,
            'retry_after': None,
            'limit_remaining': None
        }

        # Check status code
        if status_code == 429:
            result['detected'] = True
            result['type'] = 'http_429'

        # Check headers
        rate_headers = {
            r'retry-after:\s*(\d+)': 'retry_after',
            r'x-ratelimit-remaining:\s*(\d+)': 'limit_remaining',
            r'x-rate-limit-remaining:\s*(\d+)': 'limit_remaining',
            r'ratelimit-remaining:\s*(\d+)': 'limit_remaining',
        }

        for pattern, field in rate_headers.items():
            match = re.search(pattern, response_headers, re.IGNORECASE)
            if match:
                result['detected'] = True
                result[field] = int(match.group(1))

        # Check body patterns
        rate_patterns = [
            r'rate\s*limit',
            r'too\s*many\s*requests',
            r'slow\s*down',
            r'request\s*limit',
            r'throttl',
        ]

        for pattern in rate_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                result['detected'] = True
                result['type'] = 'body_pattern'
                break

        return result

    def generate_evasion_headers(self, waf_type: WAFType = WAFType.UNKNOWN) -> Dict[str, str]:
        """Generate headers that may help evade WAF detection."""
        # Random realistic user agent
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]

        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

        # WAF-specific headers
        if waf_type == WAFType.CLOUDFLARE:
            # Don't add anything that triggers Cloudflare
            pass
        elif waf_type == WAFType.AKAMAI:
            headers['Pragma'] = 'no-cache'

        return headers

    def encode_payload(self, payload: str, encoding_type: str = 'url') -> str:
        """
        Encode payload using various techniques.

        Args:
            payload: Original payload
            encoding_type: Type of encoding (url, double_url, unicode, hex, mixed)

        Returns:
            Encoded payload
        """
        if encoding_type == 'url':
            return quote(payload, safe='')

        elif encoding_type == 'double_url':
            return quote(quote(payload, safe=''), safe='')

        elif encoding_type == 'unicode':
            # Convert to Unicode escape sequences
            return ''.join(f'\\u{ord(c):04x}' for c in payload)

        elif encoding_type == 'hex':
            # Convert to hex
            return ''.join(f'%{ord(c):02x}' for c in payload)

        elif encoding_type == 'mixed':
            # Mix of encodings
            result = []
            for c in payload:
                choice = random.randint(0, 2)
                if choice == 0:
                    result.append(c)
                elif choice == 1:
                    result.append(f'%{ord(c):02x}')
                else:
                    result.append(f'%{ord(c):02X}')
            return ''.join(result)

        return payload

    def calculate_delay(self, waf_type: WAFType, request_count: int = 0) -> float:
        """
        Calculate recommended delay between requests.

        Args:
            waf_type: Detected WAF type
            request_count: Number of requests made so far

        Returns:
            Recommended delay in seconds
        """
        base_delays = {
            WAFType.CLOUDFLARE: 2.0,
            WAFType.IMPERVA: 1.5,
            WAFType.AKAMAI: 1.0,
            WAFType.AWS_WAF: 0.5,
            WAFType.SUCURI: 1.5,
            WAFType.MODSECURITY: 0.3,
            WAFType.NONE: 0.1,
        }

        base = base_delays.get(waf_type, 1.0)

        # Add jitter
        jitter = random.uniform(0, base * 0.3)

        # Increase delay after many requests
        if request_count > 100:
            base *= 1.5
        elif request_count > 50:
            base *= 1.2

        return base + jitter
