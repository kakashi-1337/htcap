# -*- coding: utf-8 -*-

"""
HTCAP Extensions - WebSocket Analyzer
Analyze WebSocket communications for security vulnerabilities.

For AUTHORIZED penetration testing only.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import json
import hashlib
from typing import List, Dict, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class MessageDirection(Enum):
    """WebSocket message direction."""
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


class WSVulnType(Enum):
    """WebSocket vulnerability types."""
    MISSING_AUTH = "missing_authentication"
    WEAK_AUTH = "weak_authentication"
    CSRF = "cross_site_websocket_hijacking"
    INJECTION = "injection"
    SENSITIVE_DATA = "sensitive_data_exposure"
    INSECURE_ORIGIN = "insecure_origin"
    NO_TLS = "no_tls"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    MASS_ASSIGNMENT = "mass_assignment"
    IDOR = "idor"


class MessageType(Enum):
    """Types of WebSocket messages."""
    TEXT = "text"
    BINARY = "binary"
    PING = "ping"
    PONG = "pong"
    CLOSE = "close"


@dataclass
class WSMessage:
    """Represents a WebSocket message."""
    direction: MessageDirection
    message_type: MessageType
    data: Any
    timestamp: datetime = field(default_factory=datetime.now)
    size: int = 0

    def __post_init__(self):
        if isinstance(self.data, (str, bytes)):
            self.size = len(self.data)


@dataclass
class WSEndpoint:
    """Represents a WebSocket endpoint."""
    url: str
    origin: Optional[str] = None
    protocols: List[str] = field(default_factory=list)
    is_secure: bool = False
    requires_auth: bool = False
    auth_type: Optional[str] = None


@dataclass
class WSVulnerability:
    """Represents a WebSocket vulnerability finding."""
    vuln_type: WSVulnType
    endpoint: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class WebSocketAnalyzer:
    """
    Analyze WebSocket traffic for security issues.

    Features:
    - Message pattern analysis
    - Authentication detection
    - Injection point identification
    - Sensitive data detection
    - CSWSH detection
    """

    # Patterns that might indicate sensitive data
    SENSITIVE_PATTERNS = [
        (r'"password"\s*:\s*"[^"]+', "password"),
        (r'"token"\s*:\s*"[^"]+', "token"),
        (r'"api_?key"\s*:\s*"[^"]+', "api_key"),
        (r'"secret"\s*:\s*"[^"]+', "secret"),
        (r'"credit_?card"\s*:\s*"\d+', "credit_card"),
        (r'"ssn"\s*:\s*"\d+', "ssn"),
        (r'"email"\s*:\s*"[^"]+@[^"]+', "email"),
        (r'"session"\s*:\s*"[^"]+', "session"),
        (r'"auth"\s*:\s*"[^"]+', "auth"),
        (r'\b[A-Za-z0-9+/]{40,}={0,2}\b', "base64_blob"),
    ]

    # Patterns for injection testing
    INJECTION_PAYLOADS = {
        "sql": ["' OR '1'='1", "1; DROP TABLE", "UNION SELECT"],
        "nosql": ['{"$gt":""}', '{"$ne":""}', '{"$where":"1==1"}'],
        "command": ["; ls", "| cat /etc/passwd", "`id`"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    }

    def __init__(self):
        self.endpoints: List[WSEndpoint] = []
        self.messages: List[WSMessage] = []
        self.vulnerabilities: List[WSVulnerability] = []
        self.message_patterns: Dict[str, int] = {}

    def add_endpoint(self, url: str, origin: Optional[str] = None,
                     protocols: List[str] = None) -> WSEndpoint:
        """Register a WebSocket endpoint for analysis."""
        is_secure = url.startswith('wss://')

        endpoint = WSEndpoint(
            url=url,
            origin=origin,
            protocols=protocols or [],
            is_secure=is_secure
        )
        self.endpoints.append(endpoint)
        return endpoint

    def record_message(self, endpoint_url: str, direction: MessageDirection,
                      data: Any, message_type: MessageType = MessageType.TEXT):
        """Record a WebSocket message for analysis."""
        message = WSMessage(
            direction=direction,
            message_type=message_type,
            data=data
        )
        self.messages.append(message)

        # Track message patterns
        if isinstance(data, str):
            pattern_hash = self._get_message_pattern(data)
            self.message_patterns[pattern_hash] = \
                self.message_patterns.get(pattern_hash, 0) + 1

    def _get_message_pattern(self, data: str) -> str:
        """Extract structural pattern from message (normalize values)."""
        try:
            obj = json.loads(data)
            return self._normalize_json(obj)
        except json.JSONDecodeError:
            # For non-JSON, hash the structure
            normalized = re.sub(r'\d+', 'N', data)
            normalized = re.sub(r'"[^"]*"', '"S"', normalized)
            return hashlib.md5(normalized.encode()).hexdigest()[:16]

    def _normalize_json(self, obj: Any, depth: int = 0) -> str:
        """Normalize JSON to extract structure."""
        if depth > 10:
            return "..."

        if isinstance(obj, dict):
            keys = sorted(obj.keys())
            return "{" + ",".join(f"{k}:{self._normalize_json(obj[k], depth+1)}"
                                  for k in keys) + "}"
        elif isinstance(obj, list):
            if len(obj) == 0:
                return "[]"
            return f"[{self._normalize_json(obj[0], depth+1)}...]"
        elif isinstance(obj, str):
            return "S"
        elif isinstance(obj, (int, float)):
            return "N"
        elif isinstance(obj, bool):
            return "B"
        else:
            return "?"

    def analyze(self) -> List[WSVulnerability]:
        """Run all security checks on recorded data."""
        self.vulnerabilities = []

        for endpoint in self.endpoints:
            self._check_tls(endpoint)
            self._check_origin(endpoint)
            self._check_auth(endpoint)

        self._check_sensitive_data()
        self._check_injection_points()
        self._check_cswsh()
        self._check_idor()

        return self.vulnerabilities

    def _check_tls(self, endpoint: WSEndpoint):
        """Check if WebSocket uses TLS."""
        if not endpoint.is_secure:
            self.vulnerabilities.append(WSVulnerability(
                vuln_type=WSVulnType.NO_TLS,
                endpoint=endpoint.url,
                description="WebSocket connection does not use TLS (wss://)",
                severity="high",
                evidence={"url": endpoint.url},
                recommendations=[
                    "Use wss:// instead of ws://",
                    "Ensure valid TLS certificate",
                    "Implement certificate pinning for mobile apps"
                ]
            ))

    def _check_origin(self, endpoint: WSEndpoint):
        """Check for origin validation issues."""
        # This would need actual testing, but we can flag potential issues
        if endpoint.origin:
            self.vulnerabilities.append(WSVulnerability(
                vuln_type=WSVulnType.INSECURE_ORIGIN,
                endpoint=endpoint.url,
                description="WebSocket may not properly validate Origin header",
                severity="medium",
                evidence={"origin": endpoint.origin},
                recommendations=[
                    "Validate Origin header server-side",
                    "Whitelist allowed origins",
                    "Reject connections from unexpected origins"
                ]
            ))

    def _check_auth(self, endpoint: WSEndpoint):
        """Check authentication mechanisms."""
        # Look for auth patterns in messages
        has_auth = False
        auth_method = None

        for msg in self.messages:
            if isinstance(msg.data, str):
                data_lower = msg.data.lower()
                if any(kw in data_lower for kw in ['auth', 'login', 'token', 'bearer']):
                    has_auth = True
                    if 'bearer' in data_lower:
                        auth_method = 'bearer_token'
                    elif 'token' in data_lower:
                        auth_method = 'token'
                    break

        if not has_auth:
            self.vulnerabilities.append(WSVulnerability(
                vuln_type=WSVulnType.MISSING_AUTH,
                endpoint=endpoint.url,
                description="No authentication detected in WebSocket handshake or messages",
                severity="high",
                recommendations=[
                    "Implement authentication before WebSocket upgrade",
                    "Use token-based authentication",
                    "Validate session on each message"
                ]
            ))

        endpoint.requires_auth = has_auth
        endpoint.auth_type = auth_method

    def _check_sensitive_data(self):
        """Check for sensitive data in messages."""
        for msg in self.messages:
            if not isinstance(msg.data, str):
                continue

            for pattern, data_type in self.SENSITIVE_PATTERNS:
                matches = re.findall(pattern, msg.data, re.IGNORECASE)
                if matches:
                    # Mask the sensitive data for reporting
                    masked = [m[:10] + "***" if len(m) > 10 else "***"
                             for m in matches]

                    self.vulnerabilities.append(WSVulnerability(
                        vuln_type=WSVulnType.SENSITIVE_DATA,
                        endpoint="websocket",
                        description=f"Sensitive data ({data_type}) found in WebSocket message",
                        severity="high" if data_type in ['password', 'credit_card', 'ssn']
                                 else "medium",
                        evidence={
                            "data_type": data_type,
                            "direction": msg.direction.value,
                            "masked_samples": masked[:3]
                        },
                        recommendations=[
                            "Avoid sending sensitive data over WebSocket",
                            "Encrypt sensitive payloads",
                            "Use one-time tokens instead of credentials"
                        ]
                    ))

    def _check_injection_points(self):
        """Identify potential injection points in messages."""
        for msg in self.messages:
            if msg.direction != MessageDirection.CLIENT_TO_SERVER:
                continue

            if not isinstance(msg.data, str):
                continue

            try:
                obj = json.loads(msg.data)
                injection_points = self._find_injection_points(obj)

                if injection_points:
                    self.vulnerabilities.append(WSVulnerability(
                        vuln_type=WSVulnType.INJECTION,
                        endpoint="websocket",
                        description="Potential injection points found in WebSocket messages",
                        severity="medium",
                        evidence={
                            "fields": injection_points,
                            "sample_message": msg.data[:200]
                        },
                        recommendations=[
                            "Validate and sanitize all input fields",
                            "Use parameterized queries for database operations",
                            "Implement input type checking"
                        ]
                    ))
            except json.JSONDecodeError:
                # Non-JSON message might still have injection points
                if any(c in msg.data for c in ["'", '"', '<', '>', '|', ';']):
                    self.vulnerabilities.append(WSVulnerability(
                        vuln_type=WSVulnType.INJECTION,
                        endpoint="websocket",
                        description="Non-JSON WebSocket message with special characters",
                        severity="low",
                        evidence={"sample": msg.data[:100]},
                        recommendations=[
                            "Validate message format",
                            "Escape special characters"
                        ]
                    ))

    def _find_injection_points(self, obj: Any, path: str = "") -> List[str]:
        """Find fields that might be injection points."""
        points = []

        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key

                # Check if key suggests user input
                input_keywords = ['id', 'name', 'query', 'search', 'filter',
                                 'user', 'input', 'data', 'value', 'param',
                                 'cmd', 'command', 'file', 'path', 'url']

                if any(kw in key.lower() for kw in input_keywords):
                    if isinstance(value, str):
                        points.append(current_path)

                # Recurse
                points.extend(self._find_injection_points(value, current_path))

        elif isinstance(obj, list):
            for i, item in enumerate(obj[:3]):  # Check first 3 items
                points.extend(self._find_injection_points(item, f"{path}[{i}]"))

        return points

    def _check_cswsh(self):
        """Check for Cross-Site WebSocket Hijacking vulnerability."""
        # CSWSH is possible when:
        # 1. No Origin validation
        # 2. Auth relies on cookies
        # 3. No CSRF token in messages

        for endpoint in self.endpoints:
            has_csrf_token = False
            uses_cookie_auth = False

            for msg in self.messages:
                if isinstance(msg.data, str):
                    if 'csrf' in msg.data.lower() or '_token' in msg.data.lower():
                        has_csrf_token = True
                    if 'cookie' in msg.data.lower():
                        uses_cookie_auth = True

            if not has_csrf_token:
                self.vulnerabilities.append(WSVulnerability(
                    vuln_type=WSVulnType.CSRF,
                    endpoint=endpoint.url,
                    description="WebSocket may be vulnerable to Cross-Site WebSocket Hijacking (CSWSH)",
                    severity="high",
                    evidence={
                        "has_csrf_token": has_csrf_token,
                        "uses_cookie_auth": uses_cookie_auth
                    },
                    recommendations=[
                        "Validate Origin header",
                        "Implement CSRF tokens in handshake",
                        "Use non-cookie based authentication",
                        "Require explicit user action before WS connection"
                    ]
                ))

    def _check_idor(self):
        """Check for potential IDOR in WebSocket messages."""
        id_patterns = [
            r'"(?:id|user_?id|account_?id|order_?id)"\s*:\s*(\d+)',
            r'"(?:id|user_?id|account_?id|order_?id)"\s*:\s*"([^"]+)"',
        ]

        seen_ids = {}

        for msg in self.messages:
            if not isinstance(msg.data, str):
                continue

            for pattern in id_patterns:
                matches = re.findall(pattern, msg.data, re.IGNORECASE)
                for match in matches:
                    if match not in seen_ids:
                        seen_ids[match] = []
                    seen_ids[match].append(msg.direction.value)

        # If we see IDs, flag for manual testing
        if seen_ids:
            self.vulnerabilities.append(WSVulnerability(
                vuln_type=WSVulnType.IDOR,
                endpoint="websocket",
                description="ID-based references found in WebSocket messages - test for IDOR",
                severity="medium",
                evidence={
                    "id_count": len(seen_ids),
                    "sample_ids": list(seen_ids.keys())[:5]
                },
                recommendations=[
                    "Test access control by modifying ID values",
                    "Implement proper authorization checks",
                    "Use UUIDs instead of sequential IDs"
                ]
            ))

    def generate_injection_payloads(self, message_template: str) -> List[Dict]:
        """
        Generate injection test payloads based on a message template.

        Args:
            message_template: Original WebSocket message

        Returns:
            List of test payloads with injection type
        """
        payloads = []

        try:
            obj = json.loads(message_template)
            injection_points = self._find_injection_points(obj)

            for point in injection_points:
                for inj_type, inj_payloads in self.INJECTION_PAYLOADS.items():
                    for payload in inj_payloads:
                        modified = self._inject_payload(obj, point, payload)
                        payloads.append({
                            "injection_type": inj_type,
                            "field": point,
                            "payload": payload,
                            "message": json.dumps(modified)
                        })

        except json.JSONDecodeError:
            # For non-JSON, append payloads
            for inj_type, inj_payloads in self.INJECTION_PAYLOADS.items():
                for payload in inj_payloads:
                    payloads.append({
                        "injection_type": inj_type,
                        "field": "raw",
                        "payload": payload,
                        "message": message_template + payload
                    })

        return payloads

    def _inject_payload(self, obj: Any, path: str, payload: str) -> Any:
        """Inject payload into object at path."""
        import copy
        result = copy.deepcopy(obj)

        parts = path.replace('[', '.').replace(']', '').split('.')
        current = result

        for i, part in enumerate(parts[:-1]):
            if part.isdigit():
                current = current[int(part)]
            else:
                current = current[part]

        final = parts[-1]
        if final.isdigit():
            current[int(final)] = payload
        else:
            current[final] = payload

        return result

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        return {
            "endpoints_analyzed": len(self.endpoints),
            "messages_recorded": len(self.messages),
            "unique_patterns": len(self.message_patterns),
            "vulnerabilities_found": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "vuln_types": list(set(v.vuln_type.value for v in self.vulnerabilities))
        }

    def to_json(self) -> str:
        """Export analysis results to JSON."""
        return json.dumps({
            "endpoints": [
                {
                    "url": e.url,
                    "is_secure": e.is_secure,
                    "protocols": e.protocols,
                    "requires_auth": e.requires_auth,
                    "auth_type": e.auth_type
                }
                for e in self.endpoints
            ],
            "vulnerabilities": [
                {
                    "type": v.vuln_type.value,
                    "endpoint": v.endpoint,
                    "description": v.description,
                    "severity": v.severity,
                    "evidence": v.evidence,
                    "recommendations": v.recommendations
                }
                for v in self.vulnerabilities
            ],
            "summary": self.get_summary()
        }, indent=2)
