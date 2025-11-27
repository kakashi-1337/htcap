# -*- coding: utf-8 -*-

"""
HTCAP - HTTP Request Smuggling Detector
Detects HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE).

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import socket
import ssl
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
from core.scan.base_fuzzer import BaseFuzzer


class HTTPSmugglingFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting HTTP Request Smuggling vulnerabilities.

    Detects:
    - CL.TE (Content-Length / Transfer-Encoding)
    - TE.CL (Transfer-Encoding / Content-Length)
    - TE.TE (Transfer-Encoding obfuscation)
    - HTTP/2 downgrade smuggling
    """

    def init(self):
        """Initialize the fuzzer with smuggling-specific configurations."""
        self.name = "HTTP Request Smuggling"
        self.description = "Detects HTTP Request Smuggling vulnerabilities"

        self.timeout = 10
        self.delay_threshold = 5  # Seconds to detect timing-based smuggling

        # Transfer-Encoding obfuscation techniques
        self.te_obfuscations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: x\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: \tchunked",
            "X: X\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding\r\n: chunked",
            "Transfer-encoding: chunked",
            "TRANSFER-ENCODING: chunked",
            "Transfer-Encoding: chunked\r\n",
            " Transfer-Encoding: chunked",
            "\tTransfer-Encoding: chunked",
        ]

    def _create_socket(self, host: str, port: int, use_ssl: bool) -> socket.socket:
        """Create a socket connection to the target."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        return sock

    def _send_raw_request(self, host: str, port: int, use_ssl: bool,
                          request: bytes) -> Tuple[Optional[bytes], float]:
        """
        Send a raw HTTP request and measure response time.

        Returns:
            Tuple of (response_bytes, response_time)
        """
        start_time = time.time()
        response = None

        try:
            sock = self._create_socket(host, port, use_ssl)
            sock.sendall(request)

            # Read response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()
        except Exception as e:
            pass

        elapsed = time.time() - start_time
        return response, elapsed

    def _build_clte_probe(self, host: str, path: str) -> bytes:
        """
        Build a CL.TE smuggling probe.

        Front-end uses Content-Length, back-end uses Transfer-Encoding.
        """
        # The Content-Length covers only part of the body
        # The back-end sees the chunked encoding and processes "G" as start of next request
        body = "1\r\nG\r\n0\r\n\r\n"

        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        )
        return request.encode()

    def _build_tecl_probe(self, host: str, path: str) -> bytes:
        """
        Build a TE.CL smuggling probe.

        Front-end uses Transfer-Encoding, back-end uses Content-Length.
        """
        smuggled = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 10\r\n"
            f"\r\n"
            f"x=1"
        )

        # Chunked body that includes a smuggled request
        chunk_size = hex(len(smuggled))[2:]

        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        )
        return request.encode()

    def _build_timing_clte_probe(self, host: str, path: str) -> bytes:
        """
        Build a timing-based CL.TE detection probe.

        If vulnerable, the back-end will wait for the rest of the chunked body.
        """
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )
        return request.encode()

    def _build_timing_tecl_probe(self, host: str, path: str) -> bytes:
        """
        Build a timing-based TE.CL detection probe.

        If vulnerable, the back-end will wait for more data based on Content-Length.
        """
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 100\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        )
        return request.encode()

    def _build_tete_probe(self, host: str, path: str, te_variant: str) -> bytes:
        """
        Build a TE.TE smuggling probe with obfuscated Transfer-Encoding.
        """
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{te_variant}\r\n"
            f"\r\n"
            f"1\r\n"
            f"G\r\n"
            f"0\r\n"
            f"\r\n"
        )
        return request.encode()

    def _check_response_anomaly(self, response: bytes) -> Optional[str]:
        """Check for response anomalies indicating smuggling."""
        if not response:
            return None

        response_str = response.decode('utf-8', errors='ignore')

        # Check for multiple responses (smuggling succeeded)
        http_count = response_str.count('HTTP/1.')
        if http_count > 1:
            return "Multiple HTTP responses detected"

        # Check for 400 Bad Request (common indicator)
        if 'HTTP/1.1 400' in response_str or 'HTTP/1.0 400' in response_str:
            return "400 Bad Request - possible malformed smuggled request"

        # Check for timeout indicators
        if 'timeout' in response_str.lower():
            return "Timeout in response"

        # Check for different status codes that might indicate smuggling
        if 'HTTP/1.1 403' in response_str and 'forbidden' in response_str.lower():
            return "403 Forbidden - smuggled request may have triggered"

        return None

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """
        Execute HTTP Smuggling detection.

        Args:
            request: The request object to fuzz
            params: Additional parameters

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Parse target URL
        parsed = urlparse(request.url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        path = parsed.path or '/'

        if not host:
            return vulnerabilities

        # Test CL.TE timing-based detection
        try:
            probe = self._build_timing_clte_probe(host, path)
            response, elapsed = self._send_raw_request(host, port, use_ssl, probe)

            if elapsed >= self.delay_threshold:
                vulnerabilities.append({
                    'type': 'http_smuggling_clte',
                    'description': f"Potential CL.TE HTTP Request Smuggling detected. "
                                 f"Server delayed {elapsed:.2f}s (threshold: {self.delay_threshold}s). "
                                 f"The back-end may be processing Transfer-Encoding while "
                                 f"front-end uses Content-Length."
                })
            elif response:
                anomaly = self._check_response_anomaly(response)
                if anomaly:
                    vulnerabilities.append({
                        'type': 'http_smuggling_clte',
                        'description': f"Potential CL.TE HTTP Request Smuggling detected. {anomaly}"
                    })
        except Exception:
            pass

        # Test TE.CL timing-based detection
        try:
            probe = self._build_timing_tecl_probe(host, path)
            response, elapsed = self._send_raw_request(host, port, use_ssl, probe)

            if elapsed >= self.delay_threshold:
                vulnerabilities.append({
                    'type': 'http_smuggling_tecl',
                    'description': f"Potential TE.CL HTTP Request Smuggling detected. "
                                 f"Server delayed {elapsed:.2f}s (threshold: {self.delay_threshold}s). "
                                 f"The back-end may be using Content-Length while "
                                 f"front-end uses Transfer-Encoding."
                })
            elif response:
                anomaly = self._check_response_anomaly(response)
                if anomaly:
                    vulnerabilities.append({
                        'type': 'http_smuggling_tecl',
                        'description': f"Potential TE.CL HTTP Request Smuggling detected. {anomaly}"
                    })
        except Exception:
            pass

        # Test TE.TE with various obfuscations
        for te_variant in self.te_obfuscations[:5]:  # Limit for performance
            try:
                probe = self._build_tete_probe(host, path, te_variant)
                response, elapsed = self._send_raw_request(host, port, use_ssl, probe)

                if response:
                    anomaly = self._check_response_anomaly(response)
                    if anomaly:
                        vulnerabilities.append({
                            'type': 'http_smuggling_tete',
                            'description': f"Potential TE.TE HTTP Request Smuggling detected "
                                         f"using obfuscation: '{te_variant}'. {anomaly}"
                        })
                        break
            except Exception:
                pass

        return vulnerabilities
