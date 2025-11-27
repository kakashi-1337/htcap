# -*- coding: utf-8 -*-

"""
HTCAP - Insecure Direct Object Reference (IDOR) Fuzzer
Detects IDOR vulnerabilities by manipulating object references.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import json
import hashlib
import uuid
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.scan.base_fuzzer import BaseFuzzer
from core.constants import VULNTYPE_IDOR


class IDORFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting Insecure Direct Object Reference vulnerabilities.

    Detects:
    - Numeric ID manipulation (id=1 -> id=2)
    - UUID/GUID manipulation
    - Encoded ID manipulation (base64, hex)
    - Horizontal privilege escalation
    - Vertical privilege escalation
    - Path-based IDOR (/users/123/profile)
    """

    def init(self):
        """Initialize the fuzzer with IDOR-specific configurations."""
        self.name = "IDOR Detection"
        self.description = "Detects Insecure Direct Object Reference vulnerabilities"

        # Parameter names commonly vulnerable to IDOR
        self.idor_params = [
            'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid',
            'profile_id', 'profileid', 'doc_id', 'docid', 'document_id',
            'file_id', 'fileid', 'order_id', 'orderid', 'invoice_id',
            'payment_id', 'transaction_id', 'txn_id', 'record_id',
            'item_id', 'itemid', 'product_id', 'productid', 'cart_id',
            'message_id', 'msg_id', 'thread_id', 'comment_id', 'post_id',
            'article_id', 'blog_id', 'page_id', 'report_id', 'ticket_id',
            'customer_id', 'client_id', 'member_id', 'employee_id',
            'project_id', 'task_id', 'job_id', 'ref', 'reference',
            'no', 'num', 'number', 'key', 'token', 'uuid', 'guid',
            'handle', 'username', 'email', 'phone', 'acct', 'account',
        ]

        # Patterns to identify object references
        self.id_patterns = {
            'numeric': r'^\d+$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'uuid_no_dash': r'^[0-9a-f]{32}$',
            'base64': r'^[A-Za-z0-9+/]+=*$',
            'hex': r'^[0-9a-fA-F]+$',
            'mongodb_objectid': r'^[0-9a-fA-F]{24}$',
            'short_hash': r'^[a-zA-Z0-9]{6,12}$',
        }

        # Test values for different ID types
        self.test_mutations = {
            'numeric': [
                lambda x: str(int(x) + 1),  # Increment
                lambda x: str(int(x) - 1),  # Decrement
                lambda x: '1',              # First ID
                lambda x: '0',              # Zero
                lambda x: '-1',             # Negative
                lambda x: str(int(x) * 2),  # Double
                lambda x: '999999',         # Large number
                lambda x: '2',              # Common test ID
            ],
            'uuid': [
                lambda x: str(uuid.uuid4()),  # Random UUID
                lambda x: '00000000-0000-0000-0000-000000000001',  # Test UUID
                lambda x: x[:-1] + ('0' if x[-1] != '0' else '1'),  # Modify last char
            ],
            'base64': [
                lambda x: self._modify_base64(x),
            ],
        }

        # Response indicators for successful IDOR
        self.success_indicators = [
            # Different user data exposed
            r'other.*user',
            r'unauthorized.*access',
            r'different.*account',
            # PII exposure
            r'email.*@',
            r'phone.*\d{3}',
            r'address',
            r'credit.*card',
            r'ssn',
            r'password',
            # Financial data
            r'balance',
            r'amount',
            r'transaction',
            r'payment',
        ]

        # Error indicators (not vulnerable)
        self.error_indicators = [
            r'not\s*found',
            r'404',
            r'does\s*not\s*exist',
            r'invalid.*id',
            r'unauthorized',
            r'forbidden',
            r'access\s*denied',
            r'permission',
            r'authentication\s*required',
        ]

    def _modify_base64(self, value: str) -> str:
        """Modify a base64 encoded value."""
        import base64
        try:
            decoded = base64.b64decode(value).decode('utf-8')
            # Try to find and modify numeric values
            modified = re.sub(r'\d+', lambda m: str(int(m.group()) + 1), decoded)
            return base64.b64encode(modified.encode()).decode('utf-8')
        except:
            return value

    def _identify_id_type(self, value: str) -> Optional[str]:
        """Identify the type of ID based on its format."""
        for id_type, pattern in self.id_patterns.items():
            if re.match(pattern, value, re.IGNORECASE):
                return id_type
        return None

    def _is_idor_param(self, param_name: str) -> bool:
        """Check if a parameter name suggests it's an object reference."""
        param_lower = param_name.lower()
        return any(idor_param in param_lower for idor_param in self.idor_params)

    def _extract_path_ids(self, url: str) -> List[Tuple[int, str, str]]:
        """
        Extract potential IDs from URL path.
        Returns list of (position, original_value, id_type)
        """
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        ids = []

        for i, part in enumerate(path_parts):
            if part:
                id_type = self._identify_id_type(part)
                if id_type:
                    ids.append((i, part, id_type))

        return ids

    def _extract_param_ids(self, request) -> List[Tuple[str, str, str, str]]:
        """
        Extract potential IDs from query params and body.
        Returns list of (location, param_name, original_value, id_type)
        """
        ids = []

        # Check URL parameters
        parsed = urlparse(request.url)
        query_params = parse_qs(parsed.query)

        for param, values in query_params.items():
            if self._is_idor_param(param) or self._identify_id_type(values[0]):
                id_type = self._identify_id_type(values[0])
                if id_type:
                    ids.append(('url', param, values[0], id_type))

        # Check body parameters
        if request.data:
            try:
                if isinstance(request.data, str):
                    body_data = json.loads(request.data)
                else:
                    body_data = request.data

                if isinstance(body_data, dict):
                    self._extract_json_ids(body_data, ids, 'body')
            except json.JSONDecodeError:
                # Try URL-encoded form data
                for param in request.data.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        if self._is_idor_param(key):
                            id_type = self._identify_id_type(value)
                            if id_type:
                                ids.append(('body', key, value, id_type))

        return ids

    def _extract_json_ids(self, data: Dict, ids: List, location: str, path: str = ""):
        """Recursively extract IDs from JSON data."""
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            if isinstance(value, dict):
                self._extract_json_ids(value, ids, location, current_path)
            elif isinstance(value, str):
                if self._is_idor_param(key):
                    id_type = self._identify_id_type(value)
                    if id_type:
                        ids.append((location, current_path, value, id_type))
            elif isinstance(value, int):
                if self._is_idor_param(key):
                    ids.append((location, current_path, str(value), 'numeric'))

    def _mutate_url_path(self, url: str, position: int, new_value: str) -> str:
        """Replace a path segment with a new value."""
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        path_parts[position] = new_value
        new_path = '/'.join(path_parts)
        return urlunparse(parsed._replace(path=new_path))

    def _mutate_url_param(self, url: str, param: str, new_value: str) -> str:
        """Replace a URL parameter with a new value."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params[param] = [new_value]
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _mutate_body_param(self, data: str, param: str, new_value: str) -> str:
        """Replace a body parameter with a new value."""
        try:
            body = json.loads(data)
            if isinstance(body, dict):
                # Handle nested paths like "user.id"
                parts = param.split('.')
                current = body
                for part in parts[:-1]:
                    current = current[part]
                current[parts[-1]] = new_value
                return json.dumps(body)
        except json.JSONDecodeError:
            # URL-encoded form data
            new_params = []
            for p in data.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    if k == param:
                        new_params.append(f"{k}={new_value}")
                    else:
                        new_params.append(p)
                else:
                    new_params.append(p)
            return '&'.join(new_params)

        return data

    def _calculate_response_hash(self, response_body: str) -> str:
        """Calculate a hash of the response for comparison."""
        # Normalize the response (remove dynamic elements)
        normalized = re.sub(r'\d{10,}', 'TIMESTAMP', response_body)  # Unix timestamps
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                           'UUID', normalized, flags=re.IGNORECASE)
        return hashlib.md5(normalized.encode()).hexdigest()

    def _responses_are_different(self, resp1: str, resp2: str) -> bool:
        """Check if two responses are meaningfully different."""
        if not resp1 or not resp2:
            return False

        hash1 = self._calculate_response_hash(resp1)
        hash2 = self._calculate_response_hash(resp2)

        if hash1 != hash2:
            # Also check length difference
            len_diff = abs(len(resp1) - len(resp2))
            # Significant difference if hash differs and length change > 10%
            return len_diff > (len(resp1) * 0.1)

        return False

    def _check_for_sensitive_data(self, response: str) -> Optional[str]:
        """Check if response contains sensitive data indicators."""
        for indicator in self.success_indicators:
            if re.search(indicator, response, re.IGNORECASE):
                return indicator
        return None

    def _is_error_response(self, response: str) -> bool:
        """Check if response indicates an error/denial."""
        for indicator in self.error_indicators:
            if re.search(indicator, response, re.IGNORECASE):
                return True
        return False

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """
        Execute IDOR fuzzing.

        Args:
            request: The request object to fuzz
            params: Additional parameters

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Get original response for comparison
        try:
            original_response = self.send_request(request)
            if not original_response:
                return vulnerabilities
            original_body = original_response.body
        except Exception:
            return vulnerabilities

        # Extract IDs from URL path
        path_ids = self._extract_path_ids(request.url)

        # Extract IDs from parameters
        param_ids = self._extract_param_ids(request)

        # Test path-based IDOR
        for position, original_value, id_type in path_ids:
            mutations = self.test_mutations.get(id_type, [])

            for mutator in mutations[:3]:  # Limit mutations for performance
                try:
                    new_value = mutator(original_value)
                    if new_value == original_value:
                        continue

                    modified_url = self._mutate_url_path(request.url, position, new_value)
                    response = self.send_request(request, modified_url=modified_url)

                    if response and not self._is_error_response(response.body):
                        if self._responses_are_different(original_body, response.body):
                            sensitive = self._check_for_sensitive_data(response.body)
                            vulnerabilities.append({
                                'type': VULNTYPE_IDOR,
                                'description': f"Path-based IDOR detected. Changed '{original_value}' to '{new_value}' "
                                             f"in URL path and received different data. "
                                             f"{'Sensitive data indicator: ' + sensitive if sensitive else ''}"
                            })
                            break
                except Exception:
                    pass

        # Test parameter-based IDOR
        for location, param_name, original_value, id_type in param_ids:
            mutations = self.test_mutations.get(id_type, [])

            for mutator in mutations[:3]:  # Limit mutations for performance
                try:
                    new_value = mutator(original_value)
                    if new_value == original_value:
                        continue

                    if location == 'url':
                        modified_url = self._mutate_url_param(request.url, param_name, new_value)
                        response = self.send_request(request, modified_url=modified_url)
                    else:
                        modified_data = self._mutate_body_param(request.data, param_name, new_value)
                        response = self.send_request(request, data=modified_data)

                    if response and not self._is_error_response(response.body):
                        if self._responses_are_different(original_body, response.body):
                            sensitive = self._check_for_sensitive_data(response.body)
                            vulnerabilities.append({
                                'type': VULNTYPE_IDOR,
                                'description': f"Parameter-based IDOR detected in '{param_name}'. "
                                             f"Changed '{original_value}' to '{new_value}' "
                                             f"and received different data. "
                                             f"{'Sensitive data indicator: ' + sensitive if sensitive else ''}"
                            })
                            break
                except Exception:
                    pass

        return vulnerabilities
