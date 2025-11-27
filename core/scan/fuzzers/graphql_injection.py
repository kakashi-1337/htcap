# -*- coding: utf-8 -*-

"""
HTCAP - GraphQL Injection Fuzzer
Detects GraphQL-specific vulnerabilities including injection attacks,
introspection issues, and query manipulation.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import json
import re
from typing import List, Dict, Any, Optional, Tuple
from core.scan.base_fuzzer import BaseFuzzer
from core.constants import (
    VULNTYPE_SQLI,
    VULNTYPE_NOSQLI,
    REQTYPE_GRAPHQL,
    CONTENT_TYPE_JSON
)


class GraphQLInjection(BaseFuzzer):
    """
    Fuzzer for detecting GraphQL injection vulnerabilities.

    Detects:
    - SQL injection via GraphQL arguments
    - NoSQL injection
    - GraphQL query manipulation
    - Introspection information disclosure
    - Batching attacks
    - Alias-based DoS potential
    """

    def init(self):
        """Initialize the fuzzer with GraphQL-specific payloads."""
        self.name = "GraphQL Injection"
        self.description = "Detects GraphQL injection vulnerabilities"

        # SQL injection payloads adapted for GraphQL
        self.sqli_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1' --",
            "1\" OR \"1\"=\"1\" --",
            "'; DROP TABLE users; --",
            "1; SELECT * FROM users",
            "' UNION SELECT NULL--",
            "' UNION SELECT username, password FROM users--",
            "1' AND '1'='1",
            "1' AND SLEEP(5)--",
            "1' WAITFOR DELAY '0:0:5'--",
            "' OR 1=1#",
            "admin'--",
            "1' ORDER BY 1--",
        ]

        # NoSQL injection payloads
        self.nosqli_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "this.password.length > 0"}',
            '{"$or": [{"a": 1}, {"b": 2}]}',
            "'; return true; var x='",
            '{"$gt": "", "$lt": "~"}',
            '{"$nin": []}',
        ]

        # GraphQL-specific attack payloads
        self.graphql_payloads = [
            # Field suggestion exploitation
            '__typename',
            # Directive injection
            '@skip(if: true)',
            '@include(if: false)',
            # Alias bombing (DoS detection)
            'a1: __typename\na2: __typename\na3: __typename',
            # Fragment spreading
            '...on Query { __typename }',
        ]

        # Error patterns indicating SQL injection
        self.sql_error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'MySqlException',
            r'valid MySQL result',
            r'check the manual that corresponds to your (MySQL|MariaDB)',
            r'MySqlClient\.',
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'Driver.*SQL[\-\_\ ]*Server',
            r'OLE DB.*SQL Server',
            r'\bSQL Server[^&lt;&quot;]+Driver',
            r'Warning.*mssql_',
            r'\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}',
            r'System\.Data\.SqlClient\.',
            r'(?s)Exception.*\WRoadhouse\.Cms\.',
            r'Microsoft SQL Native Client error \'[0-9a-fA-F]{8}',
            r'com\.microsoft\.sqlserver\.jdbc',
            r'ODBC SQL Server Driver',
            r'SQLServer JDBC Driver',
            r'macaborpt',
            r'\[SQL Server\]',
            r'com\.informix\.jdbc',
            r'Exception.*Informix',
            r'ORA-[0-9]{5}',
            r'Oracle error',
            r'Warning.*oci_',
            r'Warning.*ora_',
            r'CLI Driver.*DB2',
            r'DB2 SQL error',
            r'SQLite/JDBCDriver',
            r'SQLite\.Exception',
            r'System\.Data\.SQLite\.SQLiteException',
            r'Warning.*sqlite_',
            r'Warning.*SQLite3::',
            r'\[SQLITE_ERROR\]',
            r'SQLITE_CONSTRAINT',
            r'sqlite3\.OperationalError:',
            r'sqlite3\.ProgrammingError:',
            r'sqlite3\.IntegrityError:',
            r'org\.sqlite\.JDBC',
        ]

        # Error patterns indicating NoSQL injection
        self.nosql_error_patterns = [
            r'MongoError',
            r'mongo.*exception',
            r'\$where',
            r'BSON',
            r'unterminated string',
            r'Command failed with error',
            r'E11000 duplicate key',
        ]

        # GraphQL error patterns that might indicate vulnerabilities
        self.graphql_error_patterns = [
            r'Cannot query field',
            r'Unknown argument',
            r'Syntax Error',
            r'did you mean',
            r'Field.*doesn\'t exist',
            r'not authorized',
            r'permission denied',
        ]

    def is_graphql_request(self, request) -> bool:
        """Check if the request is a GraphQL request."""
        if request.type == REQTYPE_GRAPHQL:
            return True

        # Check URL patterns
        url_lower = request.url.lower()
        if '/graphql' in url_lower or '/gql' in url_lower:
            return True

        # Check if body contains GraphQL query
        if request.data:
            try:
                data = json.loads(request.data) if isinstance(request.data, str) else request.data
                if isinstance(data, dict) and ('query' in data or 'mutation' in data):
                    return True
            except (json.JSONDecodeError, TypeError):
                pass

        return False

    def parse_graphql_request(self, request) -> Optional[Dict[str, Any]]:
        """Parse GraphQL request data."""
        if not request.data:
            return None

        try:
            if isinstance(request.data, str):
                data = json.loads(request.data)
            else:
                data = request.data

            return {
                'query': data.get('query', ''),
                'variables': data.get('variables', {}),
                'operationName': data.get('operationName')
            }
        except (json.JSONDecodeError, TypeError):
            return None

    def inject_into_variables(self, variables: Dict, payload: str) -> List[Dict]:
        """
        Generate injected variable variations.

        Args:
            variables: Original GraphQL variables
            payload: Injection payload

        Returns:
            List of modified variable dictionaries
        """
        injected = []

        def inject_recursive(obj: Any, path: str = "") -> List[Tuple[str, Any]]:
            results = []
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, str):
                        # Inject into string values
                        modified = obj.copy()
                        modified[key] = payload
                        results.append((current_path, modified))
                        # Also try appending
                        modified2 = obj.copy()
                        modified2[key] = value + payload
                        results.append((f"{current_path}_append", modified2))
                    elif isinstance(value, (dict, list)):
                        for sub_path, sub_result in inject_recursive(value, current_path):
                            modified = obj.copy()
                            modified[key] = sub_result
                            results.append((sub_path, modified))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    if isinstance(item, str):
                        modified = obj.copy()
                        modified[i] = payload
                        results.append((current_path, modified))
                    elif isinstance(item, (dict, list)):
                        for sub_path, sub_result in inject_recursive(item, current_path):
                            modified = obj.copy()
                            modified[i] = sub_result
                            results.append((sub_path, modified))
            return results

        for path, modified_vars in inject_recursive(variables):
            injected.append({'path': path, 'variables': modified_vars})

        return injected

    def check_response_for_errors(self, response: str, patterns: List[str]) -> Optional[str]:
        """
        Check response for error patterns.

        Args:
            response: HTTP response body
            patterns: List of regex patterns to match

        Returns:
            Matched pattern or None
        """
        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return pattern
        return None

    def fuzz(self, request, params):
        """
        Execute GraphQL injection fuzzing.

        Args:
            request: The request object to fuzz
            params: Additional parameters

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        if not self.is_graphql_request(request):
            return vulnerabilities

        parsed = self.parse_graphql_request(request)
        if not parsed:
            return vulnerabilities

        variables = parsed.get('variables', {})
        original_query = parsed.get('query', '')

        # Test SQL injection in variables
        for payload in self.sqli_payloads:
            if variables:
                for injection in self.inject_into_variables(variables, payload):
                    modified_data = json.dumps({
                        'query': original_query,
                        'variables': injection['variables'],
                        'operationName': parsed.get('operationName')
                    })

                    try:
                        response = self.send_request(request, data=modified_data)
                        if response:
                            matched = self.check_response_for_errors(
                                response.body,
                                self.sql_error_patterns
                            )
                            if matched:
                                vulnerabilities.append({
                                    'type': VULNTYPE_SQLI,
                                    'description': f"SQL Injection detected in GraphQL variable '{injection['path']}' with payload: {payload}. Error pattern: {matched}"
                                })
                                break
                    except Exception:
                        pass

        # Test NoSQL injection in variables
        for payload in self.nosqli_payloads:
            if variables:
                for injection in self.inject_into_variables(variables, payload):
                    modified_data = json.dumps({
                        'query': original_query,
                        'variables': injection['variables'],
                        'operationName': parsed.get('operationName')
                    })

                    try:
                        response = self.send_request(request, data=modified_data)
                        if response:
                            matched = self.check_response_for_errors(
                                response.body,
                                self.nosql_error_patterns
                            )
                            if matched:
                                vulnerabilities.append({
                                    'type': VULNTYPE_NOSQLI,
                                    'description': f"NoSQL Injection detected in GraphQL variable '{injection['path']}' with payload: {payload}. Error pattern: {matched}"
                                })
                                break
                    except Exception:
                        pass

        # Test for introspection (information disclosure)
        introspection_query = """
        query {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
        introspection_data = json.dumps({'query': introspection_query})

        try:
            response = self.send_request(request, data=introspection_data)
            if response and '__schema' in response.body and 'types' in response.body:
                vulnerabilities.append({
                    'type': 'graphql_introspection',
                    'description': "GraphQL introspection is enabled. This exposes the entire API schema and can aid attackers in crafting targeted attacks."
                })
        except Exception:
            pass

        # Test for batching attacks (potential DoS)
        batch_query = [
            {'query': '{ __typename }'},
            {'query': '{ __typename }'},
            {'query': '{ __typename }'},
        ]
        batch_data = json.dumps(batch_query)

        try:
            response = self.send_request(request, data=batch_data)
            if response and isinstance(json.loads(response.body), list):
                vulnerabilities.append({
                    'type': 'graphql_batching',
                    'description': "GraphQL batching is enabled. This could be exploited for denial of service or to bypass rate limiting."
                })
        except Exception:
            pass

        return vulnerabilities
