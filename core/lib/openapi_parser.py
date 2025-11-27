# -*- coding: utf-8 -*-

"""
HTCAP - OpenAPI/Swagger Parser
Parses OpenAPI specifications to extract endpoints for security testing.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import json
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin
from core.lib.request import Request
from core.constants import (
    REQTYPE_REST, METHOD_GET, METHOD_POST, METHOD_PUT,
    METHOD_DELETE, METHOD_PATCH
)


@dataclass
class APIEndpoint:
    """Represents an API endpoint."""
    path: str
    method: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: List[Dict] = field(default_factory=list)
    request_body: Optional[Dict] = None
    security: List[Dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    responses: Dict = field(default_factory=dict)


@dataclass
class APISchema:
    """Represents a parsed API schema."""
    title: str
    version: str
    base_url: str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_schemes: Dict = field(default_factory=dict)
    components: Dict = field(default_factory=dict)


class OpenAPIParser:
    """
    Parses OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications.

    Features:
    - Endpoint extraction
    - Parameter identification
    - Security scheme detection
    - Request generation for fuzzing
    """

    def __init__(self):
        self.schema: Optional[APISchema] = None

    def parse(self, spec: Dict, base_url: str = "") -> APISchema:
        """
        Parse an OpenAPI specification.

        Args:
            spec: OpenAPI specification as dictionary
            base_url: Base URL to use for endpoints

        Returns:
            Parsed APISchema
        """
        # Detect version
        if 'swagger' in spec:
            return self._parse_swagger_2(spec, base_url)
        elif 'openapi' in spec:
            return self._parse_openapi_3(spec, base_url)
        else:
            raise ValueError("Unknown API specification format")

    def _parse_swagger_2(self, spec: Dict, base_url: str) -> APISchema:
        """Parse Swagger 2.0 specification."""
        info = spec.get('info', {})

        # Determine base URL
        if not base_url:
            host = spec.get('host', 'localhost')
            base_path = spec.get('basePath', '/')
            schemes = spec.get('schemes', ['https'])
            base_url = f"{schemes[0]}://{host}{base_path}"

        schema = APISchema(
            title=info.get('title', 'Unknown API'),
            version=info.get('version', '1.0'),
            base_url=base_url.rstrip('/'),
            security_schemes=spec.get('securityDefinitions', {}),
            components=spec.get('definitions', {})
        )

        # Parse paths
        for path, methods in spec.get('paths', {}).items():
            for method, operation in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                    continue

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get('operationId'),
                    summary=operation.get('summary'),
                    description=operation.get('description'),
                    parameters=operation.get('parameters', []),
                    security=operation.get('security', spec.get('security', [])),
                    tags=operation.get('tags', []),
                    responses=operation.get('responses', {})
                )

                schema.endpoints.append(endpoint)

        self.schema = schema
        return schema

    def _parse_openapi_3(self, spec: Dict, base_url: str) -> APISchema:
        """Parse OpenAPI 3.x specification."""
        info = spec.get('info', {})

        # Determine base URL
        if not base_url:
            servers = spec.get('servers', [])
            if servers:
                base_url = servers[0].get('url', 'http://localhost')
            else:
                base_url = 'http://localhost'

        components = spec.get('components', {})

        schema = APISchema(
            title=info.get('title', 'Unknown API'),
            version=info.get('version', '1.0'),
            base_url=base_url.rstrip('/'),
            security_schemes=components.get('securitySchemes', {}),
            components=components
        )

        # Parse paths
        for path, methods in spec.get('paths', {}).items():
            for method, operation in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                    continue

                # Combine path-level and operation-level parameters
                params = methods.get('parameters', []) + operation.get('parameters', [])

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get('operationId'),
                    summary=operation.get('summary'),
                    description=operation.get('description'),
                    parameters=params,
                    request_body=operation.get('requestBody'),
                    security=operation.get('security', spec.get('security', [])),
                    tags=operation.get('tags', []),
                    responses=operation.get('responses', {})
                )

                schema.endpoints.append(endpoint)

        self.schema = schema
        return schema

    def _resolve_ref(self, ref: str, components: Dict) -> Dict:
        """Resolve a $ref reference."""
        if not ref.startswith('#/'):
            return {}

        parts = ref[2:].split('/')
        current = {'components': components}

        for part in parts:
            if part in current:
                current = current[part]
            else:
                return {}

        return current

    def _generate_sample_value(self, param_schema: Dict) -> Any:
        """Generate a sample value for a parameter schema."""
        param_type = param_schema.get('type', 'string')
        param_format = param_schema.get('format', '')
        example = param_schema.get('example')
        default = param_schema.get('default')
        enum = param_schema.get('enum')

        if example is not None:
            return example
        if default is not None:
            return default
        if enum:
            return enum[0]

        type_samples = {
            'string': {
                '': 'test',
                'email': 'test@example.com',
                'uri': 'https://example.com',
                'uuid': '550e8400-e29b-41d4-a716-446655440000',
                'date': '2024-01-01',
                'date-time': '2024-01-01T00:00:00Z',
                'password': 'password123',
                'byte': 'dGVzdA==',
            },
            'integer': 1,
            'number': 1.0,
            'boolean': True,
            'array': [],
            'object': {},
        }

        if param_type == 'string':
            return type_samples['string'].get(param_format, type_samples['string'][''])

        return type_samples.get(param_type, 'test')

    def generate_requests(self, auth_headers: Dict = None) -> List[Request]:
        """
        Generate Request objects for all endpoints.

        Args:
            auth_headers: Authentication headers to include

        Returns:
            List of Request objects for fuzzing
        """
        if not self.schema:
            return []

        requests = []

        for endpoint in self.schema.endpoints:
            # Build URL with path parameters
            url = self.schema.base_url + endpoint.path

            # Process path parameters
            path_params = {}
            query_params = {}
            header_params = {}
            body_data = None

            for param in endpoint.parameters:
                name = param.get('name')
                location = param.get('in')
                schema = param.get('schema', param)
                value = self._generate_sample_value(schema)

                if location == 'path':
                    path_params[name] = value
                elif location == 'query':
                    query_params[name] = value
                elif location == 'header':
                    header_params[name] = value

            # Replace path parameters
            for name, value in path_params.items():
                url = url.replace(f'{{{name}}}', str(value))

            # Add query parameters
            if query_params:
                query_string = '&'.join(f"{k}={v}" for k, v in query_params.items())
                url = f"{url}?{query_string}"

            # Process request body
            if endpoint.request_body:
                content = endpoint.request_body.get('content', {})

                # Prefer JSON
                if 'application/json' in content:
                    schema = content['application/json'].get('schema', {})
                    body_data = self._generate_body_from_schema(schema)
                    body_data = json.dumps(body_data)

            # Build extra headers
            extra_headers = header_params.copy()
            if auth_headers:
                extra_headers.update(auth_headers)

            # Create request
            req = Request(
                type=REQTYPE_REST,
                method=endpoint.method,
                url=url,
                data=body_data,
                extra_headers=extra_headers if extra_headers else None
            )

            requests.append(req)

        return requests

    def _generate_body_from_schema(self, schema: Dict) -> Any:
        """Generate sample request body from schema."""
        if '$ref' in schema:
            schema = self._resolve_ref(schema['$ref'], self.schema.components)

        schema_type = schema.get('type', 'object')

        if schema_type == 'object':
            result = {}
            properties = schema.get('properties', {})
            for prop_name, prop_schema in properties.items():
                result[prop_name] = self._generate_body_from_schema(prop_schema)
            return result

        elif schema_type == 'array':
            items_schema = schema.get('items', {})
            return [self._generate_body_from_schema(items_schema)]

        else:
            return self._generate_sample_value(schema)

    def get_security_info(self) -> Dict[str, Any]:
        """Get security-related information from the API spec."""
        if not self.schema:
            return {}

        info = {
            'security_schemes': self.schema.security_schemes,
            'auth_required_endpoints': [],
            'unauth_endpoints': [],
            'sensitive_endpoints': [],
        }

        sensitive_patterns = [
            r'/admin', r'/user', r'/account', r'/password',
            r'/auth', r'/login', r'/token', r'/secret',
            r'/payment', r'/billing', r'/order',
        ]

        for endpoint in self.schema.endpoints:
            endpoint_info = f"{endpoint.method} {endpoint.path}"

            if endpoint.security:
                info['auth_required_endpoints'].append(endpoint_info)
            else:
                info['unauth_endpoints'].append(endpoint_info)

            for pattern in sensitive_patterns:
                if re.search(pattern, endpoint.path, re.IGNORECASE):
                    info['sensitive_endpoints'].append(endpoint_info)
                    break

        return info

    @staticmethod
    def discover_spec_urls(base_url: str) -> List[str]:
        """Generate common OpenAPI spec URLs to try."""
        common_paths = [
            '/swagger.json',
            '/swagger/v1/swagger.json',
            '/api/swagger.json',
            '/api-docs',
            '/api-docs.json',
            '/v1/api-docs',
            '/v2/api-docs',
            '/v3/api-docs',
            '/openapi.json',
            '/openapi.yaml',
            '/api/openapi.json',
            '/docs/openapi.json',
            '/.well-known/openapi.json',
            '/swagger-ui.html',
            '/swagger-resources',
            '/api/swagger-resources',
        ]

        return [urljoin(base_url, path) for path in common_paths]
