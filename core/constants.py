# -*- coding: utf-8 -*-

"""
HTCAP - Constants and Configuration
Author: filippo.cavallarin@wearesegment.com

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

from typing import Final

# Version Information
VERSION: Final[str] = "2.1.0"
VERSION_NAME: Final[str] = "Skills Edition"

# Thread Status
THSTAT_WAITING: Final[int] = 0
THSTAT_RUNNING: Final[int] = 1

# Crawl Scope
CRAWLSCOPE_DOMAIN: Final[str] = "domain"
CRAWLSCOPE_DIRECTORY: Final[str] = "directory"
CRAWLSCOPE_URL: Final[str] = "url"

# Crawl Mode
CRAWLMODE_PASSIVE: Final[str] = "passive"
CRAWLMODE_ACTIVE: Final[str] = "active"
CRAWLMODE_AGGRESSIVE: Final[str] = "aggressive"

# Request Types (Original)
REQTYPE_LINK: Final[str] = "link"
REQTYPE_XHR: Final[str] = "xhr"
REQTYPE_FETCH: Final[str] = "fetch"
REQTYPE_WS: Final[str] = "websocket"
REQTYPE_JSONP: Final[str] = "jsonp"
REQTYPE_FORM: Final[str] = "form"
REQTYPE_REDIRECT: Final[str] = "redirect"
REQTYPE_IMAGE: Final[str] = "image"
REQTYPE_UNKNOWN: Final[str] = "unknown"

# New Request Types for Modern SPAs
REQTYPE_GRAPHQL: Final[str] = "graphql"
REQTYPE_REST: Final[str] = "rest"
REQTYPE_GRPC_WEB: Final[str] = "grpc-web"
REQTYPE_SSE: Final[str] = "sse"  # Server-Sent Events
REQTYPE_BEACON: Final[str] = "beacon"  # Navigator.sendBeacon

# Error Types
ERROR_CONTENTTYPE: Final[str] = "content_type"
ERROR_TIMEOUT: Final[str] = "timeout"
ERROR_PROBE_TO: Final[str] = "probe_timeout"
ERROR_LOAD: Final[str] = "loaderror"
ERROR_PROBEKILLED: Final[str] = "probe_killed"
ERROR_PROBEFAILURE: Final[str] = "probe_failure"
ERROR_MAXREDIRECTS: Final[str] = "too_many_redirects"
ERROR_CRAWLDEPTH: Final[str] = "crawler_depth_limit_reached"
ERROR_LOGINSEQ: Final[str] = "login_sequence"
ERROR_NETWORK: Final[str] = "network_error"
ERROR_SSL: Final[str] = "ssl_error"
ERROR_AUTH: Final[str] = "authentication_error"

# Vulnerability Types - Core
VULNTYPE_SQLI: Final[str] = "sqli"
VULNTYPE_XSS: Final[str] = "xss"
VULNTYPE_CMDI: Final[str] = "command_injection"
VULNTYPE_LFI: Final[str] = "local_file_inclusion"
VULNTYPE_RFI: Final[str] = "remote_file_inclusion"
VULNTYPE_SSRF: Final[str] = "ssrf"
VULNTYPE_IDOR: Final[str] = "idor"
VULNTYPE_OPENREDIRECT: Final[str] = "open_redirect"
VULNTYPE_NOSQLI: Final[str] = "nosql_injection"
VULNTYPE_SSTI: Final[str] = "ssti"  # Server-Side Template Injection
VULNTYPE_XXE: Final[str] = "xxe"
VULNTYPE_CORS: Final[str] = "cors_misconfiguration"
VULNTYPE_JWT: Final[str] = "jwt_vulnerability"

# Vulnerability Types - Advanced (New in v2.1)
VULNTYPE_HTTP_SMUGGLING: Final[str] = "http_request_smuggling"
VULNTYPE_CACHE_POISONING: Final[str] = "cache_poisoning"
VULNTYPE_CACHE_DECEPTION: Final[str] = "cache_deception"
VULNTYPE_HOST_HEADER: Final[str] = "host_header_injection"
VULNTYPE_RACE_CONDITION: Final[str] = "race_condition"
VULNTYPE_PROTOTYPE_POLLUTION: Final[str] = "prototype_pollution"
VULNTYPE_DOM_XSS: Final[str] = "dom_xss"
VULNTYPE_CSWSH: Final[str] = "cross_site_websocket_hijacking"
VULNTYPE_GRAPHQL_INTROSPECTION: Final[str] = "graphql_introspection"
VULNTYPE_GRAPHQL_BATCHING: Final[str] = "graphql_batching"
VULNTYPE_CRLF: Final[str] = "crlf_injection"
VULNTYPE_CLICKJACKING: Final[str] = "clickjacking"
VULNTYPE_CSRF: Final[str] = "csrf"
VULNTYPE_INFO_DISCLOSURE: Final[str] = "information_disclosure"
VULNTYPE_BROKEN_AUTH: Final[str] = "broken_authentication"
VULNTYPE_MASS_ASSIGNMENT: Final[str] = "mass_assignment"

# HTTP Methods
METHOD_GET: Final[str] = "GET"
METHOD_POST: Final[str] = "POST"
METHOD_PUT: Final[str] = "PUT"
METHOD_DELETE: Final[str] = "DELETE"
METHOD_PATCH: Final[str] = "PATCH"
METHOD_OPTIONS: Final[str] = "OPTIONS"
METHOD_HEAD: Final[str] = "HEAD"

# Login Sequence Types
LOGSEQTYPE_STANDALONE: Final[str] = "standalone"
LOGSEQTYPE_SHARED: Final[str] = "shared"

# Content Types
CONTENT_TYPE_JSON: Final[str] = "application/json"
CONTENT_TYPE_XML: Final[str] = "application/xml"
CONTENT_TYPE_FORM: Final[str] = "application/x-www-form-urlencoded"
CONTENT_TYPE_MULTIPART: Final[str] = "multipart/form-data"
CONTENT_TYPE_GRAPHQL: Final[str] = "application/graphql"
CONTENT_TYPE_TEXT: Final[str] = "text/plain"
CONTENT_TYPE_HTML: Final[str] = "text/html"

# Authentication Types
AUTH_TYPE_BASIC: Final[str] = "basic"
AUTH_TYPE_BEARER: Final[str] = "bearer"
AUTH_TYPE_JWT: Final[str] = "jwt"
AUTH_TYPE_OAUTH2: Final[str] = "oauth2"
AUTH_TYPE_API_KEY: Final[str] = "api_key"
AUTH_TYPE_COOKIE: Final[str] = "cookie"

# Default Configuration
DEFAULT_TIMEOUT: Final[int] = 300
DEFAULT_MAX_DEPTH: Final[int] = 100
DEFAULT_MAX_POST_DEPTH: Final[int] = 10
DEFAULT_MAX_REDIRECTS: Final[int] = 10
DEFAULT_NUM_THREADS: Final[int] = 10
DEFAULT_USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# GraphQL specific
GRAPHQL_INTROSPECTION_QUERY: Final[str] = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""

# All supported request types (for filtering)
ALL_REQUEST_TYPES: Final[tuple] = (
    REQTYPE_LINK, REQTYPE_XHR, REQTYPE_FETCH, REQTYPE_WS, REQTYPE_JSONP,
    REQTYPE_FORM, REQTYPE_REDIRECT, REQTYPE_IMAGE, REQTYPE_GRAPHQL,
    REQTYPE_REST, REQTYPE_GRPC_WEB, REQTYPE_SSE, REQTYPE_BEACON, REQTYPE_UNKNOWN
)

# Request types that are typically API calls
API_REQUEST_TYPES: Final[tuple] = (
    REQTYPE_XHR, REQTYPE_FETCH, REQTYPE_GRAPHQL, REQTYPE_REST,
    REQTYPE_GRPC_WEB, REQTYPE_JSONP
)
