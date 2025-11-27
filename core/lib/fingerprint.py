# -*- coding: utf-8 -*-

"""
HTCAP - Technology Fingerprinter
Identifies technologies, frameworks, and libraries used by web applications.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import json
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class TechCategory(Enum):
    """Technology categories."""
    FRONTEND_FRAMEWORK = "frontend_framework"
    BACKEND_FRAMEWORK = "backend_framework"
    CMS = "cms"
    ECOMMERCE = "ecommerce"
    CDN = "cdn"
    ANALYTICS = "analytics"
    SECURITY = "security"
    SERVER = "server"
    LANGUAGE = "language"
    DATABASE = "database"
    CACHE = "cache"
    JAVASCRIPT_LIBRARY = "javascript_library"
    CSS_FRAMEWORK = "css_framework"
    BUILD_TOOL = "build_tool"
    WAF = "waf"


@dataclass
class Technology:
    """Represents a detected technology."""
    name: str
    category: TechCategory
    version: Optional[str] = None
    confidence: int = 100  # 0-100
    evidence: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)


class TechFingerprinter:
    """
    Fingerprints web technologies from HTTP responses.

    Detects:
    - Frontend frameworks (React, Vue, Angular, etc.)
    - Backend frameworks (Express, Django, Rails, etc.)
    - CMS platforms (WordPress, Drupal, etc.)
    - JavaScript libraries
    - Server software
    - CDNs and WAFs
    """

    def __init__(self):
        self.detected: Set[str] = set()
        self._init_signatures()

    def _init_signatures(self):
        """Initialize technology signatures."""
        self.signatures = {
            # Frontend Frameworks
            'React': {
                'category': TechCategory.FRONTEND_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'react\.production\.min\.js',
                        r'react-dom',
                        r'data-reactroot',
                        r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
                        r'_reactRootContainer',
                    ],
                    'headers': [],
                    'scripts': [r'react', r'react-dom'],
                },
                'version_pattern': r'react[./-]v?(\d+\.\d+\.\d+)',
            },
            'Vue.js': {
                'category': TechCategory.FRONTEND_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'vue\.min\.js',
                        r'vue\.runtime',
                        r'data-v-[a-f0-9]+',
                        r'__vue__',
                        r'Vue\.config',
                    ],
                    'headers': [],
                    'scripts': [r'vue'],
                },
                'version_pattern': r'vue[./-]v?(\d+\.\d+\.\d+)',
            },
            'Angular': {
                'category': TechCategory.FRONTEND_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'ng-version="',
                        r'ng-app',
                        r'angular\.min\.js',
                        r'\[\[.*?\]\]',  # Angular interpolation
                        r'ng-controller',
                        r'_ng(host|content)',
                    ],
                    'headers': [],
                    'scripts': [r'angular', r'zone\.js'],
                },
                'version_pattern': r'ng-version="(\d+\.\d+\.\d+)"',
            },
            'Next.js': {
                'category': TechCategory.FRONTEND_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'_next/static',
                        r'__NEXT_DATA__',
                        r'next/dist',
                    ],
                    'headers': [r'x-powered-by:\s*Next\.js'],
                    'scripts': [],
                },
            },
            'Nuxt.js': {
                'category': TechCategory.FRONTEND_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'_nuxt/',
                        r'__NUXT__',
                        r'nuxt\.js',
                    ],
                    'headers': [],
                    'scripts': [],
                },
            },
            'jQuery': {
                'category': TechCategory.JAVASCRIPT_LIBRARY,
                'patterns': {
                    'body': [
                        r'jquery[.-](\d+\.\d+\.\d+)?\.min\.js',
                        r'jquery\.js',
                    ],
                    'headers': [],
                    'scripts': [r'jquery'],
                },
                'version_pattern': r'jquery[./-]v?(\d+\.\d+\.\d+)',
            },

            # Backend Frameworks
            'Express': {
                'category': TechCategory.BACKEND_FRAMEWORK,
                'patterns': {
                    'body': [],
                    'headers': [r'x-powered-by:\s*Express'],
                    'scripts': [],
                },
            },
            'Django': {
                'category': TechCategory.BACKEND_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'csrfmiddlewaretoken',
                        r'__admin_media_prefix__',
                    ],
                    'headers': [],
                    'cookies': [r'csrftoken', r'django'],
                },
            },
            'Ruby on Rails': {
                'category': TechCategory.BACKEND_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'csrf-token',
                        r'data-turbolinks',
                    ],
                    'headers': [r'x-powered-by:\s*Phusion Passenger'],
                    'cookies': [r'_rails_', r'_session_id'],
                },
            },
            'Laravel': {
                'category': TechCategory.BACKEND_FRAMEWORK,
                'patterns': {
                    'body': [],
                    'headers': [],
                    'cookies': [r'laravel_session', r'XSRF-TOKEN'],
                },
            },
            'ASP.NET': {
                'category': TechCategory.BACKEND_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'__VIEWSTATE',
                        r'__EVENTVALIDATION',
                        r'aspnetForm',
                    ],
                    'headers': [
                        r'x-powered-by:\s*ASP\.NET',
                        r'x-aspnet-version',
                    ],
                    'cookies': [r'ASP\.NET_SessionId', r'\.ASPXAUTH'],
                },
            },
            'Spring': {
                'category': TechCategory.BACKEND_FRAMEWORK,
                'patterns': {
                    'body': [],
                    'headers': [],
                    'cookies': [r'JSESSIONID'],
                },
            },
            'Flask': {
                'category': TechCategory.BACKEND_FRAMEWORK,
                'patterns': {
                    'body': [],
                    'headers': [],
                    'cookies': [r'session=ey'],  # Flask JWT-like session
                },
            },

            # CMS
            'WordPress': {
                'category': TechCategory.CMS,
                'patterns': {
                    'body': [
                        r'wp-content/',
                        r'wp-includes/',
                        r'wp-json',
                        r'/xmlrpc\.php',
                    ],
                    'headers': [r'x-powered-by:\s*W3 Total Cache'],
                    'scripts': [],
                },
                'version_pattern': r'WordPress\s*(\d+\.\d+\.?\d*)',
            },
            'Drupal': {
                'category': TechCategory.CMS,
                'patterns': {
                    'body': [
                        r'Drupal\.settings',
                        r'/sites/default/files',
                        r'drupal\.js',
                    ],
                    'headers': [r'x-drupal-cache', r'x-generator:\s*Drupal'],
                    'scripts': [],
                },
            },
            'Joomla': {
                'category': TechCategory.CMS,
                'patterns': {
                    'body': [
                        r'/media/jui/',
                        r'Joomla!',
                        r'/components/com_',
                    ],
                    'headers': [],
                    'scripts': [],
                },
            },

            # Servers
            'Nginx': {
                'category': TechCategory.SERVER,
                'patterns': {
                    'body': [],
                    'headers': [r'server:\s*nginx'],
                    'scripts': [],
                },
                'version_pattern': r'nginx/(\d+\.\d+\.?\d*)',
            },
            'Apache': {
                'category': TechCategory.SERVER,
                'patterns': {
                    'body': [],
                    'headers': [r'server:\s*Apache'],
                    'scripts': [],
                },
                'version_pattern': r'Apache/(\d+\.\d+\.?\d*)',
            },
            'IIS': {
                'category': TechCategory.SERVER,
                'patterns': {
                    'body': [],
                    'headers': [r'server:\s*Microsoft-IIS'],
                    'scripts': [],
                },
                'version_pattern': r'Microsoft-IIS/(\d+\.?\d*)',
            },

            # CDN/WAF
            'Cloudflare': {
                'category': TechCategory.CDN,
                'patterns': {
                    'body': [],
                    'headers': [
                        r'cf-ray',
                        r'cf-cache-status',
                        r'server:\s*cloudflare',
                    ],
                    'cookies': [r'__cf'],
                },
            },
            'Akamai': {
                'category': TechCategory.CDN,
                'patterns': {
                    'body': [],
                    'headers': [r'x-akamai', r'akamai-'],
                    'scripts': [],
                },
            },
            'AWS CloudFront': {
                'category': TechCategory.CDN,
                'patterns': {
                    'body': [],
                    'headers': [r'x-amz-cf-', r'via:.*cloudfront'],
                    'scripts': [],
                },
            },

            # CSS Frameworks
            'Bootstrap': {
                'category': TechCategory.CSS_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'bootstrap\.min\.css',
                        r'bootstrap\.css',
                        r'class="[^"]*\b(container|row|col-)',
                    ],
                    'headers': [],
                    'scripts': [r'bootstrap'],
                },
                'version_pattern': r'bootstrap[./-]v?(\d+\.\d+\.\d+)',
            },
            'Tailwind CSS': {
                'category': TechCategory.CSS_FRAMEWORK,
                'patterns': {
                    'body': [
                        r'tailwind',
                        r'class="[^"]*\b(flex|grid|p-\d|m-\d|text-)',
                    ],
                    'headers': [],
                    'scripts': [],
                },
            },

            # Analytics
            'Google Analytics': {
                'category': TechCategory.ANALYTICS,
                'patterns': {
                    'body': [
                        r'google-analytics\.com/analytics\.js',
                        r'googletagmanager\.com',
                        r'ga\s*\(\s*[\'"]create[\'"]',
                        r'gtag\s*\(',
                        r'UA-\d+-\d+',
                        r'G-[A-Z0-9]+',
                    ],
                    'headers': [],
                    'scripts': [],
                },
            },

            # Build Tools
            'Webpack': {
                'category': TechCategory.BUILD_TOOL,
                'patterns': {
                    'body': [
                        r'webpackJsonp',
                        r'__webpack_require__',
                        r'webpack',
                    ],
                    'headers': [],
                    'scripts': [],
                },
            },
            'Vite': {
                'category': TechCategory.BUILD_TOOL,
                'patterns': {
                    'body': [
                        r'/@vite/',
                        r'vite/client',
                    ],
                    'headers': [],
                    'scripts': [],
                },
            },
        }

    def fingerprint(self, response_body: str, response_headers: str = "",
                   cookies: str = "") -> List[Technology]:
        """
        Fingerprint technologies from HTTP response.

        Args:
            response_body: HTML/JS response body
            response_headers: HTTP response headers
            cookies: Cookie string

        Returns:
            List of detected technologies
        """
        detected_techs = []

        for tech_name, signature in self.signatures.items():
            confidence = 0
            evidence = []

            # Check body patterns
            for pattern in signature['patterns'].get('body', []):
                if re.search(pattern, response_body, re.IGNORECASE):
                    confidence += 30
                    evidence.append(f"Body pattern: {pattern}")

            # Check header patterns
            for pattern in signature['patterns'].get('headers', []):
                if re.search(pattern, response_headers, re.IGNORECASE):
                    confidence += 40
                    evidence.append(f"Header pattern: {pattern}")

            # Check cookie patterns
            for pattern in signature['patterns'].get('cookies', []):
                if re.search(pattern, cookies, re.IGNORECASE):
                    confidence += 35
                    evidence.append(f"Cookie pattern: {pattern}")

            # Check script references
            for pattern in signature['patterns'].get('scripts', []):
                if re.search(rf'<script[^>]*{pattern}', response_body, re.IGNORECASE):
                    confidence += 25
                    evidence.append(f"Script reference: {pattern}")

            if confidence > 0:
                # Try to extract version
                version = None
                if 'version_pattern' in signature:
                    match = re.search(signature['version_pattern'],
                                    response_body + response_headers, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        confidence += 10
                        evidence.append(f"Version detected: {version}")

                # Cap confidence at 100
                confidence = min(confidence, 100)

                tech = Technology(
                    name=tech_name,
                    category=signature['category'],
                    version=version,
                    confidence=confidence,
                    evidence=evidence
                )
                detected_techs.append(tech)
                self.detected.add(tech_name)

        return detected_techs

    def get_security_implications(self, technologies: List[Technology]) -> List[Dict[str, str]]:
        """Get security implications for detected technologies."""
        implications = []

        security_notes = {
            'WordPress': "Check for outdated plugins, xmlrpc.php exposure, user enumeration",
            'jQuery': "Old versions vulnerable to XSS (CVE-2020-11022, CVE-2020-11023)",
            'Angular': "Check for template injection, version-specific vulnerabilities",
            'ASP.NET': "Check ViewState security, padding oracle attacks",
            'Drupal': "Check Drupalgeddon vulnerabilities if version < 7.58 or < 8.5.1",
            'Ruby on Rails': "Check for mass assignment, session security",
            'Express': "Check for prototype pollution, dependency vulnerabilities",
        }

        for tech in technologies:
            if tech.name in security_notes:
                implications.append({
                    'technology': tech.name,
                    'version': tech.version or 'Unknown',
                    'note': security_notes[tech.name]
                })

        return implications
