# -*- coding: utf-8 -*-

"""
HTCAP Extensions - DOM Clobbering Detector
Detect DOM clobbering vulnerabilities in HTML/JavaScript.

DOM clobbering is a technique where HTML elements can overwrite
JavaScript variables and properties via named elements.

For AUTHORIZED penetration testing only.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import re
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ClobberTarget(Enum):
    """Types of clobbering targets."""
    WINDOW_PROPERTY = "window_property"
    DOCUMENT_PROPERTY = "document_property"
    FORM_PROPERTY = "form_property"
    GLOBAL_VARIABLE = "global_variable"


class ClobberImpact(Enum):
    """Impact of successful clobbering."""
    CODE_EXECUTION = "code_execution"
    SECURITY_BYPASS = "security_bypass"
    DATA_EXFILTRATION = "data_exfiltration"
    DOM_MANIPULATION = "dom_manipulation"
    DENIAL_OF_SERVICE = "denial_of_service"


@dataclass
class ClobberableTarget:
    """Represents a property that can be clobbered."""
    name: str
    target_type: ClobberTarget
    location: str
    code_context: str
    sink_type: Optional[str] = None
    exploitable: bool = False
    impact: Optional[ClobberImpact] = None


@dataclass
class ClobberVector:
    """Represents a DOM clobbering attack vector."""
    target_name: str
    html_payload: str
    description: str
    impact: ClobberImpact
    bypasses: List[str] = field(default_factory=list)


@dataclass
class DOMClobberVuln:
    """Represents a DOM clobbering vulnerability."""
    target: ClobberableTarget
    vectors: List[ClobberVector]
    severity: str
    description: str
    recommendations: List[str] = field(default_factory=list)


class DOMClobberingDetector:
    """
    Detect DOM clobbering vulnerabilities.

    DOM clobbering exploits the fact that:
    1. Named elements (id, name) create window properties
    2. Forms' named elements become form properties
    3. document.getElementById can be bypassed
    4. Certain properties can be overwritten with element references
    """

    # Properties commonly accessed that could be clobbered
    CLOBBERABLE_PROPERTIES = {
        # Window/global properties
        'window': [
            'location', 'name', 'status', 'defaultStatus',
            'origin', 'opener', 'parent', 'top', 'frames',
            'length', 'closed', 'document', 'history',
            'navigator', 'screen', 'localStorage', 'sessionStorage',
        ],
        # Document properties
        'document': [
            'body', 'head', 'forms', 'images', 'links',
            'scripts', 'anchors', 'embeds', 'plugins',
            'domain', 'referrer', 'cookie', 'title',
            'URL', 'documentURI', 'baseURI',
        ],
    }

    # Dangerous sinks that use clobbered values
    DANGEROUS_SINKS = {
        'eval': ClobberImpact.CODE_EXECUTION,
        'Function': ClobberImpact.CODE_EXECUTION,
        'setTimeout': ClobberImpact.CODE_EXECUTION,
        'setInterval': ClobberImpact.CODE_EXECUTION,
        'innerHTML': ClobberImpact.CODE_EXECUTION,
        'outerHTML': ClobberImpact.CODE_EXECUTION,
        'document.write': ClobberImpact.CODE_EXECUTION,
        'location': ClobberImpact.SECURITY_BYPASS,
        'location.href': ClobberImpact.SECURITY_BYPASS,
        'location.assign': ClobberImpact.SECURITY_BYPASS,
        'fetch': ClobberImpact.DATA_EXFILTRATION,
        'XMLHttpRequest': ClobberImpact.DATA_EXFILTRATION,
        'src': ClobberImpact.CODE_EXECUTION,
        'href': ClobberImpact.SECURITY_BYPASS,
        'action': ClobberImpact.DATA_EXFILTRATION,
    }

    # HTML elements that can clobber
    CLOBBERING_ELEMENTS = {
        'id': ['div', 'span', 'a', 'img', 'form', 'input', 'iframe',
               'object', 'embed', 'param', 'meta', 'base', 'area'],
        'name': ['a', 'applet', 'embed', 'form', 'frame', 'frameset',
                'iframe', 'img', 'object', 'map', 'meta', 'param'],
    }

    def __init__(self):
        self.targets: List[ClobberableTarget] = []
        self.vulnerabilities: List[DOMClobberVuln] = []

    def analyze(self, html: str, js_code: str = "") -> List[DOMClobberVuln]:
        """
        Analyze HTML and JavaScript for DOM clobbering vulnerabilities.

        Args:
            html: HTML source code
            js_code: JavaScript source code

        Returns:
            List of detected vulnerabilities
        """
        self.targets = []
        self.vulnerabilities = []

        # Find potential clobbering targets in JS
        self._find_clobberable_targets(js_code)

        # Check if any targets are already clobbered in HTML
        self._check_existing_clobbering(html)

        # Generate attack vectors for vulnerable targets
        self._generate_attack_vectors()

        return self.vulnerabilities

    def _find_clobberable_targets(self, js_code: str):
        """Find JavaScript code that accesses potentially clobberable properties."""
        # Pattern for accessing window/global properties without typeof check
        window_access_patterns = [
            # Direct property access
            r'\bwindow\.(\w+)',
            r'\bself\.(\w+)',
            # Global variable usage
            r'\btypeof\s+(\w+)\s*[!=]==?\s*["\']undefined["\']',
            # Truthiness check that could be bypassed
            r'if\s*\(\s*(\w+)\s*\)',
            r'if\s*\(\s*!(\w+)\s*\)',
            # Assignment from global
            r'(?:var|let|const)\s+\w+\s*=\s*(\w+)\s*(?:\|\||&&|\?|;)',
        ]

        for pattern in window_access_patterns:
            for match in re.finditer(pattern, js_code, re.MULTILINE):
                prop_name = match.group(1)

                # Skip JavaScript keywords
                if prop_name in ['undefined', 'null', 'true', 'false', 'this',
                                'function', 'return', 'if', 'else', 'for']:
                    continue

                # Get context
                start = max(0, match.start() - 100)
                end = min(len(js_code), match.end() + 100)
                context = js_code[start:end]

                # Determine target type
                if 'window.' in match.group(0) or 'self.' in match.group(0):
                    target_type = ClobberTarget.WINDOW_PROPERTY
                else:
                    target_type = ClobberTarget.GLOBAL_VARIABLE

                # Check if it flows to a dangerous sink
                sink_type, impact = self._check_sink_flow(prop_name, js_code, match.end())

                target = ClobberableTarget(
                    name=prop_name,
                    target_type=target_type,
                    location=f"offset:{match.start()}",
                    code_context=context.strip(),
                    sink_type=sink_type,
                    exploitable=(sink_type is not None),
                    impact=impact
                )
                self.targets.append(target)

        # Look for document property access
        doc_patterns = [
            r'document\.(\w+)',
            r'document\[["\']([\w]+)["\']\]',
        ]

        for pattern in doc_patterns:
            for match in re.finditer(pattern, js_code):
                prop_name = match.group(1)

                if prop_name in self.CLOBBERABLE_PROPERTIES['document']:
                    start = max(0, match.start() - 100)
                    end = min(len(js_code), match.end() + 100)
                    context = js_code[start:end]

                    sink_type, impact = self._check_sink_flow(prop_name, js_code, match.end())

                    target = ClobberableTarget(
                        name=prop_name,
                        target_type=ClobberTarget.DOCUMENT_PROPERTY,
                        location=f"offset:{match.start()}",
                        code_context=context.strip(),
                        sink_type=sink_type,
                        exploitable=(sink_type is not None),
                        impact=impact
                    )
                    self.targets.append(target)

    def _check_sink_flow(self, prop_name: str, js_code: str,
                         start_pos: int) -> Tuple[Optional[str], Optional[ClobberImpact]]:
        """Check if property flows to a dangerous sink."""
        # Look at code after the property access
        search_window = js_code[start_pos:start_pos + 500]

        for sink, impact in self.DANGEROUS_SINKS.items():
            # Check if the sink is used with this property
            sink_patterns = [
                f'{sink}\\s*\\(.*{prop_name}',
                f'{prop_name}.*{sink}',
                f'\\.{sink}\\s*=.*{prop_name}',
            ]

            for pattern in sink_patterns:
                if re.search(pattern, search_window, re.IGNORECASE):
                    return sink, impact

        return None, None

    def _check_existing_clobbering(self, html: str):
        """Check if any elements in HTML already clobber targets."""
        # Find all elements with id or name attributes
        element_pattern = r'<(\w+)[^>]*(?:id|name)\s*=\s*["\']([^"\']+)["\'][^>]*>'

        for match in re.finditer(element_pattern, html, re.IGNORECASE):
            tag = match.group(1).lower()
            identifier = match.group(2)

            # Check if this clobbers any of our targets
            for target in self.targets:
                if target.name == identifier:
                    # This HTML already clobbers the target
                    # This might be intentional or a bug
                    pass

    def _generate_attack_vectors(self):
        """Generate attack vectors for clobberable targets."""
        for target in self.targets:
            if not target.exploitable:
                continue

            vectors = self._create_clobber_vectors(target)

            if vectors:
                severity = self._calculate_severity(target)

                vuln = DOMClobberVuln(
                    target=target,
                    vectors=vectors,
                    severity=severity,
                    description=self._get_vuln_description(target),
                    recommendations=self._get_recommendations(target)
                )
                self.vulnerabilities.append(vuln)

    def _create_clobber_vectors(self, target: ClobberableTarget) -> List[ClobberVector]:
        """Create clobbering payloads for a target."""
        vectors = []
        name = target.name

        # Basic id clobbering
        vectors.append(ClobberVector(
            target_name=name,
            html_payload=f'<img id="{name}">',
            description=f"Clobber window.{name} with img element",
            impact=target.impact or ClobberImpact.DOM_MANIPULATION
        ))

        # Anchor tag clobbering (allows href attribute access)
        if target.sink_type in ['location', 'href', 'src']:
            vectors.append(ClobberVector(
                target_name=name,
                html_payload=f'<a id="{name}" href="https://evil.com">',
                description=f"Clobber with anchor to control href/toString",
                impact=ClobberImpact.SECURITY_BYPASS,
                bypasses=["Bypasses URL validation if toString is used"]
            ))

        # Form clobbering (for nested property access)
        vectors.append(ClobberVector(
            target_name=name,
            html_payload=f'<form id="{name}"><input name="href" value="javascript:alert(1)"></form>',
            description=f"Clobber with form to control sub-properties",
            impact=ClobberImpact.CODE_EXECUTION,
            bypasses=["Can clobber x.href, x.action, etc."]
        ))

        # Double clobbering for nested access (x.y)
        # Using HTMLCollection
        vectors.append(ClobberVector(
            target_name=name,
            html_payload=f'<a id="{name}"></a><a id="{name}" name="inner" href="evil">',
            description="HTMLCollection clobbering for nested property access",
            impact=target.impact or ClobberImpact.DOM_MANIPULATION,
            bypasses=["Creates HTMLCollection for x, access x.inner via named item"]
        ))

        # Object/embed clobbering
        vectors.append(ClobberVector(
            target_name=name,
            html_payload=f'<object id="{name}"><param name="prop" value="clobbered"></object>',
            description="Object element clobbering with param children",
            impact=target.impact or ClobberImpact.DOM_MANIPULATION
        ))

        return vectors

    def _calculate_severity(self, target: ClobberableTarget) -> str:
        """Calculate vulnerability severity."""
        if target.impact == ClobberImpact.CODE_EXECUTION:
            return "critical"
        elif target.impact == ClobberImpact.DATA_EXFILTRATION:
            return "high"
        elif target.impact == ClobberImpact.SECURITY_BYPASS:
            return "high"
        elif target.impact == ClobberImpact.DOM_MANIPULATION:
            return "medium"
        return "low"

    def _get_vuln_description(self, target: ClobberableTarget) -> str:
        """Get vulnerability description."""
        desc = f"The JavaScript code accesses '{target.name}' which can be clobbered "
        desc += f"via HTML elements with matching id or name attributes. "

        if target.sink_type:
            desc += f"The value flows to a dangerous sink ({target.sink_type}), "
            desc += "allowing potential code execution or security bypass."

        return desc

    def _get_recommendations(self, target: ClobberableTarget) -> List[str]:
        """Get recommendations for fixing the vulnerability."""
        recs = [
            "Use typeof check: if (typeof x !== 'undefined' && x !== null)",
            "Verify object type: if (x instanceof HTMLElement) return;",
            "Use Object.hasOwn() or hasOwnProperty() checks",
            "Sanitize HTML input to prevent element injection",
            "Use strict Content Security Policy",
        ]

        if target.target_type == ClobberTarget.GLOBAL_VARIABLE:
            recs.insert(0, "Avoid relying on global variables; use proper scoping")

        if target.sink_type:
            recs.append(f"Validate data type before using in {target.sink_type}")

        return recs

    def check_clobbering_protection(self, js_code: str, var_name: str) -> Dict[str, bool]:
        """
        Check if a variable access has clobbering protection.

        Args:
            js_code: JavaScript code
            var_name: Variable name to check

        Returns:
            Dict with protection status
        """
        protections = {
            "typeof_check": False,
            "instanceof_check": False,
            "hasownproperty_check": False,
            "nullish_coalescing": False,
            "optional_chaining": False,
        }

        # Search around variable usage
        patterns = {
            "typeof_check": rf'typeof\s+{var_name}\s*[!=]==?\s*["\']undefined["\']',
            "instanceof_check": rf'{var_name}\s+instanceof\s+\w+',
            "hasownproperty_check": rf'(?:hasOwnProperty|Object\.hasOwn)\s*\([^)]*{var_name}',
            "nullish_coalescing": rf'{var_name}\s*\?\?',
            "optional_chaining": rf'{var_name}\s*\?\.',
        }

        for protection, pattern in patterns.items():
            if re.search(pattern, js_code):
                protections[protection] = True

        return protections

    def generate_test_html(self, target_name: str) -> str:
        """
        Generate test HTML to verify clobbering vulnerability.

        Args:
            target_name: Name of the property/variable to clobber

        Returns:
            HTML code for testing
        """
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>DOM Clobbering Test - {target_name}</title>
</head>
<body>
    <h1>DOM Clobbering Test</h1>

    <!-- Test 1: Basic ID clobbering -->
    <div id="{target_name}">Clobbering element</div>

    <!-- Test 2: Anchor clobbering with href -->
    <!--
    <a id="{target_name}" href="https://evil.com">Clobbered Link</a>
    -->

    <!-- Test 3: Form clobbering for nested properties -->
    <!--
    <form id="{target_name}">
        <input name="href" value="javascript:alert('clobbered')">
        <input name="src" value="https://evil.com/script.js">
    </form>
    -->

    <!-- Test 4: HTMLCollection clobbering -->
    <!--
    <a id="{target_name}"></a>
    <a id="{target_name}" name="inner" href="clobbered">Collection</a>
    -->

    <script>
    // Test if clobbering worked
    console.log('Testing DOM Clobbering for: {target_name}');
    console.log('window.{target_name}:', window.{target_name});
    console.log('Type:', typeof window.{target_name});

    if (window.{target_name} instanceof HTMLElement) {{
        console.log('SUCCESS: {target_name} is clobbered with:', window.{target_name}.tagName);

        // If it's an anchor, test href access
        if (window.{target_name}.href) {{
            console.log('href:', window.{target_name}.href);
        }}
    }} else {{
        console.log('PROTECTED: {target_name} is not clobbered or protected');
    }}
    </script>
</body>
</html>'''

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        impact_counts = {}
        for target in self.targets:
            if target.impact:
                impact_counts[target.impact.value] = impact_counts.get(target.impact.value, 0) + 1

        return {
            "clobberable_targets_found": len(self.targets),
            "exploitable_targets": len([t for t in self.targets if t.exploitable]),
            "vulnerabilities_found": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "impact_breakdown": impact_counts,
            "target_types": list(set(t.target_type.value for t in self.targets)),
        }

    def to_json(self) -> str:
        """Export analysis results to JSON."""
        return json.dumps({
            "targets": [
                {
                    "name": t.name,
                    "type": t.target_type.value,
                    "location": t.location,
                    "sink_type": t.sink_type,
                    "exploitable": t.exploitable,
                    "impact": t.impact.value if t.impact else None
                }
                for t in self.targets
            ],
            "vulnerabilities": [
                {
                    "target_name": v.target.name,
                    "severity": v.severity,
                    "description": v.description,
                    "vectors": [
                        {
                            "html_payload": vec.html_payload,
                            "description": vec.description,
                            "impact": vec.impact.value,
                            "bypasses": vec.bypasses
                        }
                        for vec in v.vectors
                    ],
                    "recommendations": v.recommendations
                }
                for v in self.vulnerabilities
            ],
            "summary": self.get_summary()
        }, indent=2)
