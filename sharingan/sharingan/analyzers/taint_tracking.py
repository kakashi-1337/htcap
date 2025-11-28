# -*- coding: utf-8 -*-

"""
HTCAP Extensions - DOM Taint Tracking
Track data flow from sources to sinks for DOM XSS detection.

Inspired by DOM Invader and similar tools.

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
from datetime import datetime


class SourceType(Enum):
    """Types of taint sources (user-controlled input)."""
    URL = "url"
    URL_HASH = "url_hash"
    URL_SEARCH = "url_search"
    URL_PATHNAME = "url_pathname"
    DOCUMENT_REFERRER = "document_referrer"
    DOCUMENT_COOKIE = "document_cookie"
    WINDOW_NAME = "window_name"
    LOCAL_STORAGE = "local_storage"
    SESSION_STORAGE = "session_storage"
    POST_MESSAGE = "post_message"
    WEBSOCKET = "websocket"
    FORM_INPUT = "form_input"
    INDEXED_DB = "indexed_db"


class SinkType(Enum):
    """Types of dangerous sinks."""
    # JavaScript execution
    EVAL = "eval"
    FUNCTION = "Function"
    SET_TIMEOUT = "setTimeout"
    SET_INTERVAL = "setInterval"

    # HTML injection
    INNER_HTML = "innerHTML"
    OUTER_HTML = "outerHTML"
    INSERT_ADJACENT_HTML = "insertAdjacentHTML"
    DOCUMENT_WRITE = "document.write"
    DOCUMENT_WRITELN = "document.writeln"

    # DOM manipulation
    DOM_PARSER = "DOMParser"
    CREATE_CONTEXTUAL_FRAGMENT = "createContextualFragment"

    # URL navigation
    LOCATION_HREF = "location.href"
    LOCATION_ASSIGN = "location.assign"
    LOCATION_REPLACE = "location.replace"
    WINDOW_OPEN = "window.open"

    # Script injection
    SCRIPT_SRC = "script.src"
    SCRIPT_TEXT = "script.text"

    # Event handlers
    ON_EVENT = "on*"

    # jQuery specific
    JQUERY_HTML = "$.html()"
    JQUERY_APPEND = "$.append()"
    JQUERY_PREPEND = "$.prepend()"
    JQUERY_AFTER = "$.after()"
    JQUERY_BEFORE = "$.before()"

    # Angular specific
    NG_BIND_HTML = "ng-bind-html"
    BYPASS_SECURITY = "bypassSecurityTrust*"

    # React specific
    DANGEROUSLY_SET_INNER_HTML = "dangerouslySetInnerHTML"


class SinkSeverity(Enum):
    """Severity of sink exploitation."""
    CRITICAL = "critical"  # Direct JS execution
    HIGH = "high"          # HTML injection
    MEDIUM = "medium"      # URL manipulation
    LOW = "low"            # Minor data leakage


@dataclass
class TaintSource:
    """Represents a source of tainted data."""
    type: SourceType
    value: str
    location: str  # Where in code
    context: str   # Surrounding code
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class TaintSink:
    """Represents a dangerous sink."""
    type: SinkType
    location: str
    context: str
    severity: SinkSeverity
    framework: Optional[str] = None


@dataclass
class TaintFlow:
    """Represents data flow from source to sink."""
    source: TaintSource
    sink: TaintSink
    transformations: List[str] = field(default_factory=list)
    exploitable: bool = False
    payload_suggestion: Optional[str] = None
    confidence: float = 0.0


class TaintTracker:
    """
    Track tainted data flow through JavaScript code.

    Analyzes JavaScript to find sources and sinks, then
    attempts to determine if data flows between them.
    """

    # Source patterns for detection
    SOURCE_PATTERNS = {
        SourceType.URL: [
            r'location\.href',
            r'location\.search',
            r'location\.hash',
            r'location\.pathname',
            r'document\.URL',
            r'document\.documentURI',
            r'window\.location',
        ],
        SourceType.URL_HASH: [
            r'location\.hash',
            r'window\.location\.hash',
        ],
        SourceType.URL_SEARCH: [
            r'location\.search',
            r'window\.location\.search',
            r'URLSearchParams',
            r'new\s+URL\([^)]*\)\.searchParams',
        ],
        SourceType.DOCUMENT_REFERRER: [
            r'document\.referrer',
        ],
        SourceType.DOCUMENT_COOKIE: [
            r'document\.cookie',
        ],
        SourceType.WINDOW_NAME: [
            r'window\.name',
        ],
        SourceType.LOCAL_STORAGE: [
            r'localStorage\.getItem',
            r'localStorage\[',
        ],
        SourceType.SESSION_STORAGE: [
            r'sessionStorage\.getItem',
            r'sessionStorage\[',
        ],
        SourceType.POST_MESSAGE: [
            r'\.data',  # In message event handlers
            r'event\.data',
            r'e\.data',
        ],
    }

    # Sink patterns for detection
    SINK_PATTERNS = {
        SinkType.EVAL: (r'\beval\s*\(', SinkSeverity.CRITICAL),
        SinkType.FUNCTION: (r'new\s+Function\s*\(', SinkSeverity.CRITICAL),
        SinkType.SET_TIMEOUT: (r'setTimeout\s*\(\s*["\']?[^,\)]*["\']?\s*,', SinkSeverity.CRITICAL),
        SinkType.SET_INTERVAL: (r'setInterval\s*\(\s*["\']?[^,\)]*["\']?\s*,', SinkSeverity.CRITICAL),
        SinkType.INNER_HTML: (r'\.innerHTML\s*=', SinkSeverity.HIGH),
        SinkType.OUTER_HTML: (r'\.outerHTML\s*=', SinkSeverity.HIGH),
        SinkType.INSERT_ADJACENT_HTML: (r'\.insertAdjacentHTML\s*\(', SinkSeverity.HIGH),
        SinkType.DOCUMENT_WRITE: (r'document\.write\s*\(', SinkSeverity.HIGH),
        SinkType.DOCUMENT_WRITELN: (r'document\.writeln\s*\(', SinkSeverity.HIGH),
        SinkType.LOCATION_HREF: (r'location\.href\s*=', SinkSeverity.MEDIUM),
        SinkType.LOCATION_ASSIGN: (r'location\.assign\s*\(', SinkSeverity.MEDIUM),
        SinkType.LOCATION_REPLACE: (r'location\.replace\s*\(', SinkSeverity.MEDIUM),
        SinkType.WINDOW_OPEN: (r'window\.open\s*\(', SinkSeverity.MEDIUM),
        SinkType.SCRIPT_SRC: (r'\.src\s*=.*script', SinkSeverity.CRITICAL),
        SinkType.JQUERY_HTML: (r'\$\([^)]*\)\.html\s*\(', SinkSeverity.HIGH),
        SinkType.JQUERY_APPEND: (r'\$\([^)]*\)\.append\s*\(', SinkSeverity.HIGH),
        SinkType.DANGEROUSLY_SET_INNER_HTML: (r'dangerouslySetInnerHTML', SinkSeverity.HIGH),
    }

    # Common sanitization functions
    SANITIZERS = [
        'encodeURIComponent',
        'encodeURI',
        'escape',
        'DOMPurify.sanitize',
        'sanitize',
        'htmlEncode',
        'escapeHtml',
        'xssFilter',
        'strip_tags',
    ]

    def __init__(self):
        self.sources: List[TaintSource] = []
        self.sinks: List[TaintSink] = []
        self.flows: List[TaintFlow] = []
        self.js_code: str = ""

    def analyze(self, js_code: str) -> List[TaintFlow]:
        """
        Analyze JavaScript code for taint flows.

        Args:
            js_code: JavaScript source code

        Returns:
            List of detected taint flows
        """
        self.js_code = js_code
        self.sources = []
        self.sinks = []
        self.flows = []

        # Find all sources
        self._find_sources(js_code)

        # Find all sinks
        self._find_sinks(js_code)

        # Analyze flows
        self._analyze_flows(js_code)

        return self.flows

    def _find_sources(self, code: str):
        """Find all taint sources in code."""
        for source_type, patterns in self.SOURCE_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    # Get context around match
                    start = max(0, match.start() - 50)
                    end = min(len(code), match.end() + 50)
                    context = code[start:end]

                    source = TaintSource(
                        type=source_type,
                        value=match.group(),
                        location=f"offset:{match.start()}",
                        context=context.strip()
                    )
                    self.sources.append(source)

    def _find_sinks(self, code: str):
        """Find all dangerous sinks in code."""
        for sink_type, (pattern, severity) in self.SINK_PATTERNS.items():
            for match in re.finditer(pattern, code, re.IGNORECASE):
                start = max(0, match.start() - 50)
                end = min(len(code), match.end() + 50)
                context = code[start:end]

                # Detect framework
                framework = self._detect_framework(code)

                sink = TaintSink(
                    type=sink_type,
                    location=f"offset:{match.start()}",
                    context=context.strip(),
                    severity=severity,
                    framework=framework
                )
                self.sinks.append(sink)

    def _analyze_flows(self, code: str):
        """Analyze potential flows from sources to sinks."""
        for source in self.sources:
            for sink in self.sinks:
                # Check if source could flow to sink
                flow = self._check_flow(source, sink, code)
                if flow:
                    self.flows.append(flow)

    def _check_flow(self, source: TaintSource, sink: TaintSink,
                    code: str) -> Optional[TaintFlow]:
        """
        Check if data flows from source to sink.

        This is a simplified heuristic-based analysis.
        """
        # Get source and sink positions
        source_pos = int(source.location.split(':')[1])
        sink_pos = int(sink.location.split(':')[1])

        # Source should come before sink (usually)
        if source_pos > sink_pos:
            return None

        # Get code between source and sink
        between = code[source_pos:sink_pos]

        # Check for variable assignments that might connect them
        # This is a simplified heuristic
        var_pattern = r'(?:var|let|const)?\s*(\w+)\s*='
        vars_assigned = set(re.findall(var_pattern, between))

        # Check if sink references any assigned variable
        sink_context = sink.context.lower()

        potential_flow = False
        for var in vars_assigned:
            if var.lower() in sink_context:
                potential_flow = True
                break

        # Also check for direct assignment to sink
        source_value = source.value.split('.')[-1]
        if source_value.lower() in sink_context:
            potential_flow = True

        if not potential_flow:
            return None

        # Check for sanitization
        transformations = []
        sanitized = False

        for sanitizer in self.SANITIZERS:
            if sanitizer.lower() in between.lower():
                transformations.append(f"Sanitized by: {sanitizer}")
                sanitized = True

        # Calculate exploitability
        exploitable = not sanitized
        confidence = 0.7 if potential_flow else 0.3
        if sanitized:
            confidence *= 0.3

        # Generate payload suggestion
        payload = self._suggest_payload(source, sink)

        return TaintFlow(
            source=source,
            sink=sink,
            transformations=transformations,
            exploitable=exploitable,
            payload_suggestion=payload,
            confidence=confidence
        )

    def _detect_framework(self, code: str) -> Optional[str]:
        """Detect JavaScript framework used."""
        frameworks = {
            'React': ['React', 'ReactDOM', 'useState', 'useEffect'],
            'Angular': ['ng-', 'angular', '@Component', 'ngOnInit'],
            'Vue': ['Vue', 'v-bind', 'v-model', 'createApp'],
            'jQuery': ['$(' , 'jQuery'],
            'Backbone': ['Backbone'],
            'Ember': ['Ember'],
        }

        for framework, indicators in frameworks.items():
            for indicator in indicators:
                if indicator in code:
                    return framework

        return None

    def _suggest_payload(self, source: TaintSource, sink: TaintSink) -> str:
        """Suggest exploitation payload based on source/sink combo."""
        payloads = {
            SinkSeverity.CRITICAL: {
                SinkType.EVAL: "'-alert(1)-'",
                SinkType.FUNCTION: "alert(1)//",
                SinkType.SET_TIMEOUT: "alert(1)",
            },
            SinkSeverity.HIGH: {
                SinkType.INNER_HTML: "<img src=x onerror=alert(1)>",
                SinkType.DOCUMENT_WRITE: "<script>alert(1)</script>",
                SinkType.JQUERY_HTML: "<img src=x onerror=alert(1)>",
            },
            SinkSeverity.MEDIUM: {
                SinkType.LOCATION_HREF: "javascript:alert(1)",
                SinkType.WINDOW_OPEN: "javascript:alert(1)",
            }
        }

        severity_payloads = payloads.get(sink.severity, {})
        return severity_payloads.get(sink.type, "<img src=x onerror=alert(1)>")

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        critical_flows = [f for f in self.flows
                        if f.sink.severity == SinkSeverity.CRITICAL and f.exploitable]
        high_flows = [f for f in self.flows
                     if f.sink.severity == SinkSeverity.HIGH and f.exploitable]

        return {
            "total_sources": len(self.sources),
            "total_sinks": len(self.sinks),
            "total_flows": len(self.flows),
            "exploitable_flows": len([f for f in self.flows if f.exploitable]),
            "critical_flows": len(critical_flows),
            "high_flows": len(high_flows),
            "source_types": list(set(s.type.value for s in self.sources)),
            "sink_types": list(set(s.type.value for s in self.sinks)),
        }

    def to_json(self) -> str:
        """Export analysis results to JSON."""
        return json.dumps({
            "sources": [
                {
                    "type": s.type.value,
                    "value": s.value,
                    "location": s.location,
                    "context": s.context
                }
                for s in self.sources
            ],
            "sinks": [
                {
                    "type": s.type.value,
                    "location": s.location,
                    "context": s.context,
                    "severity": s.severity.value,
                    "framework": s.framework
                }
                for s in self.sinks
            ],
            "flows": [
                {
                    "source_type": f.source.type.value,
                    "sink_type": f.sink.type.value,
                    "sink_severity": f.sink.severity.value,
                    "exploitable": f.exploitable,
                    "confidence": f.confidence,
                    "payload": f.payload_suggestion,
                    "transformations": f.transformations
                }
                for f in self.flows
            ],
            "summary": self.get_summary()
        }, indent=2)


class URLTaintAnalyzer:
    """Analyze URL parameters for potential DOM XSS."""

    def __init__(self):
        self.tracker = TaintTracker()

    def analyze_url_reflection(self, url: str, page_source: str) -> List[Dict]:
        """
        Check if URL parameters are reflected in dangerous contexts.

        Args:
            url: The page URL with parameters
            page_source: HTML/JS source of the page

        Returns:
            List of reflection findings
        """
        from urllib.parse import urlparse, parse_qs

        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Also check hash
        if parsed.fragment:
            params['#'] = [parsed.fragment]

        for param, values in params.items():
            for value in values:
                if len(value) < 3:
                    continue

                # Check for reflection in page
                if value in page_source:
                    # Determine context
                    context = self._get_reflection_context(value, page_source)

                    findings.append({
                        "parameter": param,
                        "value": value,
                        "reflected": True,
                        "context": context,
                        "exploitable": context in ['script', 'event_handler', 'href'],
                        "payload_suggestion": self._get_context_payload(context)
                    })

        return findings

    def _get_reflection_context(self, value: str, source: str) -> str:
        """Determine the context where value is reflected."""
        idx = source.find(value)
        if idx == -1:
            return "none"

        # Get surrounding context
        before = source[max(0, idx-100):idx]
        after = source[idx:min(len(source), idx+100)]

        # Check for script context
        if '<script' in before.lower() and '</script>' not in before.lower():
            return "script"

        # Check for event handler
        if re.search(r'on\w+\s*=\s*["\']?[^"\']*$', before, re.IGNORECASE):
            return "event_handler"

        # Check for href/src
        if re.search(r'(?:href|src|action)\s*=\s*["\']?[^"\']*$', before, re.IGNORECASE):
            return "href"

        # Check for HTML attribute
        if re.search(r'<\w+[^>]*\w+\s*=\s*["\']?[^"\']*$', before):
            return "attribute"

        # Check for HTML tag
        if '<' in before and '>' not in before[-20:]:
            return "tag"

        return "text"

    def _get_context_payload(self, context: str) -> str:
        """Get appropriate payload for context."""
        payloads = {
            "script": "'-alert(1)-'",
            "event_handler": "alert(1)",
            "href": "javascript:alert(1)",
            "attribute": "\" onmouseover=\"alert(1)",
            "tag": "><img src=x onerror=alert(1)>",
            "text": "<img src=x onerror=alert(1)>",
        }
        return payloads.get(context, "<img src=x onerror=alert(1)>")
