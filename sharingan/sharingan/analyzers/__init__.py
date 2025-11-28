# -*- coding: utf-8 -*-
"""SHARINGAN Analyzers - DOM Security Analysis modules."""

from .taint_tracking import (
    TaintTracker,
    TaintFlow,
    TaintSource,
    TaintSink,
    SourceType,
    SinkType,
    SinkSeverity,
    URLTaintAnalyzer,
)

from .postmessage import (
    PostMessageAnalyzer,
    MessageHandler,
    MessageSender,
    PMVulnerability,
    PMVulnType,
    OriginCheckStrength,
)

from .websocket import (
    WebSocketAnalyzer,
    WSMessage,
    WSEndpoint,
    WSVulnerability,
    WSVulnType,
    MessageDirection,
    MessageType,
)

from .dom_clobbering import (
    DOMClobberingDetector,
    ClobberableTarget,
    ClobberVector,
    DOMClobberVuln,
    ClobberTarget,
    ClobberImpact,
)

__all__ = [
    # Taint Tracking
    "TaintTracker",
    "TaintFlow",
    "TaintSource",
    "TaintSink",
    "SourceType",
    "SinkType",
    "SinkSeverity",
    "URLTaintAnalyzer",
    # postMessage
    "PostMessageAnalyzer",
    "MessageHandler",
    "MessageSender",
    "PMVulnerability",
    "PMVulnType",
    "OriginCheckStrength",
    # WebSocket
    "WebSocketAnalyzer",
    "WSMessage",
    "WSEndpoint",
    "WSVulnerability",
    "WSVulnType",
    "MessageDirection",
    "MessageType",
    # DOM Clobbering
    "DOMClobberingDetector",
    "ClobberableTarget",
    "ClobberVector",
    "DOMClobberVuln",
    "ClobberTarget",
    "ClobberImpact",
]
