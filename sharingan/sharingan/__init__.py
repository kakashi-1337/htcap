# -*- coding: utf-8 -*-
"""
SHARINGAN - Advanced Web Security Analysis Toolkit
==================================================

The Eye That Sees All Vulnerabilities.

For AUTHORIZED penetration testing and bug bounty hunting only.

Modules:
    - analyzers: DOM analysis (taint tracking, postMessage, WebSocket, clobbering)
    - handlers: WAF detection, stealth mode, proxy rotation
    - utils: Notifications, helpers

Usage:
    from sharingan import TaintTracker, PostMessageAnalyzer, WAFHandler
    from sharingan import WebSocketAnalyzer, DOMClobberingDetector
    from sharingan import StealthMode, ProxyRotator, NotificationManager
"""

__version__ = "1.0.0"
__author__ = "kakashi-1337"
__codename__ = "Mangekyou"

# Analyzers - DOM Security Analysis
from sharingan.analyzers.taint_tracking import (
    TaintTracker,
    TaintFlow,
    TaintSource,
    TaintSink,
    SourceType,
    SinkType,
    SinkSeverity,
    URLTaintAnalyzer,
)

from sharingan.analyzers.postmessage import (
    PostMessageAnalyzer,
    MessageHandler,
    MessageSender,
    PMVulnerability,
    PMVulnType,
    OriginCheckStrength,
)

from sharingan.analyzers.websocket import (
    WebSocketAnalyzer,
    WSMessage,
    WSEndpoint,
    WSVulnerability,
    WSVulnType,
    MessageDirection,
    MessageType,
)

from sharingan.analyzers.dom_clobbering import (
    DOMClobberingDetector,
    ClobberableTarget,
    ClobberVector,
    DOMClobberVuln,
    ClobberTarget,
    ClobberImpact,
)

# Handlers - WAF, Stealth, Proxy
from sharingan.handlers.waf import (
    WAFHandler,
    WAFType,
    WAFDetectionResult,
)

from sharingan.handlers.stealth import (
    StealthMode,
    StealthConfig,
    StealthLevel,
    RequestThrottler,
)

from sharingan.handlers.proxy import (
    ProxyRotator,
    Proxy,
    ProxyType,
    ProxyHealth,
)

# Utils - Notifications
from sharingan.utils.notifications import (
    NotificationManager,
    Notification,
    NotificationType,
    Severity,
    SlackNotifier,
    DiscordNotifier,
    TelegramNotifier,
    GenericWebhookNotifier,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__codename__",
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
    # WAF
    "WAFHandler",
    "WAFType",
    "WAFDetectionResult",
    # Stealth
    "StealthMode",
    "StealthConfig",
    "StealthLevel",
    "RequestThrottler",
    # Proxy
    "ProxyRotator",
    "Proxy",
    "ProxyType",
    "ProxyHealth",
    # Notifications
    "NotificationManager",
    "Notification",
    "NotificationType",
    "Severity",
    "SlackNotifier",
    "DiscordNotifier",
    "TelegramNotifier",
    "GenericWebhookNotifier",
]
