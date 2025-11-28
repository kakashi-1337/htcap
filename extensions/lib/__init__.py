# -*- coding: utf-8 -*-
"""
HTCAP Extensions - Library Modules
==================================

Advanced security analysis modules for HTCAP.
"""

# WAF Detection & Bypass
from .waf_handler import WAFHandler, WAFType, WAFDetectionResult

# Stealth Crawling
from .stealth import StealthMode, StealthConfig, StealthLevel, RequestThrottler

# Proxy Management
from .proxy_rotator import ProxyRotator, Proxy, ProxyType, ProxyHealth

# Notifications
from .notifications import (
    NotificationManager,
    Notification,
    NotificationType,
    Severity,
    SlackNotifier,
    DiscordNotifier,
    TelegramNotifier,
    GenericWebhookNotifier
)

# DOM Analysis - Taint Tracking
from .taint_tracking import (
    TaintTracker,
    TaintFlow,
    TaintSource,
    TaintSink,
    SourceType,
    SinkType,
    SinkSeverity,
    URLTaintAnalyzer
)

# WebSocket Security Analysis
from .websocket_analyzer import (
    WebSocketAnalyzer,
    WSMessage,
    WSEndpoint,
    WSVulnerability,
    WSVulnType,
    MessageDirection,
    MessageType
)

# postMessage Security Analysis
from .postmessage_analyzer import (
    PostMessageAnalyzer,
    MessageHandler,
    MessageSender,
    PMVulnerability,
    PMVulnType,
    OriginCheckStrength
)

# DOM Clobbering Detection
from .dom_clobbering import (
    DOMClobberingDetector,
    ClobberableTarget,
    ClobberVector,
    DOMClobberVuln,
    ClobberTarget,
    ClobberImpact
)

__all__ = [
    # WAF Handler
    'WAFHandler',
    'WAFType',
    'WAFDetectionResult',
    # Stealth Mode
    'StealthMode',
    'StealthConfig',
    'StealthLevel',
    'RequestThrottler',
    # Proxy Rotator
    'ProxyRotator',
    'Proxy',
    'ProxyType',
    'ProxyHealth',
    # Notifications
    'NotificationManager',
    'Notification',
    'NotificationType',
    'Severity',
    'SlackNotifier',
    'DiscordNotifier',
    'TelegramNotifier',
    'GenericWebhookNotifier',
    # Taint Tracking
    'TaintTracker',
    'TaintFlow',
    'TaintSource',
    'TaintSink',
    'SourceType',
    'SinkType',
    'SinkSeverity',
    'URLTaintAnalyzer',
    # WebSocket Analyzer
    'WebSocketAnalyzer',
    'WSMessage',
    'WSEndpoint',
    'WSVulnerability',
    'WSVulnType',
    'MessageDirection',
    'MessageType',
    # postMessage Analyzer
    'PostMessageAnalyzer',
    'MessageHandler',
    'MessageSender',
    'PMVulnerability',
    'PMVulnType',
    'OriginCheckStrength',
    # DOM Clobbering
    'DOMClobberingDetector',
    'ClobberableTarget',
    'ClobberVector',
    'DOMClobberVuln',
    'ClobberTarget',
    'ClobberImpact',
]
