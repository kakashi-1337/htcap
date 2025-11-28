# -*- coding: utf-8 -*-
"""SHARINGAN Handlers - WAF, Stealth, and Proxy modules."""

from .waf import WAFHandler, WAFType, WAFDetectionResult
from .stealth import StealthMode, StealthConfig, StealthLevel, RequestThrottler
from .proxy import ProxyRotator, Proxy, ProxyType, ProxyHealth

__all__ = [
    "WAFHandler",
    "WAFType",
    "WAFDetectionResult",
    "StealthMode",
    "StealthConfig",
    "StealthLevel",
    "RequestThrottler",
    "ProxyRotator",
    "Proxy",
    "ProxyType",
    "ProxyHealth",
]
