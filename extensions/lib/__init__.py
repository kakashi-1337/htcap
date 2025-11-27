# -*- coding: utf-8 -*-
"""Extensions library modules."""

from .waf_handler import WAFHandler, WAFType, WAFDetectionResult
from .stealth import StealthMode, StealthConfig, StealthLevel, RequestThrottler
from .proxy_rotator import ProxyRotator, Proxy, ProxyType, ProxyHealth
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
]
