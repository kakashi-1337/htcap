# -*- coding: utf-8 -*-
"""SHARINGAN Utils - Notifications, reports, sessions, and helpers."""

from .notifications import (
    NotificationManager,
    Notification,
    NotificationType,
    Severity,
    SlackNotifier,
    DiscordNotifier,
    TelegramNotifier,
    GenericWebhookNotifier,
)

from .report import (
    HTMLReportGenerator,
    Finding,
)

from .session import (
    SessionRecorder,
    SessionPlayer,
    SessionManager,
    Session,
    SessionState,
    RecordedRequest,
    RequestMethod,
)

__all__ = [
    # Notifications
    "NotificationManager",
    "Notification",
    "NotificationType",
    "Severity",
    "SlackNotifier",
    "DiscordNotifier",
    "TelegramNotifier",
    "GenericWebhookNotifier",
    # Reports
    "HTMLReportGenerator",
    "Finding",
    # Sessions
    "SessionRecorder",
    "SessionPlayer",
    "SessionManager",
    "Session",
    "SessionState",
    "RecordedRequest",
    "RequestMethod",
]
