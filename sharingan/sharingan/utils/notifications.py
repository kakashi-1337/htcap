# -*- coding: utf-8 -*-

"""
HTCAP Extensions - Notification System
Send scan results to Slack, Discord, Telegram, and webhooks.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import threading
import queue


class NotificationType(Enum):
    """Types of notifications."""
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    VULNERABILITY_FOUND = "vulnerability_found"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    WAF_DETECTED = "waf_detected"
    RATE_LIMITED = "rate_limited"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Notification:
    """Represents a notification to be sent."""
    type: NotificationType
    title: str
    message: str
    severity: Severity = Severity.INFO
    url: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class BaseNotifier:
    """Base class for notification providers."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.enabled = True

    def send(self, notification: Notification) -> bool:
        """Send a notification. Override in subclasses."""
        raise NotImplementedError

    def _post_json(self, url: str, data: Dict) -> bool:
        """POST JSON data to a URL."""
        try:
            json_data = json.dumps(data).encode('utf-8')
            request = urllib.request.Request(
                url,
                data=json_data,
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status in (200, 201, 204)
        except Exception as e:
            print(f"Notification error: {e}")
            return False


class SlackNotifier(BaseNotifier):
    """
    Send notifications to Slack via webhook.

    Setup: Create an Incoming Webhook in Slack App settings.
    """

    # Severity to Slack color mapping
    COLORS = {
        Severity.CRITICAL: "#FF0000",  # Red
        Severity.HIGH: "#FF6600",      # Orange
        Severity.MEDIUM: "#FFCC00",    # Yellow
        Severity.LOW: "#00CC00",       # Green
        Severity.INFO: "#0066FF",      # Blue
    }

    # Severity to emoji
    EMOJIS = {
        Severity.CRITICAL: ":rotating_light:",
        Severity.HIGH: ":warning:",
        Severity.MEDIUM: ":large_yellow_circle:",
        Severity.LOW: ":white_check_mark:",
        Severity.INFO: ":information_source:",
    }

    def send(self, notification: Notification) -> bool:
        """Send notification to Slack."""
        color = self.COLORS.get(notification.severity, "#808080")
        emoji = self.EMOJIS.get(notification.severity, ":bell:")

        # Build attachment
        attachment = {
            "color": color,
            "title": f"{emoji} {notification.title}",
            "text": notification.message,
            "footer": "HTCAP Scanner",
            "ts": int(notification.timestamp.timestamp()),
            "fields": []
        }

        # Add URL if present
        if notification.url:
            attachment["fields"].append({
                "title": "Target",
                "value": notification.url,
                "short": False
            })

        # Add severity
        attachment["fields"].append({
            "title": "Severity",
            "value": notification.severity.value.upper(),
            "short": True
        })

        # Add type
        attachment["fields"].append({
            "title": "Type",
            "value": notification.type.value.replace("_", " ").title(),
            "short": True
        })

        # Add extra details
        for key, value in notification.details.items():
            attachment["fields"].append({
                "title": key.replace("_", " ").title(),
                "value": str(value)[:500],  # Truncate long values
                "short": len(str(value)) < 50
            })

        payload = {"attachments": [attachment]}
        return self._post_json(self.webhook_url, payload)


class DiscordNotifier(BaseNotifier):
    """
    Send notifications to Discord via webhook.

    Setup: Create a webhook in Discord channel settings.
    """

    # Severity to Discord embed color (decimal)
    COLORS = {
        Severity.CRITICAL: 16711680,  # Red
        Severity.HIGH: 16744448,      # Orange
        Severity.MEDIUM: 16776960,    # Yellow
        Severity.LOW: 65280,          # Green
        Severity.INFO: 255,           # Blue
    }

    def send(self, notification: Notification) -> bool:
        """Send notification to Discord."""
        color = self.COLORS.get(notification.severity, 8421504)

        embed = {
            "title": notification.title,
            "description": notification.message,
            "color": color,
            "timestamp": notification.timestamp.isoformat(),
            "footer": {"text": "HTCAP Scanner"},
            "fields": []
        }

        # Add URL
        if notification.url:
            embed["fields"].append({
                "name": "Target",
                "value": notification.url,
                "inline": False
            })

        # Add severity and type
        embed["fields"].append({
            "name": "Severity",
            "value": notification.severity.value.upper(),
            "inline": True
        })
        embed["fields"].append({
            "name": "Type",
            "value": notification.type.value.replace("_", " ").title(),
            "inline": True
        })

        # Add extra details
        for key, value in notification.details.items():
            embed["fields"].append({
                "name": key.replace("_", " ").title(),
                "value": str(value)[:1024],
                "inline": len(str(value)) < 50
            })

        payload = {
            "username": "HTCAP Scanner",
            "embeds": [embed]
        }
        return self._post_json(self.webhook_url, payload)


class TelegramNotifier(BaseNotifier):
    """
    Send notifications to Telegram via Bot API.

    Setup: Create a bot via @BotFather and get chat ID.
    webhook_url format: bot_token:chat_id
    """

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.webhook_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self.enabled = True

    def send(self, notification: Notification) -> bool:
        """Send notification to Telegram."""
        # Severity emoji
        emojis = {
            Severity.CRITICAL: "🚨",
            Severity.HIGH: "⚠️",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "✅",
            Severity.INFO: "ℹ️",
        }
        emoji = emojis.get(notification.severity, "🔔")

        # Build message with HTML formatting
        message = f"<b>{emoji} {notification.title}</b>\n\n"
        message += f"{notification.message}\n\n"

        if notification.url:
            message += f"<b>Target:</b> <code>{notification.url}</code>\n"

        message += f"<b>Severity:</b> {notification.severity.value.upper()}\n"
        message += f"<b>Type:</b> {notification.type.value.replace('_', ' ').title()}\n"

        for key, value in notification.details.items():
            message += f"<b>{key.replace('_', ' ').title()}:</b> {str(value)[:200]}\n"

        message += f"\n<i>HTCAP Scanner • {notification.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</i>"

        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        return self._post_json(self.webhook_url, payload)


class GenericWebhookNotifier(BaseNotifier):
    """Send notifications to any webhook endpoint as JSON."""

    def send(self, notification: Notification) -> bool:
        """Send notification to generic webhook."""
        payload = {
            "type": notification.type.value,
            "title": notification.title,
            "message": notification.message,
            "severity": notification.severity.value,
            "url": notification.url,
            "details": notification.details,
            "timestamp": notification.timestamp.isoformat(),
            "source": "htcap"
        }
        return self._post_json(self.webhook_url, payload)


class NotificationManager:
    """
    Manages multiple notification providers and queues.

    Features:
    - Multiple provider support
    - Async sending via queue
    - Rate limiting
    - Filtering by severity
    """

    def __init__(self, min_severity: Severity = Severity.LOW):
        self.providers: List[BaseNotifier] = []
        self.min_severity = min_severity
        self._queue: queue.Queue = queue.Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False

    def add_slack(self, webhook_url: str) -> 'NotificationManager':
        """Add Slack notifier."""
        self.providers.append(SlackNotifier(webhook_url))
        return self

    def add_discord(self, webhook_url: str) -> 'NotificationManager':
        """Add Discord notifier."""
        self.providers.append(DiscordNotifier(webhook_url))
        return self

    def add_telegram(self, bot_token: str, chat_id: str) -> 'NotificationManager':
        """Add Telegram notifier."""
        self.providers.append(TelegramNotifier(bot_token, chat_id))
        return self

    def add_webhook(self, url: str) -> 'NotificationManager':
        """Add generic webhook notifier."""
        self.providers.append(GenericWebhookNotifier(url))
        return self

    def start(self):
        """Start the async notification worker."""
        if self._running:
            return

        self._running = True
        self._worker_thread = threading.Thread(target=self._worker, daemon=True)
        self._worker_thread.start()

    def stop(self):
        """Stop the notification worker."""
        self._running = False
        if self._worker_thread:
            self._queue.put(None)  # Signal to stop
            self._worker_thread.join(timeout=5)

    def _worker(self):
        """Background worker to send notifications."""
        while self._running:
            try:
                notification = self._queue.get(timeout=1)
                if notification is None:
                    break

                for provider in self.providers:
                    if provider.enabled:
                        try:
                            provider.send(notification)
                        except Exception:
                            pass

            except queue.Empty:
                continue

    def notify(self, notification: Notification):
        """Queue a notification for sending."""
        # Check severity filter
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if severity_order.index(notification.severity) < severity_order.index(self.min_severity):
            return

        if self._running:
            self._queue.put(notification)
        else:
            # Sync send if worker not running
            for provider in self.providers:
                if provider.enabled:
                    provider.send(notification)

    def notify_vulnerability(self, vuln_type: str, url: str, description: str,
                            severity: Severity = Severity.MEDIUM, **details):
        """Convenience method for vulnerability notifications."""
        self.notify(Notification(
            type=NotificationType.VULNERABILITY_FOUND,
            title=f"Vulnerability Found: {vuln_type}",
            message=description,
            severity=severity,
            url=url,
            details=details
        ))

    def notify_scan_started(self, target: str, **details):
        """Notify scan started."""
        self.notify(Notification(
            type=NotificationType.SCAN_STARTED,
            title="Scan Started",
            message=f"Starting security scan of {target}",
            severity=Severity.INFO,
            url=target,
            details=details
        ))

    def notify_scan_completed(self, target: str, vuln_count: int, **details):
        """Notify scan completed."""
        severity = Severity.INFO if vuln_count == 0 else Severity.HIGH
        self.notify(Notification(
            type=NotificationType.SCAN_COMPLETED,
            title="Scan Completed",
            message=f"Scan of {target} completed. Found {vuln_count} vulnerabilities.",
            severity=severity,
            url=target,
            details={"vulnerabilities_found": vuln_count, **details}
        ))

    def notify_waf_detected(self, target: str, waf_type: str, **details):
        """Notify WAF detected."""
        self.notify(Notification(
            type=NotificationType.WAF_DETECTED,
            title=f"WAF Detected: {waf_type}",
            message=f"Web Application Firewall detected on {target}",
            severity=Severity.INFO,
            url=target,
            details={"waf_type": waf_type, **details}
        ))
