# -*- coding: utf-8 -*-

"""
HTCAP Extensions - Stealth Mode
Provides techniques for stealthy crawling and scanning.

For AUTHORIZED penetration testing only.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import random
import time
import hashlib
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum


class StealthLevel(Enum):
    """Stealth levels for scanning."""
    NONE = 0        # No stealth, maximum speed
    LOW = 1         # Basic delays, rotating UA
    MEDIUM = 2      # Longer delays, header randomization
    HIGH = 3        # Maximum stealth, human-like behavior
    PARANOID = 4    # Extreme caution, very slow


@dataclass
class StealthConfig:
    """Configuration for stealth mode."""
    level: StealthLevel = StealthLevel.MEDIUM
    min_delay: float = 0.5
    max_delay: float = 3.0
    rotate_user_agent: bool = True
    randomize_headers: bool = True
    use_proxies: bool = False
    proxies: List[str] = None
    max_requests_per_session: int = 50
    session_break_time: float = 30.0


class StealthMode:
    """
    Provides stealth capabilities for web scanning.

    Features:
    - Request throttling with human-like delays
    - User-Agent rotation
    - Header randomization
    - Proxy rotation
    - Session management
    - Fingerprint randomization
    """

    def __init__(self, config: StealthConfig = None):
        self.config = config or StealthConfig()
        self.request_count = 0
        self.session_start = time.time()
        self._init_user_agents()
        self._init_headers()

    def _init_user_agents(self):
        """Initialize pool of realistic user agents."""
        self.user_agents = [
            # Chrome Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",

            # Chrome Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",

            # Firefox Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",

            # Firefox Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",

            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",

            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",

            # Chrome Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

            # Mobile
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        ]

    def _init_headers(self):
        """Initialize header variations."""
        self.accept_languages = [
            "en-US,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.5",
            "en-CA,en;q=0.9,fr;q=0.8",
        ]

        self.accept_encodings = [
            "gzip, deflate, br",
            "gzip, deflate",
            "gzip, deflate, br, zstd",
        ]

        self.connection_types = [
            "keep-alive",
            "close",
        ]

    def get_delay(self) -> float:
        """
        Calculate delay based on stealth level.

        Returns:
            Delay in seconds with human-like randomization
        """
        level = self.config.level

        if level == StealthLevel.NONE:
            return 0

        # Base delays per level
        delays = {
            StealthLevel.LOW: (0.3, 1.0),
            StealthLevel.MEDIUM: (0.5, 2.0),
            StealthLevel.HIGH: (1.0, 4.0),
            StealthLevel.PARANOID: (3.0, 10.0),
        }

        min_d, max_d = delays.get(level, (0.5, 2.0))

        # Add human-like variation
        # Humans have occasional longer pauses
        if random.random() < 0.1:  # 10% chance of longer pause
            max_d *= 2

        delay = random.uniform(min_d, max_d)

        # Add micro-variations
        delay += random.gauss(0, 0.1)
        delay = max(0.1, delay)

        return delay

    def get_user_agent(self) -> str:
        """Get a random user agent."""
        if not self.config.rotate_user_agent:
            return self.user_agents[0]
        return random.choice(self.user_agents)

    def get_headers(self, base_headers: Dict[str, str] = None) -> Dict[str, str]:
        """
        Get randomized headers for request.

        Args:
            base_headers: Base headers to include

        Returns:
            Dictionary of HTTP headers
        """
        headers = base_headers.copy() if base_headers else {}

        headers['User-Agent'] = self.get_user_agent()

        if self.config.randomize_headers:
            headers['Accept-Language'] = random.choice(self.accept_languages)
            headers['Accept-Encoding'] = random.choice(self.accept_encodings)

            # Randomly include/exclude optional headers
            if random.random() > 0.3:
                headers['DNT'] = '1'

            if random.random() > 0.5:
                headers['Upgrade-Insecure-Requests'] = '1'

            # Sec-Fetch headers (modern browsers)
            if random.random() > 0.2:
                headers['Sec-Fetch-Dest'] = random.choice(['document', 'empty'])
                headers['Sec-Fetch-Mode'] = random.choice(['navigate', 'cors', 'no-cors'])
                headers['Sec-Fetch-Site'] = random.choice(['none', 'same-origin', 'cross-site'])

        headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        headers['Connection'] = random.choice(self.connection_types)

        return headers

    def should_take_break(self) -> bool:
        """Check if we should take a break (session rotation)."""
        if self.request_count >= self.config.max_requests_per_session:
            return True

        # Random break (1% chance per request at HIGH/PARANOID)
        if self.config.level in (StealthLevel.HIGH, StealthLevel.PARANOID):
            if random.random() < 0.01:
                return True

        return False

    def take_break(self) -> float:
        """
        Take a session break.

        Returns:
            Duration of break taken
        """
        break_time = self.config.session_break_time

        # Add variation
        break_time *= random.uniform(0.8, 1.5)

        time.sleep(break_time)

        # Reset session
        self.request_count = 0
        self.session_start = time.time()

        return break_time

    def pre_request(self) -> Dict[str, Any]:
        """
        Prepare for a request.

        Returns:
            Dict with headers and any pre-request info
        """
        # Check if break needed
        if self.should_take_break():
            break_duration = self.take_break()

        # Calculate delay
        delay = self.get_delay()
        if delay > 0:
            time.sleep(delay)

        # Increment counter
        self.request_count += 1

        return {
            'headers': self.get_headers(),
            'request_number': self.request_count,
            'delay_applied': delay,
        }

    def get_proxy(self) -> Optional[str]:
        """Get a proxy from the rotation pool."""
        if not self.config.use_proxies or not self.config.proxies:
            return None
        return random.choice(self.config.proxies)

    @staticmethod
    def generate_session_fingerprint() -> Dict[str, Any]:
        """
        Generate a consistent browser fingerprint for the session.

        Returns:
            Dict with fingerprint parameters
        """
        screen_resolutions = [
            (1920, 1080), (1366, 768), (1536, 864),
            (1440, 900), (1280, 720), (2560, 1440),
        ]

        timezones = [
            -480, -420, -360, -300, -240, 0, 60, 120
        ]

        languages = [
            ['en-US', 'en'],
            ['en-GB', 'en'],
            ['en-US', 'en', 'es'],
        ]

        resolution = random.choice(screen_resolutions)

        return {
            'screen_width': resolution[0],
            'screen_height': resolution[1],
            'color_depth': 24,
            'timezone_offset': random.choice(timezones),
            'languages': random.choice(languages),
            'platform': random.choice(['Win32', 'MacIntel', 'Linux x86_64']),
            'cookie_enabled': True,
            'do_not_track': random.choice(['1', None]),
        }


class RequestThrottler:
    """
    Advanced request throttling with adaptive rate limiting.

    Adjusts speed based on server responses.
    """

    def __init__(self, initial_delay: float = 1.0):
        self.base_delay = initial_delay
        self.current_delay = initial_delay
        self.consecutive_errors = 0
        self.consecutive_successes = 0
        self.blocked_count = 0

    def record_success(self):
        """Record a successful request."""
        self.consecutive_successes += 1
        self.consecutive_errors = 0

        # Speed up slightly after consistent success
        if self.consecutive_successes > 10:
            self.current_delay = max(0.1, self.current_delay * 0.95)

    def record_error(self, status_code: int = 0):
        """Record a failed request."""
        self.consecutive_errors += 1
        self.consecutive_successes = 0

        # Slow down on errors
        if status_code == 429:  # Rate limited
            self.current_delay *= 3
            self.blocked_count += 1
        elif status_code in (403, 503):  # Possibly blocked
            self.current_delay *= 2
            self.blocked_count += 1
        else:
            self.current_delay *= 1.2

        # Cap at reasonable maximum
        self.current_delay = min(60.0, self.current_delay)

    def get_delay(self) -> float:
        """Get the current recommended delay."""
        jitter = random.uniform(-0.1, 0.1) * self.current_delay
        return max(0.1, self.current_delay + jitter)

    def wait(self):
        """Wait the recommended delay."""
        time.sleep(self.get_delay())

    def is_being_blocked(self) -> bool:
        """Check if we're likely being blocked."""
        return self.blocked_count >= 3 or self.consecutive_errors >= 5
