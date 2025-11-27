# -*- coding: utf-8 -*-

"""
HTCAP Extensions - Proxy Rotator
Manages proxy rotation for distributed scanning.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import random
import time
import threading
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import re


class ProxyType(Enum):
    """Proxy protocol types."""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class ProxyStatus(Enum):
    """Proxy health status."""
    UNKNOWN = "unknown"
    ALIVE = "alive"
    DEAD = "dead"
    SLOW = "slow"
    RATE_LIMITED = "rate_limited"


@dataclass
class Proxy:
    """Represents a proxy server."""
    host: str
    port: int
    protocol: ProxyType = ProxyType.HTTP
    username: Optional[str] = None
    password: Optional[str] = None
    status: ProxyStatus = ProxyStatus.UNKNOWN
    response_time: float = 0.0
    fail_count: int = 0
    success_count: int = 0
    last_used: float = 0.0
    last_checked: float = 0.0
    country: Optional[str] = None

    @property
    def url(self) -> str:
        """Get proxy URL string."""
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.protocol.value}://{auth}{self.host}:{self.port}"

    @property
    def is_healthy(self) -> bool:
        """Check if proxy is considered healthy."""
        return self.status in (ProxyStatus.ALIVE, ProxyStatus.UNKNOWN)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for requests library."""
        url = self.url
        if self.protocol in (ProxyType.HTTP, ProxyType.HTTPS):
            return {"http": url, "https": url}
        else:
            return {"http": url, "https": url}


class ProxyRotator:
    """
    Manages a pool of proxies with intelligent rotation.

    Features:
    - Round-robin, random, and smart rotation strategies
    - Health checking and automatic removal of dead proxies
    - Rate limit detection and cooldown
    - Geographic filtering
    - Statistics tracking
    """

    def __init__(self, proxies: List[str] = None, rotation_strategy: str = "smart"):
        """
        Initialize the proxy rotator.

        Args:
            proxies: List of proxy strings (format: protocol://user:pass@host:port)
            rotation_strategy: 'round_robin', 'random', or 'smart'
        """
        self.proxies: List[Proxy] = []
        self.rotation_strategy = rotation_strategy
        self.current_index = 0
        self._lock = threading.Lock()
        self.cooldown_time = 60.0  # Seconds to wait after rate limit
        self.max_fails = 3  # Max failures before marking dead

        if proxies:
            self.add_proxies(proxies)

    def add_proxies(self, proxy_strings: List[str]):
        """
        Add proxies from string list.

        Format: protocol://user:pass@host:port or host:port
        """
        for proxy_str in proxy_strings:
            proxy = self._parse_proxy_string(proxy_str)
            if proxy:
                self.proxies.append(proxy)

    def _parse_proxy_string(self, proxy_str: str) -> Optional[Proxy]:
        """Parse a proxy string into a Proxy object."""
        try:
            # Handle full URL format
            match = re.match(
                r'^(?P<protocol>https?|socks[45])?://'
                r'(?:(?P<user>[^:]+):(?P<pass>[^@]+)@)?'
                r'(?P<host>[^:]+):(?P<port>\d+)$',
                proxy_str
            )

            if match:
                groups = match.groupdict()
                protocol = ProxyType(groups['protocol'] or 'http')
                return Proxy(
                    host=groups['host'],
                    port=int(groups['port']),
                    protocol=protocol,
                    username=groups['user'],
                    password=groups['pass']
                )

            # Handle simple host:port format
            match = re.match(r'^(?P<host>[^:]+):(?P<port>\d+)$', proxy_str)
            if match:
                return Proxy(
                    host=match.group('host'),
                    port=int(match.group('port'))
                )

            return None
        except Exception:
            return None

    def add_proxy(self, proxy: Proxy):
        """Add a single proxy to the pool."""
        with self._lock:
            self.proxies.append(proxy)

    def remove_proxy(self, proxy: Proxy):
        """Remove a proxy from the pool."""
        with self._lock:
            if proxy in self.proxies:
                self.proxies.remove(proxy)

    def get_proxy(self) -> Optional[Proxy]:
        """
        Get the next proxy based on rotation strategy.

        Returns:
            Next available proxy or None if pool is empty
        """
        with self._lock:
            healthy_proxies = [p for p in self.proxies if p.is_healthy]

            if not healthy_proxies:
                # Try to reset some proxies
                self._reset_dead_proxies()
                healthy_proxies = [p for p in self.proxies if p.is_healthy]

            if not healthy_proxies:
                return None

            if self.rotation_strategy == "round_robin":
                proxy = self._round_robin(healthy_proxies)
            elif self.rotation_strategy == "random":
                proxy = self._random(healthy_proxies)
            else:  # smart
                proxy = self._smart_select(healthy_proxies)

            proxy.last_used = time.time()
            return proxy

    def _round_robin(self, proxies: List[Proxy]) -> Proxy:
        """Round-robin selection."""
        self.current_index = self.current_index % len(proxies)
        proxy = proxies[self.current_index]
        self.current_index += 1
        return proxy

    def _random(self, proxies: List[Proxy]) -> Proxy:
        """Random selection."""
        return random.choice(proxies)

    def _smart_select(self, proxies: List[Proxy]) -> Proxy:
        """
        Smart selection based on:
        - Response time (prefer faster)
        - Success rate (prefer reliable)
        - Last used time (distribute load)
        """
        def score(p: Proxy) -> float:
            # Lower is better
            time_score = p.response_time if p.response_time > 0 else 1.0

            # Success rate (higher is better, so invert)
            total = p.success_count + p.fail_count
            if total > 0:
                success_rate = p.success_count / total
                reliability_score = 1.0 - success_rate
            else:
                reliability_score = 0.5

            # Time since last use (higher is better for distribution)
            time_since_use = time.time() - p.last_used
            freshness_score = 1.0 / (time_since_use + 1)

            return time_score + reliability_score + freshness_score

        return min(proxies, key=score)

    def _reset_dead_proxies(self):
        """Reset proxies that have been dead for a while."""
        current_time = time.time()
        for proxy in self.proxies:
            if proxy.status == ProxyStatus.DEAD:
                # Reset if dead for more than 5 minutes
                if current_time - proxy.last_checked > 300:
                    proxy.status = ProxyStatus.UNKNOWN
                    proxy.fail_count = 0

    def report_success(self, proxy: Proxy, response_time: float = 0.0):
        """Report a successful request through a proxy."""
        with self._lock:
            proxy.success_count += 1
            proxy.status = ProxyStatus.ALIVE
            if response_time > 0:
                # Rolling average
                proxy.response_time = (proxy.response_time * 0.7) + (response_time * 0.3)

    def report_failure(self, proxy: Proxy, reason: str = ""):
        """Report a failed request through a proxy."""
        with self._lock:
            proxy.fail_count += 1
            proxy.last_checked = time.time()

            if "rate" in reason.lower() or "429" in reason:
                proxy.status = ProxyStatus.RATE_LIMITED
            elif "timeout" in reason.lower() or "slow" in reason.lower():
                proxy.status = ProxyStatus.SLOW
            elif proxy.fail_count >= self.max_fails:
                proxy.status = ProxyStatus.DEAD

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the proxy pool."""
        total = len(self.proxies)
        alive = sum(1 for p in self.proxies if p.status == ProxyStatus.ALIVE)
        dead = sum(1 for p in self.proxies if p.status == ProxyStatus.DEAD)
        rate_limited = sum(1 for p in self.proxies if p.status == ProxyStatus.RATE_LIMITED)

        total_requests = sum(p.success_count + p.fail_count for p in self.proxies)
        total_success = sum(p.success_count for p in self.proxies)

        return {
            'total_proxies': total,
            'alive': alive,
            'dead': dead,
            'rate_limited': rate_limited,
            'unknown': total - alive - dead - rate_limited,
            'total_requests': total_requests,
            'success_rate': total_success / total_requests if total_requests > 0 else 0,
            'avg_response_time': sum(p.response_time for p in self.proxies if p.response_time > 0) / max(1, alive),
        }

    def load_from_file(self, filepath: str):
        """Load proxies from a file (one per line)."""
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
                proxy_strings = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
                self.add_proxies(proxy_strings)
        except Exception as e:
            raise Exception(f"Failed to load proxies from {filepath}: {e}")

    def load_from_url(self, url: str):
        """Load proxies from a URL (proxy list API)."""
        import urllib.request
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read().decode('utf-8')
                proxy_strings = [line.strip() for line in content.split('\n') if line.strip()]
                self.add_proxies(proxy_strings)
        except Exception as e:
            raise Exception(f"Failed to load proxies from {url}: {e}")

    def export_working(self) -> List[str]:
        """Export list of working proxy URLs."""
        return [p.url for p in self.proxies if p.status == ProxyStatus.ALIVE]

    def __len__(self) -> int:
        return len(self.proxies)

    def __iter__(self):
        return iter(self.proxies)


class ProxyChain:
    """
    Manages chained proxy connections (proxy through proxy).

    Useful for additional anonymity layers.
    """

    def __init__(self):
        self.chain: List[Proxy] = []

    def add_hop(self, proxy: Proxy):
        """Add a proxy hop to the chain."""
        self.chain.append(proxy)

    def get_chain_config(self) -> Dict[str, Any]:
        """Get configuration for proxy chain (for tools like proxychains)."""
        return {
            'hops': len(self.chain),
            'proxies': [p.to_dict() for p in self.chain]
        }
