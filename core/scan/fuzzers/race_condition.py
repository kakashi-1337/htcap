# -*- coding: utf-8 -*-

"""
HTCAP - Race Condition Tester
Detects race condition vulnerabilities using parallel requests.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import threading
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.scan.base_fuzzer import BaseFuzzer


class RaceConditionFuzzer(BaseFuzzer):
    """
    Fuzzer for detecting Race Condition vulnerabilities.

    Detects:
    - TOCTOU (Time-of-check to time-of-use)
    - Double spending
    - Limit bypass
    - Coupon/discount abuse
    - Vote manipulation
    """

    def init(self):
        """Initialize the fuzzer."""
        self.name = "Race Condition Detection"
        self.description = "Detects Race Condition vulnerabilities"

        # Number of parallel requests to send
        self.parallel_requests = 10

        # Patterns indicating race-vulnerable endpoints
        self.vulnerable_patterns = [
            r'/transfer', r'/send', r'/pay', r'/withdraw',
            r'/redeem', r'/coupon', r'/discount', r'/promo',
            r'/vote', r'/like', r'/follow', r'/rate',
            r'/claim', r'/reward', r'/bonus', r'/points',
            r'/limit', r'/quota', r'/allowance',
            r'/invite', r'/referral', r'/signup', r'/register',
            r'/apply', r'/submit', r'/create', r'/add',
        ]

        # Response patterns suggesting successful operation
        self.success_patterns = [
            r'success', r'completed', r'transferred', r'sent',
            r'redeemed', r'applied', r'claimed', r'added',
            r'created', r'submitted', r'registered',
        ]

        # Response patterns suggesting rate limit or duplicate
        self.blocked_patterns = [
            r'already', r'duplicate', r'exists', r'limit',
            r'exceeded', r'maximum', r'once', r'single',
            r'rate.*limit', r'too.*many', r'slow.*down',
        ]

    def _is_vulnerable_endpoint(self, url: str) -> bool:
        """Check if URL matches race-condition vulnerable patterns."""
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in self.vulnerable_patterns)

    def _send_parallel_requests(self, request, count: int) -> List[Tuple[int, Any, float]]:
        """
        Send multiple requests in parallel.

        Returns list of (index, response, response_time) tuples.
        """
        results = []
        start_barrier = threading.Barrier(count + 1)

        def send_request_thread(index):
            try:
                start_barrier.wait()  # Synchronize all threads
                start_time = time.time()
                response = self.send_request(request)
                elapsed = time.time() - start_time
                return (index, response, elapsed)
            except Exception as e:
                return (index, None, 0)

        with ThreadPoolExecutor(max_workers=count) as executor:
            futures = [executor.submit(send_request_thread, i) for i in range(count)]
            start_barrier.wait()  # Release all threads simultaneously

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=30)
                    results.append(result)
                except Exception:
                    pass

        return results

    def _analyze_responses(self, responses: List[Tuple[int, Any, float]]) -> Dict[str, Any]:
        """Analyze parallel request responses for race condition indicators."""
        analysis = {
            'total': len(responses),
            'successful': 0,
            'blocked': 0,
            'errors': 0,
            'unique_bodies': set(),
            'timing_variance': 0,
        }

        times = []
        for idx, response, elapsed in responses:
            times.append(elapsed)

            if not response:
                analysis['errors'] += 1
                continue

            body = response.body if hasattr(response, 'body') else str(response)
            body_lower = body.lower()

            # Check for success
            if any(re.search(p, body_lower) for p in self.success_patterns):
                analysis['successful'] += 1

            # Check for blocked/rate limited
            if any(re.search(p, body_lower) for p in self.blocked_patterns):
                analysis['blocked'] += 1

            # Track unique responses
            analysis['unique_bodies'].add(hash(body[:500]))

        if times:
            analysis['timing_variance'] = max(times) - min(times)

        analysis['unique_bodies'] = len(analysis['unique_bodies'])
        return analysis

    def fuzz(self, request, params) -> List[Dict[str, Any]]:
        """Execute Race Condition detection."""
        vulnerabilities = []

        # Check if endpoint looks vulnerable
        if not self._is_vulnerable_endpoint(request.url):
            # Still test POST requests
            if request.method != 'POST':
                return vulnerabilities

        # Send parallel requests
        try:
            responses = self._send_parallel_requests(request, self.parallel_requests)
            analysis = self._analyze_responses(responses)

            # Detect race conditions
            # Multiple successful responses suggest race condition
            if analysis['successful'] > 1:
                vulnerabilities.append({
                    'type': 'race_condition',
                    'description': f"Potential Race Condition detected. "
                                 f"{analysis['successful']}/{analysis['total']} parallel requests "
                                 f"returned success indicators. "
                                 f"This could enable double-spending, limit bypass, or duplicate actions.",
                    'severity': 'high',
                    'details': analysis
                })

            # All requests succeeded with same response (no rate limiting)
            elif analysis['successful'] == 0 and analysis['blocked'] == 0:
                if analysis['unique_bodies'] == 1 and analysis['errors'] == 0:
                    vulnerabilities.append({
                        'type': 'race_condition_no_rate_limit',
                        'description': f"No rate limiting detected. "
                                     f"All {analysis['total']} parallel requests received "
                                     f"identical responses with no blocking. "
                                     f"This endpoint may be vulnerable to race conditions.",
                        'severity': 'medium',
                        'details': analysis
                    })

            # Mixed results (some success, some blocked) - timing dependent
            elif analysis['successful'] > 0 and analysis['blocked'] > 0:
                vulnerabilities.append({
                    'type': 'race_condition_timing',
                    'description': f"Timing-dependent Race Condition detected. "
                                 f"{analysis['successful']} succeeded, {analysis['blocked']} blocked "
                                 f"out of {analysis['total']} parallel requests. "
                                 f"The protection mechanism may be bypassable with precise timing.",
                    'severity': 'medium',
                    'details': analysis
                })

        except Exception as e:
            pass

        return vulnerabilities
