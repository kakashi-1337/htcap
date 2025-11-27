# -*- coding: utf-8 -*-
"""
HTCAP Extensions - Custom Fuzzers
=================================

These fuzzers extend HTCAP's vulnerability detection capabilities.
Import from core/scan/fuzzers/ for the full fuzzer collection.
"""

# Re-export fuzzers from core for convenience
try:
    from core.scan.fuzzers.idor import IDORFuzzer
    from core.scan.fuzzers.http_smuggling import HTTPSmugglingFuzzer
    from core.scan.fuzzers.cache_poisoning import CachePoisoningFuzzer
    from core.scan.fuzzers.cors import CORSFuzzer
    from core.scan.fuzzers.host_header import HostHeaderFuzzer
    from core.scan.fuzzers.race_condition import RaceConditionFuzzer
    from core.scan.fuzzers.prototype_pollution import PrototypePollutionFuzzer
    from core.scan.fuzzers.dom_xss import DOMXSSFuzzer
    from core.scan.fuzzers.graphql_injection import GraphQLInjection
    from core.scan.fuzzers.ssrf import SSRFFuzzer
except ImportError:
    pass

__all__ = [
    'IDORFuzzer',
    'HTTPSmugglingFuzzer',
    'CachePoisoningFuzzer',
    'CORSFuzzer',
    'HostHeaderFuzzer',
    'RaceConditionFuzzer',
    'PrototypePollutionFuzzer',
    'DOMXSSFuzzer',
    'GraphQLInjection',
    'SSRFFuzzer',
]
