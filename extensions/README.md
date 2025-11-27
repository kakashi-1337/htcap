# HTCAP Extensions

Custom security modules and enhancements for HTCAP.

## Structure

```
extensions/
├── __init__.py
├── README.md
├── lib/
│   ├── __init__.py
│   ├── waf_handler.py      # WAF detection & bypass
│   └── stealth.py          # Stealth crawling mode
├── fuzzers/
│   └── __init__.py         # Re-exports core fuzzers
└── utils/
    └── __init__.py
```

## WAF Handler

Detect and work with Web Application Firewalls:

```python
from extensions.lib import WAFHandler, WAFType

waf = WAFHandler()

# Detect WAF from response
result = waf.detect(
    response_headers=headers,
    response_body=body,
    cookies=cookies,
    status_code=403
)

if result.detected:
    print(f"WAF Detected: {result.waf_type.value}")
    print(f"Confidence: {result.confidence}%")
    print(f"Evidence: {result.evidence}")
    print(f"Bypass suggestions: {result.bypass_suggestions}")

# Get evasion headers
headers = waf.generate_evasion_headers(WAFType.CLOUDFLARE)

# Encode payloads
encoded = waf.encode_payload("<script>alert(1)</script>", "double_url")

# Calculate delays
delay = waf.calculate_delay(WAFType.CLOUDFLARE, request_count=50)
```

### Supported WAFs

| WAF | Detection | Bypass Tips |
|-----|-----------|-------------|
| Cloudflare | Headers, cookies, challenge page | Origin IP, delays, proxies |
| Imperva/Incapsula | Headers, cookies | HPP, encoding |
| Akamai | Headers, cookies | Pragma headers |
| AWS WAF | Headers | Encoding, method tampering |
| Sucuri | Headers, body | |
| ModSecurity | Headers, body | Comment bypass |
| F5 BIG-IP | Headers, cookies | |
| CloudFront | Headers | |
| Fastly | Headers | |
| Wordfence | Cookies, body | |

## Stealth Mode

Human-like crawling to avoid detection:

```python
from extensions.lib import StealthMode, StealthConfig, StealthLevel

# Configure stealth
config = StealthConfig(
    level=StealthLevel.HIGH,
    min_delay=1.0,
    max_delay=4.0,
    rotate_user_agent=True,
    randomize_headers=True,
    max_requests_per_session=50,
    session_break_time=30.0
)

stealth = StealthMode(config)

# Before each request
prep = stealth.pre_request()  # Applies delay, returns headers
headers = prep['headers']

# Get randomized headers
headers = stealth.get_headers()

# Check if break needed
if stealth.should_take_break():
    stealth.take_break()
```

### Stealth Levels

| Level | Delay | Features |
|-------|-------|----------|
| NONE | 0 | Maximum speed |
| LOW | 0.3-1s | Basic UA rotation |
| MEDIUM | 0.5-2s | Header randomization |
| HIGH | 1-4s | Human-like behavior |
| PARANOID | 3-10s | Maximum caution |

## Request Throttler

Adaptive rate limiting:

```python
from extensions.lib.stealth import RequestThrottler

throttler = RequestThrottler(initial_delay=1.0)

for url in urls:
    response = make_request(url)

    if response.status_code == 200:
        throttler.record_success()
    else:
        throttler.record_error(response.status_code)

    if throttler.is_being_blocked():
        print("Warning: Likely being blocked!")
        break

    throttler.wait()
```

## Proxy Rotator

Manage and rotate proxies for distributed scanning:

```python
from extensions.lib import ProxyRotator, ProxyType

rotator = ProxyRotator()

# Add proxies
rotator.add_proxy("http://proxy1.example.com:8080")
rotator.add_proxy("socks5://proxy2.example.com:1080", proxy_type=ProxyType.SOCKS5)

# Load from file (one proxy per line)
rotator.load_from_file("proxies.txt")

# Get proxy with smart selection (considers health)
proxy = rotator.get_proxy()

# Report results to improve selection
rotator.report_success(proxy, response_time=0.5)
rotator.report_failure(proxy, "timeout")

# Get statistics
stats = rotator.get_stats()
print(f"Total: {stats['total']}, Healthy: {stats['healthy']}")
```

### Rotation Strategies

| Strategy | Description |
|----------|-------------|
| ROUND_ROBIN | Sequential rotation through all proxies |
| RANDOM | Random selection |
| SMART | Weighted by health and response time |

## Notifications

Send scan results to Slack, Discord, Telegram, or custom webhooks:

```python
from extensions.lib import NotificationManager, Severity

# Set up notifications
manager = NotificationManager(min_severity=Severity.MEDIUM)
manager.add_slack("https://hooks.slack.com/services/...")
manager.add_discord("https://discord.com/api/webhooks/...")
manager.add_telegram("BOT_TOKEN", "CHAT_ID")
manager.add_webhook("https://your-endpoint.com/webhook")

# Start async worker (optional, for background sending)
manager.start()

# Send notifications
manager.notify_scan_started("https://target.com")
manager.notify_vulnerability(
    vuln_type="XSS",
    url="https://target.com/page?q=test",
    description="Reflected XSS in search parameter",
    severity=Severity.HIGH,
    parameter="q"
)
manager.notify_scan_completed("https://target.com", vuln_count=5)

# Cleanup
manager.stop()
```

### Notification Types

| Type | Description |
|------|-------------|
| SCAN_STARTED | Scan initiated |
| SCAN_COMPLETED | Scan finished with summary |
| VULNERABILITY_FOUND | Security issue detected |
| WAF_DETECTED | WAF detected on target |
| ERROR | Scan error occurred |
| WARNING | Non-critical issue |
| RATE_LIMITED | Rate limiting detected |

## Available Fuzzers

All custom fuzzers are in `core/scan/fuzzers/`:

| Fuzzer | File | Detection |
|--------|------|-----------|
| IDOR | `idor.py` | Insecure Direct Object Reference |
| HTTP Smuggling | `http_smuggling.py` | CL.TE, TE.CL, TE.TE |
| Cache Poisoning | `cache_poisoning.py` | Web cache attacks |
| CORS | `cors.py` | CORS misconfiguration |
| Host Header | `host_header.py` | Host header injection |
| Race Condition | `race_condition.py` | TOCTOU, double spending |
| Prototype Pollution | `prototype_pollution.py` | JS prototype pollution |
| DOM XSS | `dom_xss.py` | DOM-based XSS |
| GraphQL | `graphql_injection.py` | GraphQL injection |
| SSRF | `ssrf.py` | Server-side request forgery |

## Usage Notes

**For AUTHORIZED penetration testing only.**

1. Always get written permission before testing
2. Respect rate limits and robots.txt
3. Don't use against production systems without authorization
4. Be aware of legal implications in your jurisdiction

## License

GPLv2 - Same as HTCAP
