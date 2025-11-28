# SHARINGAN

```
   ███████╗██╗  ██╗ █████╗ ██████╗ ██╗███╗   ██╗ ██████╗  █████╗ ███╗   ██╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██║████╗  ██║██╔════╝ ██╔══██╗████╗  ██║
   ███████╗███████║███████║██████╔╝██║██╔██╗ ██║██║  ███╗███████║██╔██╗ ██║
   ╚════██║██╔══██║██╔══██║██╔══██╗██║██║╚██╗██║██║   ██║██╔══██║██║╚██╗██║
   ███████║██║  ██║██║  ██║██║  ██║██║██║ ╚████║╚██████╔╝██║  ██║██║ ╚████║
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
```

**The Eye That Sees All Vulnerabilities** 👁️

Advanced Web Security Analysis Toolkit for bug bounty hunters and penetration testers.

## Features

### 🔍 DOM Analysis (DOM Invader-like)
- **Taint Tracking**: Source → Sink flow analysis for DOM XSS
- **postMessage Analyzer**: Origin validation checking, PoC generation
- **WebSocket Analyzer**: CSWSH detection, injection points, auth checks
- **DOM Clobbering Detector**: Clobberable property detection with payloads

### 🛡️ Evasion & Stealth
- **WAF Detection**: 10+ WAFs (Cloudflare, Imperva, Akamai, AWS WAF, etc.)
- **WAF Bypass**: Encoding techniques, payload mutations
- **Stealth Mode**: Human-like crawling with 5 stealth levels
- **Proxy Rotation**: Smart proxy pool with health tracking

### 🚀 Advanced Features
- **Nuclei Integration**: Auto-template selection based on tech stack
- **OOB Detection**: Self-hosted Collaborator alternative
- **AI Payload Generator**: LLM-powered payloads with WAF bypass
- **Session Replay**: Record and replay authenticated sessions
- **HTML Reports**: Beautiful vulnerability reports

### 📢 Notifications
- Slack webhooks
- Discord webhooks
- Telegram Bot API
- Custom webhooks

## Installation

```bash
pip install sharingan

# Or from source
git clone https://github.com/kakashi-1337/sharingan
cd sharingan
pip install -e .
```

## Quick Start

### CLI Usage

```bash
# Analyze JavaScript for taint flows
sharingan taint -f app.js --json

# Analyze postMessage handlers
sharingan postmessage -f app.js --poc

# Detect WAF
sharingan waf --headers-file response.txt --status-code 403

# Generate HTML report
sharingan report -i results.json -o report.html
```

### Python API

```python
from sharingan import (
    TaintTracker,
    PostMessageAnalyzer,
    WebSocketAnalyzer,
    DOMClobberingDetector,
    WAFHandler,
    StealthMode,
)

# Taint Tracking
tracker = TaintTracker()
flows = tracker.analyze(javascript_code)

for flow in flows:
    if flow.exploitable:
        print(f"XSS: {flow.source.type} -> {flow.sink.type}")
        print(f"Payload: {flow.payload_suggestion}")

# postMessage Analysis
analyzer = PostMessageAnalyzer()
vulns = analyzer.analyze(js_code)

for vuln in vulns:
    print(f"Vuln: {vuln.vuln_type.value}")
    poc = analyzer.generate_exploit_poc(vuln)

# WAF Detection
waf = WAFHandler()
result = waf.detect(headers, body, cookies, status_code)

if result.detected:
    print(f"WAF: {result.waf_type.value}")
    print(f"Bypass: {result.bypass_suggestions}")
```

### OOB Detection (Collaborator Alternative)

```python
from sharingan.integrations import OOBServer

# Start OOB server
server = OOBServer(http_port=8888)
server.start()

# Generate token for SSRF test
token = server.generate_token(
    description="SSRF test",
    vuln_type="ssrf",
    target_url="https://target.com"
)

# Get callback URL
callback_url = server.get_callback_url(token)
print(f"Inject: {callback_url}")

# Wait for callback
callback = server.wait_for_callback(token, timeout=30)
if callback:
    print(f"SSRF CONFIRMED! From: {callback.source_ip}")
```

### AI Payload Generator

```python
from sharingan.integrations import AIPayloadEngine, PayloadContext, VulnCategory

engine = AIPayloadEngine(
    ollama_url="http://localhost:11434",
    model="codellama"
)

context = PayloadContext(
    vuln_type=VulnCategory.XSS,
    injection_point="parameter",
    context="html",
    waf_detected="cloudflare"
)

payloads = engine.generate(context, count=10)

for p in payloads:
    print(f"Payload: {p.payload}")
    print(f"Confidence: {p.confidence}")
```

### Session Replay

```python
from sharingan.utils import SessionRecorder, SessionPlayer

# Record session
recorder = SessionRecorder("auth_session", "target.com")
recorder.start_recording()

# ... make requests ...
recorder.record_request(
    method="POST",
    url="https://target.com/login",
    headers={"Content-Type": "application/json"},
    body='{"user":"admin","pass":"test"}',
    response_status=200,
    response_body='{"token":"eyJ..."}'
)

recorder.stop_recording()
recorder.save("session.sharingan.gz")

# Replay session
player = SessionPlayer(recorder.session)
results = player.replay(delay_factor=0.5)
```

## Module Reference

| Module | Description |
|--------|-------------|
| `sharingan.analyzers.taint_tracking` | DOM taint flow analysis |
| `sharingan.analyzers.postmessage` | postMessage vulnerability detection |
| `sharingan.analyzers.websocket` | WebSocket security analysis |
| `sharingan.analyzers.dom_clobbering` | DOM clobbering detection |
| `sharingan.handlers.waf` | WAF detection and bypass |
| `sharingan.handlers.stealth` | Stealth crawling mode |
| `sharingan.handlers.proxy` | Proxy rotation |
| `sharingan.integrations.nuclei` | Nuclei template runner |
| `sharingan.integrations.oob_server` | OOB callback server |
| `sharingan.integrations.ai_payload` | AI payload generation |
| `sharingan.utils.report` | HTML report generator |
| `sharingan.utils.session` | Session recording/replay |
| `sharingan.utils.notifications` | Alert notifications |

## Supported WAFs

| WAF | Detection | Bypass |
|-----|-----------|--------|
| Cloudflare | ✅ | ✅ |
| Imperva/Incapsula | ✅ | ✅ |
| Akamai | ✅ | ✅ |
| AWS WAF | ✅ | ✅ |
| Sucuri | ✅ | ⚠️ |
| ModSecurity | ✅ | ✅ |
| F5 BIG-IP | ✅ | ⚠️ |
| CloudFront | ✅ | ⚠️ |
| Fastly | ✅ | ⚠️ |
| Wordfence | ✅ | ⚠️ |

## Vulnerability Coverage

- XSS (Reflected, Stored, DOM-based)
- SQL Injection
- SSRF
- IDOR
- HTTP Request Smuggling
- Cache Poisoning
- CORS Misconfiguration
- Host Header Injection
- Race Conditions
- Prototype Pollution
- postMessage vulnerabilities
- WebSocket hijacking
- DOM Clobbering
- XXE
- SSTI
- GraphQL Injection

## Requirements

- Python 3.9+
- Optional: Ollama (for AI payloads)
- Optional: Nuclei (for template scanning)

## License

GPLv2

## Author

**kakashi-1337** - ANBU Black Ops Security

---

*"Those who break the rules are scum, but those who abandon their friends are worse than scum."*

**For authorized penetration testing and bug bounty only.**
