# HTCAP - Web Application Security Scanner

[![CI](https://github.com/fcavallarin/htcap/actions/workflows/ci.yml/badge.svg)](https://github.com/fcavallarin/htcap/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)

**HTCAP** is a powerful web application security scanner designed specifically for modern **Single Page Applications (SPAs)**. It crawls web applications by intercepting AJAX calls, fetch requests, WebSocket communications, and DOM changes, providing comprehensive coverage that traditional crawlers miss.

## Key Features

### Crawling Engine
- **Recursive DOM Crawling** - Discovers content through JavaScript execution
- **Modern API Support** - Intercepts XHR, Fetch, GraphQL, WebSocket, JSONP requests
- **Smart Deduplication** - Heuristic page deduplication based on text similarity
- **Scriptable Login** - Support for complex authentication flows
- **Headless Chrome** - Powered by Puppeteer for accurate JavaScript rendering

### Security Scanning
- **Built-in Fuzzers**:
  - SQL Injection (Error-based & Blind)
  - Cross-Site Scripting (XSS)
  - Command Injection
  - File Inclusion (LFI/RFI)
  - **GraphQL Injection** *(New!)*
  - **SSRF Detection** *(New!)*
- **External Tool Integration**: SQLMap, Arachni, Wapiti, Burp Suite
- **JWT Security Testing** *(New!)*

### Reporting & Export
- Interactive HTML reports with filtering
- SQLite database persistence
- Export to cURL commands
- REST API compatible output

## Quick Start

### Requirements
- Python 3.9+
- Node.js 18+ and npm
- Chrome/Chromium (installed automatically by Puppeteer)

### Installation

```bash
# Clone the repository
git clone https://github.com/fcavallarin/htcap.git
cd htcap

# Install Node.js dependencies
cd core/nodejs && npm install && cd ../..

# Run htcap
python3 htcap.py --help
```

### Docker Installation

```bash
# Build the Docker image
docker build -t htcap .

# Run htcap in Docker
docker run -v "$(pwd)/output:/out" -it htcap bash

# Inside the container
htcap crawl https://example.com /out/scan.db
```

## Usage Examples

### Basic Crawl
```bash
# Crawl a website and save results to database
htcap crawl https://example.com output.db
```

### Authenticated Crawl
```bash
# Using cookies
htcap crawl -c "session=abc123; token=xyz789" https://example.com output.db

# Using cookie file (JSON format)
htcap crawl -C cookies.json https://example.com output.db

# With HTTP Basic Auth
htcap crawl -A "username:password" https://example.com output.db
```

### Crawl with Custom Options
```bash
# Aggressive mode with 20 threads
htcap crawl -m aggressive -n 20 https://example.com output.db

# Limit crawl scope to specific directory
htcap crawl -s directory https://example.com/app/ output.db

# Exclude logout URLs
htcap crawl -x "logout|signout|exit" https://example.com output.db

# Use a proxy
htcap crawl -p http:127.0.0.1:8080 https://example.com output.db
```

### Vulnerability Scanning
```bash
# Scan with built-in fuzzers
htcap scan native output.db

# Scan with SQLMap
htcap scan sqlmap output.db

# Chain crawl and scan
htcap crawl https://example.com output.db \; scan native \; util report report.html
```

### Generate Reports
```bash
# HTML report
htcap util report output.db report.html

# List discovered AJAX requests
htcap util lsajax output.db

# Export to cURL commands
htcap util tocurl output.db
```

## Command Reference

### Crawl Command
```
htcap crawl [options] <url> <output_file>

Options:
  -h               Show help
  -m MODE          Crawl mode: passive, active, aggressive (default)
  -s SCOPE         Scope: domain (default), directory, url
  -n THREADS       Number of parallel threads (default: 10)
  -D DEPTH         Maximum crawl depth (default: 100)
  -t TIMEOUT       Page analysis timeout in seconds (default: 300)
  -c COOKIES       Cookies as JSON or name=value pairs
  -C FILE          Cookie file path
  -A CREDS         HTTP Basic Auth credentials (user:pass)
  -p PROXY         Proxy (http:host:port or socks5:host:port)
  -x EXCLUDE       Regex patterns to exclude (comma-separated)
  -d DOMAINS       Additional allowed domains (comma-separated)
  -U USERAGENT     Custom User-Agent string
  -E HEADER        Extra headers (can be repeated: -E "X-Custom: value")
  -L SEQUENCE      Login sequence file (JSON)
  -H               Save HTML content
  -l               Disable headless mode (show browser)
  -v               Verbose output
  -q               Quiet mode
```

### Scan Command
```
htcap scan <scanner> [database]

Scanners:
  native           Built-in vulnerability fuzzers
  sqlmap           SQLMap SQL injection scanner
  arachni          Arachni web scanner
  wapiti           Wapiti vulnerability scanner
```

### Util Command
```
htcap util <utility> [database] [options]

Utilities:
  report           Generate HTML report
  lsajax           List AJAX/API requests
  lsvuln           List discovered vulnerabilities
  tocurl           Export requests as cURL commands
```

## Configuration

### Login Sequence
Create a JSON file for complex authentication:

```json
{
  "type": "shared",
  "url": "https://example.com/login",
  "steps": [
    {
      "type": "fill",
      "selector": "#username",
      "value": "testuser"
    },
    {
      "type": "fill",
      "selector": "#password",
      "value": "testpass"
    },
    {
      "type": "click",
      "selector": "#login-button"
    },
    {
      "type": "wait",
      "value": 2000
    }
  ],
  "cookies": ["session", "auth_token"]
}
```

### Cookie File Format
```json
[
  {
    "name": "session",
    "value": "abc123",
    "domain": "example.com",
    "path": "/"
  }
]
```

## Architecture

```
htcap/
├── htcap.py              # Main entry point
├── core/
│   ├── crawl/            # Crawling engine
│   │   ├── crawler.py    # Main crawler orchestration
│   │   └── probe/        # JavaScript probe (Puppeteer)
│   ├── scan/             # Scanning engine
│   │   ├── scanner.py    # Scanner orchestration
│   │   ├── fuzzers/      # Built-in vulnerability fuzzers
│   │   │   ├── xss_reflected.py
│   │   │   ├── sqli_blind.py
│   │   │   ├── sqli_error.py
│   │   │   ├── graphql_injection.py  # NEW
│   │   │   └── ssrf.py               # NEW
│   │   └── scanners/     # External tool integrations
│   ├── lib/              # Core libraries
│   │   ├── auth/         # Authentication handlers (NEW)
│   │   │   └── jwt_handler.py
│   │   ├── logger.py     # Logging facility (NEW)
│   │   └── database.py   # SQLite interface
│   └── util/             # Utility commands
└── Dockerfile            # Docker configuration
```

## New in Version 2.0

### GraphQL Support
- Automatic GraphQL endpoint detection
- Introspection query testing
- GraphQL-specific injection fuzzing
- Batching attack detection

### JWT Security Testing
- Automatic JWT token detection in requests
- Algorithm confusion vulnerability testing
- None algorithm bypass testing
- Weak secret bruteforce
- Token manipulation for IDOR testing

### SSRF Detection
- Internal IP address testing
- Cloud metadata endpoint access (AWS, GCP, Azure)
- Protocol handler testing (file://, gopher://, etc.)
- Bypass technique testing

### Enhanced Logging
- Colored console output
- File logging support
- Component-specific log levels
- Debug mode for troubleshooting

### Modern Infrastructure
- Updated to Ubuntu 22.04 Docker base
- Node.js 20 LTS support
- Python 3.9+ with type hints
- GitHub Actions CI/CD pipeline

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Creating Custom Fuzzers

HTCAP includes a fuzzing framework that makes it easy to create custom vulnerability detectors:

```python
from core.scan.base_fuzzer import BaseFuzzer

class MyFuzzer(BaseFuzzer):
    def init(self):
        self.name = "My Custom Fuzzer"
        self.payloads = ["payload1", "payload2"]

    def fuzz(self, request, params):
        vulnerabilities = []
        for payload in self.payloads:
            response = self.send_request(request, data=payload)
            if self.check_vulnerability(response):
                vulnerabilities.append({
                    'type': 'custom_vuln',
                    'description': f'Found with payload: {payload}'
                })
        return vulnerabilities
```

## Security Considerations

HTCAP is a security testing tool intended for **authorized penetration testing** only. Always ensure you have explicit permission before scanning any web application.

- Only test applications you own or have written authorization to test
- Be aware that aggressive scanning may impact application performance
- Some payloads may trigger security alerts or WAF blocks
- Review scan results carefully before reporting vulnerabilities

## License

This program is free software; you can redistribute it and/or modify it under the terms of the [GNU General Public License](https://www.gnu.org/licenses/gpl-2.0.html) as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

## Credits

- **Author**: Filippo Cavallarin ([@pfrfrfr](https://twitter.com/pfrfrfr))
- **Website**: [fcvl.net/htcap](http://www.fcvl.net/htcap)
- **Powered by**: [htcrawl](https://github.com/nicholaswhite/htcrawl) - Puppeteer-based crawling library

## Support

- **Documentation**: [fcvl.net/htcap](http://www.fcvl.net/htcap)
- **Issues**: [GitHub Issues](https://github.com/fcavallarin/htcap/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fcavallarin/htcap/discussions)
