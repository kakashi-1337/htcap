# -*- coding: utf-8 -*-
"""
SHARINGAN - Session Replay
Record and replay authenticated sessions for scanning.
"""

import json
import time
import pickle
import hashlib
import gzip
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
import urllib.request
import urllib.parse
import http.cookiejar


class RequestMethod(Enum):
    """HTTP request methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass
class RecordedRequest:
    """Represents a recorded HTTP request."""
    method: RequestMethod
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    response_time: Optional[float] = None


@dataclass
class SessionState:
    """Current session state."""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)  # JWT, CSRF, etc.
    variables: Dict[str, str] = field(default_factory=dict)  # Dynamic values


@dataclass
class Session:
    """Represents a recorded session."""
    session_id: str
    name: str
    target_domain: str
    created_at: datetime
    requests: List[RecordedRequest] = field(default_factory=list)
    state: SessionState = field(default_factory=SessionState)
    description: str = ""
    tags: List[str] = field(default_factory=list)


class SessionRecorder:
    """
    Record HTTP sessions for replay.

    Captures requests/responses and extracts auth tokens.
    """

    # Patterns for extracting tokens
    TOKEN_PATTERNS = {
        'csrf': [
            r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)',
            r'_token["\']?\s*[:=]\s*["\']([^"\']+)',
            r'name=["\']?_?csrf["\']?\s+value=["\']([^"\']+)',
        ],
        'jwt': [
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        ],
        'session': [
            r'session[_-]?id["\']?\s*[:=]\s*["\']([^"\']+)',
            r'PHPSESSID=([^;]+)',
            r'JSESSIONID=([^;]+)',
        ],
    }

    def __init__(self, name: str, target_domain: str):
        """
        Initialize session recorder.

        Args:
            name: Session name
            target_domain: Target domain
        """
        self.session = Session(
            session_id=hashlib.md5(f"{name}{time.time()}".encode()).hexdigest()[:16],
            name=name,
            target_domain=target_domain,
            created_at=datetime.now()
        )
        self._recording = False

    def start_recording(self):
        """Start recording requests."""
        self._recording = True

    def stop_recording(self):
        """Stop recording requests."""
        self._recording = False

    def record_request(self, method: str, url: str, headers: Dict[str, str],
                      body: Optional[str] = None,
                      response_status: Optional[int] = None,
                      response_headers: Optional[Dict[str, str]] = None,
                      response_body: Optional[str] = None,
                      response_time: Optional[float] = None):
        """
        Record a request/response pair.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body
            response_status: Response status code
            response_headers: Response headers
            response_body: Response body
            response_time: Response time in seconds
        """
        if not self._recording:
            return

        request = RecordedRequest(
            method=RequestMethod(method.upper()),
            url=url,
            headers=headers,
            body=body,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            response_time=response_time
        )

        self.session.requests.append(request)

        # Extract tokens from response
        if response_body:
            self._extract_tokens(response_body)
        if response_headers:
            self._extract_cookies(response_headers)

    def _extract_tokens(self, body: str):
        """Extract tokens from response body."""
        import re

        for token_type, patterns in self.TOKEN_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    self.session.state.tokens[token_type] = matches[0]

    def _extract_cookies(self, headers: Dict[str, str]):
        """Extract cookies from response headers."""
        set_cookie = headers.get('Set-Cookie', '') or headers.get('set-cookie', '')
        if set_cookie:
            # Parse cookie
            for cookie in set_cookie.split(','):
                parts = cookie.split(';')[0].strip()
                if '=' in parts:
                    name, value = parts.split('=', 1)
                    self.session.state.cookies[name.strip()] = value.strip()

    def set_header(self, name: str, value: str):
        """Set a session header."""
        self.session.state.headers[name] = value

    def set_cookie(self, name: str, value: str):
        """Set a session cookie."""
        self.session.state.cookies[name] = value

    def set_token(self, name: str, value: str):
        """Set a session token."""
        self.session.state.tokens[name] = value

    def save(self, filepath: str):
        """Save session to file."""
        path = Path(filepath)

        data = {
            'session_id': self.session.session_id,
            'name': self.session.name,
            'target_domain': self.session.target_domain,
            'created_at': self.session.created_at.isoformat(),
            'description': self.session.description,
            'tags': self.session.tags,
            'state': {
                'cookies': self.session.state.cookies,
                'headers': self.session.state.headers,
                'tokens': self.session.state.tokens,
                'variables': self.session.state.variables,
            },
            'requests': [
                {
                    'method': r.method.value,
                    'url': r.url,
                    'headers': r.headers,
                    'body': r.body,
                    'timestamp': r.timestamp.isoformat(),
                    'response_status': r.response_status,
                    'response_time': r.response_time,
                }
                for r in self.session.requests
            ]
        }

        with gzip.open(path.with_suffix('.sharingan.gz'), 'wt', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> 'SessionRecorder':
        """Load session from file."""
        path = Path(filepath)

        with gzip.open(path, 'rt', encoding='utf-8') as f:
            data = json.load(f)

        recorder = cls(data['name'], data['target_domain'])
        recorder.session.session_id = data['session_id']
        recorder.session.created_at = datetime.fromisoformat(data['created_at'])
        recorder.session.description = data.get('description', '')
        recorder.session.tags = data.get('tags', [])

        state = data.get('state', {})
        recorder.session.state.cookies = state.get('cookies', {})
        recorder.session.state.headers = state.get('headers', {})
        recorder.session.state.tokens = state.get('tokens', {})
        recorder.session.state.variables = state.get('variables', {})

        for req_data in data.get('requests', []):
            recorder.session.requests.append(RecordedRequest(
                method=RequestMethod(req_data['method']),
                url=req_data['url'],
                headers=req_data['headers'],
                body=req_data.get('body'),
                timestamp=datetime.fromisoformat(req_data['timestamp']),
                response_status=req_data.get('response_status'),
                response_time=req_data.get('response_time'),
            ))

        return recorder


class SessionPlayer:
    """
    Replay recorded sessions.

    Features:
    - Replay requests with timing
    - Token refresh handling
    - Variable substitution
    """

    def __init__(self, session: Session):
        """
        Initialize session player.

        Args:
            session: Session to replay
        """
        self.session = session
        self.current_state = SessionState(
            cookies=session.state.cookies.copy(),
            headers=session.state.headers.copy(),
            tokens=session.state.tokens.copy(),
            variables=session.state.variables.copy()
        )
        self._on_request: Optional[Callable] = None
        self._on_response: Optional[Callable] = None

    def on_request(self, handler: Callable[[RecordedRequest], Optional[RecordedRequest]]):
        """Set request interceptor."""
        self._on_request = handler

    def on_response(self, handler: Callable[[RecordedRequest, Any], None]):
        """Set response handler."""
        self._on_response = handler

    def replay(self, requests: List[RecordedRequest] = None,
               delay_factor: float = 1.0,
               timeout: int = 30) -> List[Dict[str, Any]]:
        """
        Replay requests from session.

        Args:
            requests: Specific requests to replay (all if None)
            delay_factor: Multiply original delays by this factor
            timeout: Request timeout

        Returns:
            List of response data
        """
        to_replay = requests or self.session.requests
        results = []

        for i, request in enumerate(to_replay):
            # Apply interceptor
            if self._on_request:
                modified = self._on_request(request)
                if modified:
                    request = modified

            # Prepare request
            url = self._substitute_variables(request.url)
            headers = self._prepare_headers(request.headers)
            body = self._substitute_variables(request.body) if request.body else None

            # Execute request
            start_time = time.time()
            try:
                result = self._execute_request(
                    request.method.value,
                    url,
                    headers,
                    body,
                    timeout
                )
                result['success'] = True
                result['response_time'] = time.time() - start_time

                # Update state from response
                self._update_state(result)

            except Exception as e:
                result = {
                    'success': False,
                    'error': str(e),
                    'response_time': time.time() - start_time
                }

            result['request_index'] = i
            result['original_url'] = request.url
            results.append(result)

            # Response handler
            if self._on_response:
                self._on_response(request, result)

            # Delay between requests
            if i < len(to_replay) - 1:
                if request.response_time:
                    delay = request.response_time * delay_factor
                else:
                    delay = 0.5 * delay_factor
                time.sleep(min(delay, 5.0))  # Cap at 5 seconds

        return results

    def _prepare_headers(self, original_headers: Dict[str, str]) -> Dict[str, str]:
        """Prepare headers with current state."""
        headers = original_headers.copy()

        # Add session headers
        headers.update(self.current_state.headers)

        # Add cookies
        if self.current_state.cookies:
            cookie_str = '; '.join(
                f"{k}={v}" for k, v in self.current_state.cookies.items()
            )
            headers['Cookie'] = cookie_str

        # Add auth tokens
        if 'jwt' in self.current_state.tokens:
            headers['Authorization'] = f"Bearer {self.current_state.tokens['jwt']}"

        return headers

    def _substitute_variables(self, text: Optional[str]) -> Optional[str]:
        """Substitute variables in text."""
        if not text:
            return text

        result = text
        for name, value in self.current_state.variables.items():
            result = result.replace(f"${{{name}}}", value)
            result = result.replace(f"{{${name}}}", value)

        for name, value in self.current_state.tokens.items():
            result = result.replace(f"${{token:{name}}}", value)

        return result

    def _execute_request(self, method: str, url: str,
                        headers: Dict[str, str],
                        body: Optional[str],
                        timeout: int) -> Dict[str, Any]:
        """Execute HTTP request."""
        data = body.encode('utf-8') if body else None

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'body': response.read().decode('utf-8', errors='replace'),
                    'url': response.url,
                }
        except urllib.error.HTTPError as e:
            return {
                'status': e.code,
                'headers': dict(e.headers) if e.headers else {},
                'body': e.read().decode('utf-8', errors='replace') if e.fp else '',
                'url': url,
            }

    def _update_state(self, response: Dict[str, Any]):
        """Update session state from response."""
        headers = response.get('headers', {})
        body = response.get('body', '')

        # Extract cookies
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            for cookie in set_cookie.split(','):
                parts = cookie.split(';')[0].strip()
                if '=' in parts:
                    name, value = parts.split('=', 1)
                    self.current_state.cookies[name.strip()] = value.strip()

        # Extract tokens from body
        import re
        for token_type, patterns in SessionRecorder.TOKEN_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    self.current_state.tokens[token_type] = matches[0]

    def get_auth_requests(self) -> List[RecordedRequest]:
        """Get authentication-related requests."""
        auth_keywords = ['login', 'auth', 'signin', 'token', 'oauth', 'session']
        return [
            r for r in self.session.requests
            if any(kw in r.url.lower() for kw in auth_keywords)
        ]


class SessionManager:
    """
    Manage multiple sessions.
    """

    def __init__(self, sessions_dir: str = ".sharingan_sessions"):
        """
        Initialize session manager.

        Args:
            sessions_dir: Directory to store sessions
        """
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(exist_ok=True)
        self.sessions: Dict[str, Session] = {}

    def create_session(self, name: str, target_domain: str) -> SessionRecorder:
        """Create a new session."""
        recorder = SessionRecorder(name, target_domain)
        self.sessions[recorder.session.session_id] = recorder.session
        return recorder

    def save_session(self, recorder: SessionRecorder):
        """Save a session to disk."""
        filepath = self.sessions_dir / f"{recorder.session.session_id}.sharingan.gz"
        recorder.save(str(filepath))
        self.sessions[recorder.session.session_id] = recorder.session

    def load_session(self, session_id: str) -> Optional[SessionRecorder]:
        """Load a session from disk."""
        filepath = self.sessions_dir / f"{session_id}.sharingan.gz"
        if filepath.exists():
            recorder = SessionRecorder.load(str(filepath))
            self.sessions[session_id] = recorder.session
            return recorder
        return None

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all saved sessions."""
        sessions = []
        for filepath in self.sessions_dir.glob("*.sharingan.gz"):
            try:
                recorder = SessionRecorder.load(str(filepath))
                sessions.append({
                    'session_id': recorder.session.session_id,
                    'name': recorder.session.name,
                    'target_domain': recorder.session.target_domain,
                    'created_at': recorder.session.created_at.isoformat(),
                    'requests_count': len(recorder.session.requests),
                    'tags': recorder.session.tags,
                })
            except Exception:
                continue
        return sessions

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        filepath = self.sessions_dir / f"{session_id}.sharingan.gz"
        if filepath.exists():
            filepath.unlink()
            self.sessions.pop(session_id, None)
            return True
        return False
