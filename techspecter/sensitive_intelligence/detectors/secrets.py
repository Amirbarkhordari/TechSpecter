"""Secret and API key detector."""

from __future__ import annotations

import math
import re
from collections import Counter

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], float, SeverityLevel], ...] = (
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"), 97.0, SeverityLevel.HIGH),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), 96.0, SeverityLevel.HIGH),
    (
        "firebase-config",
        re.compile(r"firebase[_-]?api[_-]?key\s*[:=]", re.I),
        90.0,
        SeverityLevel.HIGH,
    ),
    (
        "stripe-secret-key",
        re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{16,}"),
        97.0,
        SeverityLevel.HIGH,
    ),
    (
        "github-token",
        re.compile(r"(?:ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{20,}"),
        96.0,
        SeverityLevel.HIGH,
    ),
    ("gitlab-token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), 95.0, SeverityLevel.HIGH),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), 95.0, SeverityLevel.HIGH),
    (
        "discord-token",
        re.compile(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"),
        94.0,
        SeverityLevel.HIGH,
    ),
    ("twilio-key", re.compile(r"AC[a-f0-9]{32}"), 93.0, SeverityLevel.HIGH),
    (
        "openai-key",
        re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"),
        96.0,
        SeverityLevel.HIGH,
    ),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"), 96.0, SeverityLevel.HIGH),
    (
        "azure-key",
        re.compile(r"(?:AccountKey|SharedAccessSignature)=[A-Za-z0-9+/=]{20,}", re.I),
        92.0,
        SeverityLevel.HIGH,
    ),
    ("gcp-key", re.compile(r"\"type\"\s*:\s*\"service_account\""), 88.0, SeverityLevel.HIGH),
    (
        "jwt-token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        94.0,
        SeverityLevel.HIGH,
    ),
    (
        "bearer-token",
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}", re.I),
        90.0,
        SeverityLevel.HIGH,
    ),
    (
        "oauth-token",
        re.compile(r"(?:access_token|refresh_token)\s*[:=]\s*['\"][^'\"]{20,}['\"]", re.I),
        88.0,
        SeverityLevel.HIGH,
    ),
    (
        "session-token",
        re.compile(r"(?:session[_-]?token|sid)\s*[:=]\s*['\"][^'\"]{16,}['\"]", re.I),
        85.0,
        SeverityLevel.MEDIUM,
    ),
    (
        "csrf-token",
        re.compile(r"csrf[_-]?token\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I),
        80.0,
        SeverityLevel.MEDIUM,
    ),
    (
        "webhook-secret",
        re.compile(r"(?:whsec_|webhook[_-]?secret\s*[:=])", re.I),
        88.0,
        SeverityLevel.HIGH,
    ),
    (
        "hmac-secret",
        re.compile(r"hmac[_-]?secret\s*[:=]\s*['\"][^'\"]{16,}['\"]", re.I),
        87.0,
        SeverityLevel.HIGH,
    ),
    (
        "signing-key",
        re.compile(r"signing[_-]?key\s*[:=]\s*['\"][^'\"]{16,}['\"]", re.I),
        87.0,
        SeverityLevel.HIGH,
    ),
    (
        "encryption-key",
        re.compile(r"(?:encryption|encrypt)[_-]?key\s*[:=]\s*['\"][^'\"]{16,}['\"]", re.I),
        86.0,
        SeverityLevel.HIGH,
    ),
    (
        "api-key",
        re.compile(r"(?:api[_-]?key|x-api-key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.I),
        88.0,
        SeverityLevel.HIGH,
    ),
    (
        "generic-access-token",
        re.compile(r"(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][^'\"]{20,}['\"]", re.I),
        85.0,
        SeverityLevel.MEDIUM,
    ),
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        98.0,
        SeverityLevel.HIGH,
    ),
    (
        "pem-block",
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        98.0,
        SeverityLevel.HIGH,
    ),
    (
        "ssh-key",
        re.compile(r"ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}"),
        92.0,
        SeverityLevel.HIGH,
    ),
    ("rsa-key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), 98.0, SeverityLevel.HIGH),
)

_ENTROPY_PATTERN = re.compile(
    r"(?:token|secret|password|key)\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-]{32,})['\"]",
    re.I,
)
_BASE64_SECRET = re.compile(
    r"(?:secret|key|token)\s*[:=]\s*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]",
    re.I,
)


class SecretDetector(BaseSensitiveDetector):
    """Detect secrets, tokens, and private key material."""

    detector_id = "secret-detector"
    finding_type = FindingType.SECRET

    def __init__(self, *, entropy_threshold: float = 4.0) -> None:
        """Initialize with entropy threshold for generic secrets."""
        self._entropy_threshold = entropy_threshold

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find secret patterns and high-entropy assignments."""
        matches = self._scan_patterns(content, _SECRET_PATTERNS, redact=True)
        matches.extend(self._scan_entropy(content))
        matches.extend(self._scan_base64_secrets(content))
        return matches

    def _scan_entropy(self, content: str) -> list[DetectorMatch]:
        results: list[DetectorMatch] = []
        for match in _ENTROPY_PATTERN.finditer(content):
            token = match.group(1)
            if _shannon_entropy(token) < self._entropy_threshold:
                continue
            start = match.start()
            results.append(
                DetectorMatch(
                    finding_type=FindingType.SECRET,
                    subtype="high-entropy-secret",
                    matched_value="high-entropy-secret [redacted]",
                    matched_pattern=_ENTROPY_PATTERN.pattern,
                    confidence=75.0,
                    severity=SeverityLevel.MEDIUM,
                    evidence=match.group(0)[:80],
                    line_number=content.count("\n", 0, start) + 1,
                    byte_offset=start,
                ),
            )
        return results

    def _scan_base64_secrets(self, content: str) -> list[DetectorMatch]:
        results: list[DetectorMatch] = []
        for match in _BASE64_SECRET.finditer(content):
            token = match.group(1)
            if not token.endswith("=") and len(token) < 48:
                continue
            if _shannon_entropy(token) < self._entropy_threshold:
                continue
            start = match.start()
            results.append(
                DetectorMatch(
                    finding_type=FindingType.SECRET,
                    subtype="base64-secret",
                    matched_value="base64-secret [redacted]",
                    matched_pattern=_BASE64_SECRET.pattern,
                    confidence=78.0,
                    severity=SeverityLevel.MEDIUM,
                    evidence=match.group(0)[:80],
                    line_number=content.count("\n", 0, start) + 1,
                    byte_offset=start,
                ),
            )
        return results


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
