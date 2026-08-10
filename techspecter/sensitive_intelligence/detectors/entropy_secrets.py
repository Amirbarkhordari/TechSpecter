"""High-entropy and base64 secret heuristics."""

from __future__ import annotations

import math
import re
from collections import Counter

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingCategory, FindingType, SeverityLevel

_ENTROPY_PATTERN = re.compile(
    r"(?:token|secret|password|key)\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-]{32,})['\"]",
    re.I,
)
_BASE64_SECRET = re.compile(
    r"(?:secret|key|token)\s*[:=]\s*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]",
    re.I,
)


class EntropySecretDetector(BaseSensitiveDetector):
    """Detect high-entropy secret assignments not covered by explicit rules."""

    detector_id = "entropy-secret-detector"
    finding_type = FindingType.SECRET

    def __init__(self, *, entropy_threshold: float = 4.0) -> None:
        self._entropy_threshold = entropy_threshold

    def detect(self, content: str) -> list[DetectorMatch]:
        matches = self._scan_entropy(content)
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
                    category=FindingCategory.SECRETS,
                    rule_id="high-entropy-secret",
                    rule_name="High Entropy Secret",
                    description="High-entropy secret-like assignment detected.",
                    recommendation="Verify whether the value is a secret and move it server-side.",
                    raw_value=token,
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
                    category=FindingCategory.SECRETS,
                    rule_id="base64-secret",
                    rule_name="Base64 Secret",
                    description="Base64-encoded secret-like assignment detected.",
                    recommendation=(
                        "Inspect the encoded value and rotate if it contains credentials."
                    ),
                    raw_value=token,
                ),
            )
        return results


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy for a string value."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _shannon_entropy(value: str) -> float:
    return shannon_entropy(value)
