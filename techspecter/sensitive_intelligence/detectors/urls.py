"""URL detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_HTTP_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_INTERNAL_URL = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
    r"[^\s\"'<>]*",
    re.I,
)


class UrlDetector(BaseSensitiveDetector):
    """Detect external and internal URLs."""

    detector_id = "url-detector"
    finding_type = FindingType.URL

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find URLs."""
        matches = self._scan_patterns(
            content,
            (("external-url", _HTTP_URL, 75.0, SeverityLevel.LOW),),
        )
        matches.extend(
            self._scan_patterns(
                content,
                (("internal-url", _INTERNAL_URL, 88.0, SeverityLevel.MEDIUM),),
            ),
        )
        return matches
