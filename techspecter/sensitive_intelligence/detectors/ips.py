"""IP address detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b",
)
_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
)


class IpDetector(BaseSensitiveDetector):
    """Detect IPv4 and IPv6 addresses."""

    detector_id = "ip-detector"
    finding_type = FindingType.IP

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find IP addresses."""
        matches = self._scan_patterns(
            content,
            (("ipv4", _IPV4, 82.0, SeverityLevel.MEDIUM),),
        )
        matches.extend(
            self._scan_patterns(
                content,
                (("ipv6", _IPV6, 85.0, SeverityLevel.MEDIUM),),
            ),
        )
        return matches
