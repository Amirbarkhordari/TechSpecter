"""Domain and hostname detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.I,
)
_HOSTNAME = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|lan)\b",
    re.I,
)
_SUBDOMAIN = re.compile(
    r"\b(?:dev|staging|test|qa|uat|preview|sandbox)\.[a-z0-9.-]+\.[a-z]{2,}\b",
    re.I,
)


class DomainDetector(BaseSensitiveDetector):
    """Detect domains, hostnames, and subdomains."""

    detector_id = "domain-detector"
    finding_type = FindingType.DOMAIN

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find domain-like strings."""
        matches = self._scan_patterns(
            content,
            (("domain", _DOMAIN, 65.0, SeverityLevel.LOW),),
        )
        matches.extend(
            self._scan_patterns(
                content,
                (("hostname", _HOSTNAME, 80.0, SeverityLevel.MEDIUM),),
                finding_type=FindingType.HOSTNAME,
            ),
        )
        matches.extend(
            self._scan_patterns(
                content,
                (("subdomain", _SUBDOMAIN, 78.0, SeverityLevel.MEDIUM),),
            ),
        )
        return matches
