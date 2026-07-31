"""Email address detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
)


class EmailDetector(BaseSensitiveDetector):
    """Detect email addresses in textual assets."""

    detector_id = "email-detector"
    finding_type = FindingType.EMAIL

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find email addresses."""
        return self._scan_patterns(
            content,
            (("email", _EMAIL, 85.0, SeverityLevel.MEDIUM),),
        )
