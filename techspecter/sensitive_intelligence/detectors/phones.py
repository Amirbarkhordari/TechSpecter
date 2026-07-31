"""Phone number detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_PHONE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?!\d)",
)


class PhoneDetector(BaseSensitiveDetector):
    """Detect phone numbers in textual assets."""

    detector_id = "phone-detector"
    finding_type = FindingType.PHONE

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find phone numbers."""
        return self._scan_patterns(
            content,
            (("phone", _PHONE, 70.0, SeverityLevel.LOW),),
        )
