"""UUID and GUID detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
)
_GUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
)


class UuidDetector(BaseSensitiveDetector):
    """Detect UUID and GUID values."""

    detector_id = "uuid-detector"
    finding_type = FindingType.UUID

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find UUID/GUID strings."""
        matches = self._scan_patterns(
            content,
            (("uuid", _UUID, 90.0, SeverityLevel.LOW),),
        )
        matches.extend(
            self._scan_patterns(
                content,
                (("guid", _GUID, 88.0, SeverityLevel.LOW),),
            ),
        )
        return matches
