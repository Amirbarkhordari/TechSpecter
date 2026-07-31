"""Username and developer identifier detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_USERNAME = re.compile(
    r"(?:username|user_name|developer|author|maintainer)\s*[:=]\s*['\"]([^'\"]{2,64})['\"]",
    re.I,
)
_APP_NAME = re.compile(
    r"(?:app(?:lication)?[_-]?name|product[_-]?name)\s*[:=]\s*['\"]([^'\"]{2,64})['\"]",
    re.I,
)
_ENV_NAME = re.compile(
    r"(?:NODE_ENV|APP_ENV|ENVIRONMENT|DEPLOY_ENV)\s*[:=]\s*['\"]([^'\"]{2,32})['\"]",
    re.I,
)


class UsernameDetector(BaseSensitiveDetector):
    """Detect usernames, application names, and environment names."""

    detector_id = "username-detector"
    finding_type = FindingType.USERNAME

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find exposed identity and environment markers."""
        matches = self._scan_patterns(
            content,
            (("username", _USERNAME, 72.0, SeverityLevel.LOW),),
        )
        matches.extend(
            self._scan_patterns(
                content,
                (("application-name", _APP_NAME, 68.0, SeverityLevel.LOW),),
                finding_type=FindingType.APPLICATION,
            ),
        )
        matches.extend(
            self._scan_patterns(
                content,
                (("environment-name", _ENV_NAME, 76.0, SeverityLevel.MEDIUM),),
                finding_type=FindingType.ENVIRONMENT,
            ),
        )
        return matches
