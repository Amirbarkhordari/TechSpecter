"""Credential and connection string detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str], float, SeverityLevel], ...] = (
    ("mongodb-uri", re.compile(r"mongodb(?:\+srv)?://[^\s\"']+", re.I), 95.0, SeverityLevel.HIGH),
    ("postgresql-uri", re.compile(r"postgres(?:ql)?://[^\s\"']+", re.I), 95.0, SeverityLevel.HIGH),
    ("mysql-uri", re.compile(r"mysql://[^\s\"']+", re.I), 95.0, SeverityLevel.HIGH),
    ("redis-uri", re.compile(r"redis://[^\s\"']+", re.I), 93.0, SeverityLevel.HIGH),
    ("ldap-credentials", re.compile(r"ldap://[^\s\"']+", re.I), 90.0, SeverityLevel.HIGH),
    ("smtp-credentials", re.compile(r"smtp://[^\s\"']+", re.I), 90.0, SeverityLevel.HIGH),
    ("ftp-credentials", re.compile(r"ftp://[^\s\"']+", re.I), 88.0, SeverityLevel.HIGH),
    ("basic-auth", re.compile(r"Basic\s+[A-Za-z0-9+/=]{8,}", re.I), 92.0, SeverityLevel.HIGH),
    (
        "username-field",
        re.compile(r"(?:username|user_name|login)\s*[:=]\s*['\"][^'\"]{2,}['\"]", re.I),
        70.0,
        SeverityLevel.LOW,
    ),
    (
        "password-field",
        re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]", re.I),
        92.0,
        SeverityLevel.HIGH,
    ),
    (
        "database-credentials",
        re.compile(r"(?:db_(?:user|pass|password|host)|database_url)\s*[:=]", re.I),
        88.0,
        SeverityLevel.HIGH,
    ),
    (
        "connection-string",
        re.compile(r"(?:connection[_-]?string|conn[_-]?str)\s*[:=]\s*['\"][^'\"]+['\"]", re.I),
        90.0,
        SeverityLevel.HIGH,
    ),
    (
        "env-variable",
        re.compile(r"(?:process\.env|import\.meta\.env)\.[A-Z0-9_]+"),
        75.0,
        SeverityLevel.MEDIUM,
    ),
    (
        "config-credentials",
        re.compile(r"(?:credentials|auth)\s*[:=]\s*\{", re.I),
        80.0,
        SeverityLevel.MEDIUM,
    ),
)


class CredentialDetector(BaseSensitiveDetector):
    """Detect credentials and connection strings."""

    detector_id = "credential-detector"
    finding_type = FindingType.CREDENTIAL

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find credential patterns."""
        return self._scan_patterns(content, _CREDENTIAL_PATTERNS, redact=True)
