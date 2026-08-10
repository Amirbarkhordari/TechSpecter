"""Credential pair correlation for username/password findings."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.models import FindingCategory, FindingType, SeverityLevel

_USERNAME = re.compile(r"(?:username|user_name|login)\s*[:=]\s*['\"]([^'\"]{2,})['\"]", re.I)
_PASSWORD = re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]", re.I)
_MAX_LINE_DISTANCE = 8


def correlate_credential_pairs(content: str) -> list[DetectorMatch]:
    """Detect correlated username/password pairs within the same asset.

    Emits detector matches as evidence producers. Confirmation is deferred to the
    sensitive candidate validation spine (values must be sufficiently strong).
    """
    lines = content.splitlines()
    indexed: list[tuple[str, str, int]] = []
    for line_number, line in enumerate(lines, start=1):
        user_match = _USERNAME.search(line)
        if user_match:
            indexed.append(("username", user_match.group(1), line_number))
        pwd_match = _PASSWORD.search(line)
        if pwd_match:
            indexed.append(("password", pwd_match.group(1), line_number))

    matches: list[DetectorMatch] = []
    usernames = [item for item in indexed if item[0] == "username"]
    passwords = [item for item in indexed if item[0] == "password"]
    for _, user_value, user_line in usernames:
        for _, password_value, pwd_line in passwords:
            if abs(user_line - pwd_line) > _MAX_LINE_DISTANCE:
                continue
            start_line = min(user_line, pwd_line)
            end_line = max(user_line, pwd_line)
            evidence = "\n".join(lines[start_line - 1 : end_line])
            matches.append(
                DetectorMatch(
                    finding_type=FindingType.CREDENTIAL,
                    subtype="correlated-credentials",
                    matched_value="username/password pair [redacted]",
                    matched_pattern="username+password proximity",
                    confidence=94.0,
                    severity=SeverityLevel.CRITICAL,
                    evidence=evidence[:200],
                    line_number=start_line,
                    byte_offset=0,
                    column_number=1,
                    category=FindingCategory.CREDENTIALS,
                    rule_id="correlated-credentials",
                    rule_name="Correlated Credentials",
                    description="Username and password assignments found near each other.",
                    recommendation="Remove hardcoded credential pairs from client-side assets.",
                    raw_value=f"{user_value}\n{password_value}",
                ),
            )
            break
    return matches
