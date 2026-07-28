"""String literal extraction."""

from __future__ import annotations

import re

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.extractors.patterns import (
    GITHUB_URL,
    LICENSE_HEADER,
    NPM_PACKAGE,
)
from techspecter.fingerprinting.javascript.models import ExtractionFinding, ParsedScript

_MEANINGFUL_STRING = re.compile(
    r"(?:react|vue|angular|svelte|webpack|vite|rollup|parcel|next|nuxt|solid|astro|"
    r"license|repository|version|node_modules|@|\.)",
    re.IGNORECASE,
)
_MIN_LENGTH = 3


def extract_string_findings(parsed: ParsedScript) -> tuple[ExtractionFinding, ...]:
    """Extract meaningful string literal evidence."""
    findings: list[ExtractionFinding] = []
    seen: set[str] = set()

    for literal in parsed.string_literals:
        value = literal.value.strip()
        if len(value) < _MIN_LENGTH or value in seen:
            continue
        if not _is_meaningful(value):
            continue
        seen.add(value)
        findings.append(
            ExtractionFinding(
                category="string",
                evidence_type=EvidenceType.STRING_LITERAL.value,
                matched_value=value,
                line_number=literal.line_number,
                reason="Meaningful string literal extracted from JavaScript",
            ),
        )
        if GITHUB_URL.search(value):
            findings.append(
                ExtractionFinding(
                    category="metadata",
                    evidence_type=EvidenceType.METADATA.value,
                    matched_value=value,
                    line_number=literal.line_number,
                    reason="GitHub repository URL observed in string literal",
                    metadata={"kind": "github_url"},
                ),
            )
        if NPM_PACKAGE.search(value):
            findings.append(
                ExtractionFinding(
                    category="package",
                    evidence_type=EvidenceType.PACKAGE_REFERENCE.value,
                    matched_value=value,
                    line_number=literal.line_number,
                    reason="NPM or node_modules reference observed in string literal",
                ),
            )
        if LICENSE_HEADER.search(value):
            findings.append(
                ExtractionFinding(
                    category="package",
                    evidence_type=EvidenceType.BANNER.value,
                    matched_value=value,
                    line_number=literal.line_number,
                    reason="License reference observed in string literal",
                    metadata={"kind": "license"},
                ),
            )

    return tuple(findings)


def _is_meaningful(value: str) -> bool:
    """Return whether a string literal is worth recording as evidence."""
    if value.startswith(("http://", "https://", "git+", "npm:", "node:")):
        return True
    if "/" in value or "@" in value or "." in value:
        return True
    return _MEANINGFUL_STRING.search(value) is not None
