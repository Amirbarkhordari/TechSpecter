"""Version candidate extraction."""

from __future__ import annotations

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.extractors.patterns import (
    CALVER_CANDIDATE,
    VERSION_CANDIDATE,
)
from techspecter.fingerprinting.javascript.models import ExtractionFinding, JavaScriptResource

_MAX_CANDIDATES = 200


def extract_version_candidates(resource: JavaScriptResource) -> tuple[ExtractionFinding, ...]:
    """Extract version candidates without selecting a canonical version."""
    content = resource.content
    findings: list[ExtractionFinding] = []
    seen: set[str] = set()

    for pattern in (VERSION_CANDIDATE, CALVER_CANDIDATE):
        for match in pattern.finditer(content):
            candidate = match.group(1)
            if candidate in seen:
                continue
            seen.add(candidate)
            findings.append(
                ExtractionFinding(
                    category="version",
                    evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                    matched_value=candidate,
                    matched_pattern=pattern.pattern,
                    reason="Version candidate extracted from JavaScript content",
                ),
            )
            if len(findings) >= _MAX_CANDIDATES:
                return tuple(findings)

    return tuple(findings)
