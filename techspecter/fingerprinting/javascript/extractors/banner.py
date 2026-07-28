"""Banner and header analysis."""

from __future__ import annotations

import re

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.extractors.patterns import (
    COPYRIGHT,
    GENERATED_BY,
    GITHUB_URL,
    LICENSE_HEADER,
    VERSION_CANDIDATE,
)
from techspecter.fingerprinting.javascript.models import ExtractionFinding, JavaScriptResource
from techspecter.fingerprinting.javascript.normalizer import extract_banner_comments

_FRAMEWORK_BANNER = re.compile(
    r"(?:React|Vue\.js|Angular|Svelte|Next\.js|Nuxt|SolidJS|Astro|webpack|Vite|Rollup|Parcel)",
    re.IGNORECASE,
)


def extract_banner_findings(resource: JavaScriptResource) -> tuple[ExtractionFinding, ...]:
    """Analyze file headers and preserved banner comments."""
    banner = extract_banner_comments(resource.content) or resource.content[:4096]
    findings: list[ExtractionFinding] = []

    for pattern, reason, meta in (
        (LICENSE_HEADER, "License header observed in JavaScript banner", {"kind": "license"}),
        (COPYRIGHT, "Copyright header observed in JavaScript banner", {"kind": "copyright"}),
        (GENERATED_BY, "Generator marker observed in JavaScript banner", {"kind": "generated_by"}),
        (GITHUB_URL, "Repository URL observed in JavaScript banner", {"kind": "github_url"}),
        (_FRAMEWORK_BANNER, "Framework name observed in JavaScript banner", {"kind": "framework"}),
    ):
        match = pattern.search(banner)
        if match is None:
            continue
        findings.append(
            ExtractionFinding(
                category="banner",
                evidence_type=EvidenceType.BANNER.value,
                matched_value=match.group(0),
                matched_pattern=pattern.pattern,
                reason=reason,
                metadata=dict(meta),
            ),
        )

    for match in VERSION_CANDIDATE.finditer(banner):
        findings.append(
            ExtractionFinding(
                category="banner",
                evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                matched_value=match.group(1),
                matched_pattern=VERSION_CANDIDATE.pattern,
                reason="Version candidate observed in JavaScript banner",
                metadata={"origin": "banner"},
            ),
        )

    return tuple(findings)
