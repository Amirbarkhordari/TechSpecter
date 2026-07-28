"""Version candidate extraction."""

from __future__ import annotations

import re

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.extractors.patterns import (
    CALVER_CANDIDATE,
    VERSION_CANDIDATE,
)
from techspecter.fingerprinting.javascript.models import ExtractionFinding, JavaScriptResource

_MAX_CANDIDATES = 500

_TECH_VERSION_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "react",
        re.compile(r'React\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
        "runtime",
    ),
    (
        "react",
        re.compile(r"react(?:-dom)?@([\d.]+(?:[-+][\w.-]+)?)"),
        "package",
    ),
    (
        "vue",
        re.compile(r'Vue\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
        "runtime",
    ),
    (
        "angular",
        re.compile(r'ng\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
        "runtime",
    ),
    (
        "angular",
        re.compile(r"@angular/core@([\d.]+(?:[-+][\w.-]+)?)"),
        "package",
    ),
    (
        "nextjs",
        re.compile(r'"nextVersion"\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"'),
        "manifest",
    ),
    (
        "nextjs",
        re.compile(r"next@([\d.]+(?:[-+][\w.-]+)?)"),
        "package",
    ),
    (
        "nuxt",
        re.compile(r'"nuxt"\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"'),
        "manifest",
    ),
    (
        "webpack",
        re.compile(r"webpack[/\s]+([\d.]+(?:[-+][\w.-]+)?)"),
        "banner",
    ),
    (
        "vite",
        re.compile(r"vite[/\s@]+([\d.]+(?:[-+][\w.-]+)?)"),
        "banner",
    ),
    (
        "bootstrap",
        re.compile(r"Bootstrap\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
        "banner",
    ),
    (
        "tailwindcss",
        re.compile(r"tailwindcss[/\s@]+([\d.]+(?:[-+][\w.-]+)?)"),
        "package",
    ),
    (
        "wordpress",
        re.compile(r"WordPress\s+([\d.]+(?:[-+][\w.-]+)?)"),
        "banner",
    ),
    (
        "laravel",
        re.compile(r"Laravel\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
        "banner",
    ),
    (
        "django",
        re.compile(r"Django[/\s]+([\d.]+(?:[-+][\w.-]+)?)"),
        "banner",
    ),
)


def extract_version_candidates(resource: JavaScriptResource) -> tuple[ExtractionFinding, ...]:
    """Extract version candidates without selecting a canonical version."""
    content = resource.content
    findings: list[ExtractionFinding] = []
    seen: set[tuple[str, str]] = set()

    for tech_id, pattern, origin in _TECH_VERSION_PATTERNS:
        for match in pattern.finditer(content):
            candidate = match.group(1)
            key = (candidate, origin)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                ExtractionFinding(
                    category="version",
                    evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                    matched_value=candidate,
                    matched_pattern=pattern.pattern,
                    reason=f"Technology-specific version candidate ({tech_id})",
                    metadata={"origin": origin, "technology": tech_id},
                ),
            )
            if len(findings) >= _MAX_CANDIDATES:
                return tuple(findings)

    for pattern in (VERSION_CANDIDATE, CALVER_CANDIDATE):
        for match in pattern.finditer(content):
            candidate = match.group(1)
            key = (candidate, "content")
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                ExtractionFinding(
                    category="version",
                    evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                    matched_value=candidate,
                    matched_pattern=pattern.pattern,
                    reason="Version candidate extracted from JavaScript content",
                    metadata={"origin": "content"},
                ),
            )
            if len(findings) >= _MAX_CANDIDATES:
                return tuple(findings)

    return tuple(findings)
