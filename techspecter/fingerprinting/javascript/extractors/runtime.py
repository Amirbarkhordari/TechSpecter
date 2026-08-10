"""Runtime pattern extraction."""

from __future__ import annotations

import re

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.models import ExtractionFinding, ParsedScript

_RUNTIME_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("react", re.compile(r"\bReactDOM\.createRoot\b"), "ReactDOM.createRoot runtime call"),
    ("react", re.compile(r"\bhydrateRoot\b"), "hydrateRoot runtime call"),
    ("react", re.compile(r"\b__REACT_DEVTOOLS_GLOBAL_HOOK__\b"), "React DevTools global hook"),
    ("react", re.compile(r"\bcreateContext\b"), "createContext runtime call"),
    ("react", re.compile(r"\buseState\b"), "useState hook reference"),
    ("react", re.compile(r"\buseEffect\b"), "useEffect hook reference"),
    ("vue", re.compile(r"\bVue\.createApp\b"), "Vue.createApp runtime call"),
    ("vue", re.compile(r"\b__VUE__\b"), "Vue global runtime marker"),
    ("angular", re.compile(r"\bɵɵdefineComponent\b"), "Angular Ivy defineComponent runtime"),
    ("angular", re.compile(r"\bzone\.js\b"), "zone.js runtime reference"),
    ("solid", re.compile(r"\bcreateSignal\b"), "Solid createSignal runtime"),
    ("svelte", re.compile(r"\bSvelteComponent\b"), "Svelte runtime component reference"),
    ("astro", re.compile(r"\bAstro\b"), "Astro runtime reference"),
    ("next", re.compile(r"\b__NEXT_DATA__\b"), "Next.js runtime data marker"),
    ("nuxt", re.compile(r"\b__NUXT__\b"), "Nuxt runtime data marker"),
)


def extract_runtime_findings(
    parsed: ParsedScript,
    *,
    content: str,
) -> tuple[ExtractionFinding, ...]:
    """Extract runtime API evidence without technology detection."""
    findings: list[ExtractionFinding] = []
    seen: set[str] = set()

    for runtime, pattern, reason in _RUNTIME_PATTERNS:
        match = pattern.search(content)
        if match is None:
            continue
        key = match.group(0)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            ExtractionFinding(
                category="runtime",
                evidence_type=EvidenceType.RUNTIME_PATTERN.value,
                matched_value=key,
                matched_pattern=pattern.pattern,
                reason=reason,
                metadata={"runtime_family": runtime},
            ),
        )

    for identifier in parsed.identifiers:
        for runtime, pattern, reason in _RUNTIME_PATTERNS:
            if pattern.search(identifier) is None:
                continue
            if identifier in seen:
                continue
            seen.add(identifier)
            findings.append(
                ExtractionFinding(
                    category="runtime",
                    evidence_type=EvidenceType.RUNTIME_PATTERN.value,
                    matched_value=identifier,
                    matched_pattern=pattern.pattern,
                    reason=reason,
                    metadata={"runtime_family": runtime},
                ),
            )

    return tuple(findings)
