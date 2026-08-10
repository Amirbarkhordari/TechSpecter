"""CSS technology-marker evidence extraction."""

from __future__ import annotations

import re
from dataclasses import dataclass

from techspecter.fingerprinting.evidence.models import EvidenceType

# Strong structural CSS markers only — never generic class names alone.
_BOOTSTRAP_BANNER = re.compile(
    r"/\*!?\s*Bootstrap\s+v?([\d.]+)",
    re.IGNORECASE,
)
_BOOTSTRAP_ASSET = re.compile(
    r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)",
    re.IGNORECASE,
)
_TAILWIND_DIRECTIVE = re.compile(
    r"@tailwind\s+(?:base|components|utilities|screens)\b",
    re.IGNORECASE,
)
_TAILWIND_VAR = re.compile(r"--tw-[a-z0-9-]+\s*:")
_TAILWIND_BANNER = re.compile(
    r"/\*!?\s*tailwindcss\s+v?([\d.]+)",
    re.IGNORECASE,
)
_SOURCE_PACKAGE = re.compile(
    r"(?:node_modules[/\\]|@import\s+['\"](~?/?)?)((?:@[\w-]+/)?[\w.-]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class CssFinding:
    """Structured CSS evidence finding prior to Evidence wrapping."""

    evidence_type: str
    matched_value: str
    matched_pattern: str
    reason: str
    metadata: dict[str, object]
    confidence_hint: float = 80.0


def extract_css_findings(content: str, *, filename: str = "") -> tuple[CssFinding, ...]:
    """Extract strong CSS technology markers from stylesheet content."""
    findings: list[CssFinding] = []
    seen: set[str] = set()

    def _add(finding: CssFinding) -> None:
        key = f"{finding.metadata.get('css_family')}:{finding.matched_value}"
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    match = _BOOTSTRAP_BANNER.search(content)
    if match is not None:
        version = match.group(1)
        _add(
            CssFinding(
                evidence_type=EvidenceType.CSS_MARKER.value,
                matched_value=match.group(0)[:80],
                matched_pattern=_BOOTSTRAP_BANNER.pattern,
                reason="Bootstrap CSS banner comment",
                metadata={
                    "css_family": "bootstrap",
                    "kind": "banner",
                    "version": version,
                },
                confidence_hint=90.0,
            ),
        )

    asset_match = _BOOTSTRAP_ASSET.search(content) or _BOOTSTRAP_ASSET.search(filename)
    if asset_match is not None:
        _add(
            CssFinding(
                evidence_type=EvidenceType.CSS_MARKER.value,
                matched_value=asset_match.group(0),
                matched_pattern=_BOOTSTRAP_ASSET.pattern,
                reason="Bootstrap stylesheet asset reference",
                metadata={"css_family": "bootstrap", "kind": "asset"},
                confidence_hint=85.0,
            ),
        )

    for match in _TAILWIND_DIRECTIVE.finditer(content):
        _add(
            CssFinding(
                evidence_type=EvidenceType.CSS_MARKER.value,
                matched_value=match.group(0),
                matched_pattern=_TAILWIND_DIRECTIVE.pattern,
                reason="Tailwind CSS @tailwind directive",
                metadata={"css_family": "tailwindcss", "kind": "directive"},
                confidence_hint=90.0,
            ),
        )

    tw_vars = _TAILWIND_VAR.findall(content)
    if len(tw_vars) >= 3:
        _add(
            CssFinding(
                evidence_type=EvidenceType.CSS_MARKER.value,
                matched_value="--tw-*",
                matched_pattern=_TAILWIND_VAR.pattern,
                reason="Multiple Tailwind CSS custom properties",
                metadata={
                    "css_family": "tailwindcss",
                    "kind": "css_variables",
                    "count": len(tw_vars),
                },
                confidence_hint=80.0,
            ),
        )

    match = _TAILWIND_BANNER.search(content)
    if match is not None:
        _add(
            CssFinding(
                evidence_type=EvidenceType.CSS_MARKER.value,
                matched_value=match.group(0)[:80],
                matched_pattern=_TAILWIND_BANNER.pattern,
                reason="Tailwind CSS banner comment",
                metadata={
                    "css_family": "tailwindcss",
                    "kind": "banner",
                    "version": match.group(1),
                },
                confidence_hint=90.0,
            ),
        )

    for match in _SOURCE_PACKAGE.finditer(content):
        package = match.group(2)
        if not package:
            continue
        lowered = package.lower()
        if lowered in {"bootstrap", "tailwindcss", "tailwind"}:
            _add(
                CssFinding(
                    evidence_type=EvidenceType.CSS_MARKER.value,
                    matched_value=package,
                    matched_pattern=_SOURCE_PACKAGE.pattern,
                    reason="CSS package/source reference",
                    metadata={"css_family": lowered, "kind": "package_path", "package": package},
                    confidence_hint=75.0,
                ),
            )

    return tuple(findings)
