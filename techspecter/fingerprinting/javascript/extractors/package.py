"""Package intelligence extraction."""

from __future__ import annotations

import json
import re

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.extractors.patterns import (
    COPYRIGHT,
    GITHUB_URL,
    LICENSE_HEADER,
    NPM_PACKAGE,
)
from techspecter.fingerprinting.javascript.models import ExtractionFinding, ParsedScript

_NODE_MODULES = re.compile(r"node_modules/(@?[\w.-]+(?:/[\w.-]+)?)")
_PACKAGE_JSON = re.compile(
    r"""['"]name['"]\s*:\s*['"](@?[\w./-]+)['"].*?['"]version['"]\s*:\s*['"]([^'"]+)['"]""",
    re.DOTALL,
)
_MODULE_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\brequire\s*\(\s*['\"]"), "CommonJS require call"),
    (re.compile(r"\bimport\s+.+\s+from\s+['\"]"), "ES module import"),
    (
        re.compile(r"\bexport\s+(?:default\s+)?(?:function|class|const|let|var)\b"),
        "ES module export",
    ),
    (re.compile(r"__webpack_require__"), "Webpack module loader"),
    (re.compile(r"System\.register\s*\("), "SystemJS module registration"),
)


def extract_package_findings(
    parsed: ParsedScript,
    *,
    content: str,
) -> tuple[ExtractionFinding, ...]:
    """Extract package and module system evidence supported by file content."""
    findings: list[ExtractionFinding] = []
    seen: set[str] = set()

    for pattern, reason in _MODULE_MARKERS:
        match = pattern.search(content)
        if match is None:
            continue
        value = match.group(0)
        if value in seen:
            continue
        seen.add(value)
        findings.append(
            ExtractionFinding(
                category="package",
                evidence_type=EvidenceType.PACKAGE_MARKER.value,
                matched_value=value,
                matched_pattern=pattern.pattern,
                reason=reason,
            ),
        )

    for match in _NODE_MODULES.finditer(content):
        package_name = match.group(1)
        if package_name in seen:
            continue
        seen.add(package_name)
        findings.append(
            ExtractionFinding(
                category="package",
                evidence_type=EvidenceType.PACKAGE_REFERENCE.value,
                matched_value=package_name,
                matched_pattern=_NODE_MODULES.pattern,
                reason="node_modules package path reference observed",
            ),
        )

    for match in _PACKAGE_JSON.finditer(content):
        package_name = match.group(1)
        version = match.group(2)
        findings.append(
            ExtractionFinding(
                category="package",
                evidence_type=EvidenceType.PACKAGE_REFERENCE.value,
                matched_value=package_name,
                matched_pattern=_PACKAGE_JSON.pattern,
                reason="Embedded package.json fragment observed",
                metadata={"version": version},
            ),
        )
        findings.append(
            ExtractionFinding(
                category="version",
                evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                matched_value=version,
                reason="Version candidate from embedded package metadata",
                metadata={"origin": "package_json_fragment", "package": package_name},
            ),
        )

    for imp in parsed.imports:
        module = imp.module
        if not module or module in seen:
            continue
        seen.add(module)
        findings.append(
            ExtractionFinding(
                category="package",
                evidence_type=EvidenceType.PACKAGE_REFERENCE.value,
                matched_value=module,
                reason="Import target observed in JavaScript",
                line_number=imp.line_number,
                metadata={"kind": "import"},
            ),
        )

    for pattern, reason, meta in (
        (LICENSE_HEADER, "License header observed in JavaScript", {"kind": "license"}),
        (COPYRIGHT, "Copyright header observed in JavaScript", {"kind": "copyright"}),
        (GITHUB_URL, "Repository URL observed in JavaScript", {"kind": "github_url"}),
    ):
        match = pattern.search(content[:8192])
        if match is None:
            continue
        findings.append(
            ExtractionFinding(
                category="package",
                evidence_type=EvidenceType.METADATA.value,
                matched_value=match.group(0),
                matched_pattern=pattern.pattern,
                reason=reason,
                metadata=dict(meta),
            ),
        )

    if NPM_PACKAGE.search(content[:8192]):
        for match in NPM_PACKAGE.finditer(content[:8192]):
            value = match.group(0)
            if value in seen:
                continue
            seen.add(value)
            findings.append(
                ExtractionFinding(
                    category="package",
                    evidence_type=EvidenceType.PACKAGE_REFERENCE.value,
                    matched_value=value,
                    matched_pattern=NPM_PACKAGE.pattern,
                    reason="NPM package identifier observed",
                ),
            )

    findings.extend(_extract_manifest_json(content))
    return tuple(findings)


def _extract_manifest_json(content: str) -> list[ExtractionFinding]:
    """Extract evidence from embedded JSON manifest fragments when present."""
    findings: list[ExtractionFinding] = []
    for match in re.finditer(r"\{[^{}]{20,2000}\}", content[:100_000]):
        fragment = match.group(0)
        if "manifest" not in fragment.lower() and "routes" not in fragment.lower():
            continue
        try:
            payload = json.loads(fragment)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        findings.append(
            ExtractionFinding(
                category="manifest",
                evidence_type=EvidenceType.MANIFEST.value,
                matched_value=fragment[:256],
                reason="Embedded manifest JSON fragment parsed",
                metadata={"keys": list(payload.keys())[:20]},
            ),
        )
    return findings
