"""Bundle intelligence extraction."""

from __future__ import annotations

import re

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.models import ExtractionFinding, JavaScriptResource

_BUNDLE_FILENAME = re.compile(
    r"(?i)(?:\.min\.js$|\.bundle\.js$|\.chunk\.js$|/chunk[-.]?\d+\.js$)",
)
_BUNDLE_RUNTIMES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "webpack",
        re.compile(r"__webpack_require__|webpackChunk|webpackJsonp"),
        "Webpack runtime marker",
    ),
    ("vite", re.compile(r"__vite__|import\.meta\.env"), "Vite runtime marker"),
    ("rollup", re.compile(r"rollupVersion|Rollup\b"), "Rollup runtime marker"),
    ("parcel", re.compile(r"parcelRequire|Parcel\b"), "Parcel runtime marker"),
    ("rspack", re.compile(r"__rspack_require__"), "Rspack runtime marker"),
    ("turbopack", re.compile(r"turbopack|__turbopack__"), "Turbopack runtime marker"),
)
_CHUNK_ID = re.compile(r"(?:chunkId|chunk\.id)\s*[:=]\s*['\"]?([\w-]+)")
_DYNAMIC_IMPORT = re.compile(r"import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
_MANIFEST = re.compile(
    r"(buildManifest|app-build-manifest|middleware-manifest|prerender-manifest|"
    r"routes-manifest|flight-manifest|vite\.manifest|__NUXT_MANIFEST__)",
    re.IGNORECASE,
)


def extract_bundle_findings(resource: JavaScriptResource) -> tuple[ExtractionFinding, ...]:
    """Extract bundle structure and bundler runtime evidence."""
    content = resource.content
    filename = resource.filename
    findings: list[ExtractionFinding] = []

    if _BUNDLE_FILENAME.search(filename):
        findings.append(
            ExtractionFinding(
                category="bundle",
                evidence_type=EvidenceType.BUNDLE_MARKER.value,
                matched_value=filename,
                matched_pattern=_BUNDLE_FILENAME.pattern,
                reason="Filename matches bundle/minified/chunk naming convention",
            ),
        )

    for bundler, pattern, reason in _BUNDLE_RUNTIMES:
        match = pattern.search(content)
        if match is None:
            continue
        findings.append(
            ExtractionFinding(
                category="bundle",
                evidence_type=EvidenceType.BUNDLE_RUNTIME.value,
                matched_value=match.group(0),
                matched_pattern=pattern.pattern,
                reason=reason,
                metadata={"bundler": bundler},
            ),
        )

    for match in _CHUNK_ID.finditer(content):
        findings.append(
            ExtractionFinding(
                category="bundle",
                evidence_type=EvidenceType.BUNDLE_MARKER.value,
                matched_value=match.group(1),
                matched_pattern=_CHUNK_ID.pattern,
                reason="Chunk identifier observed in bundle",
                metadata={"kind": "chunk_id"},
            ),
        )

    seen_imports: set[str] = set()
    for match in _DYNAMIC_IMPORT.finditer(content):
        value = match.group(1)
        if value in seen_imports:
            continue
        seen_imports.add(value)
        findings.append(
            ExtractionFinding(
                category="bundle",
                evidence_type=EvidenceType.IMPORT_EXPORT.value,
                matched_value=value,
                matched_pattern=_DYNAMIC_IMPORT.pattern,
                reason="Dynamic import target observed in bundle",
                metadata={"kind": "dynamic_import"},
            ),
        )

    for match in _MANIFEST.finditer(content):
        findings.append(
            ExtractionFinding(
                category="manifest",
                evidence_type=EvidenceType.MANIFEST.value,
                matched_value=match.group(1),
                matched_pattern=_MANIFEST.pattern,
                reason="Framework manifest reference observed",
            ),
        )

    return tuple(findings)
