"""Weighted version source priorities for candidate ranking."""

from __future__ import annotations

from techspecter.fingerprinting.evidence.models import EvidenceType

VERSION_SOURCE_PRIORITIES: dict[str, float] = {
    "package": 100.0,
    "package_metadata": 100.0,
    "runtime": 95.0,
    "version_candidate": 90.0,
    "manifest": 90.0,
    "build_metadata": 85.0,
    "metadata": 85.0,
    "sourcemap": 80.0,
    "source_map": 80.0,
    "banner": 75.0,
    "comment": 65.0,
    "content": 55.0,
    "bundle": 55.0,
    "inline": 50.0,
    "global": 50.0,
    "minified": 45.0,
    "filename": 40.0,
    "regex": 20.0,
    "unknown": 15.0,
}

_EVIDENCE_TYPE_SOURCES: dict[str, str] = {
    EvidenceType.PACKAGE_REFERENCE.value: "package",
    EvidenceType.PACKAGE_MARKER.value: "package",
    EvidenceType.RUNTIME_PATTERN.value: "runtime",
    EvidenceType.MANIFEST.value: "manifest",
    EvidenceType.METADATA.value: "metadata",
    EvidenceType.BUNDLE_RUNTIME.value: "build_metadata",
    EvidenceType.BUNDLE_MARKER.value: "build_metadata",
    EvidenceType.SOURCE_MAP_METADATA.value: "sourcemap",
    EvidenceType.SOURCE_MAP.value: "sourcemap",
    EvidenceType.BANNER.value: "banner",
    EvidenceType.SCRIPT_CONTENT.value: "comment",
    EvidenceType.STRING_LITERAL.value: "comment",
    EvidenceType.FILENAME.value: "filename",
    EvidenceType.VERSION_CANDIDATE.value: "version_candidate",
    EvidenceType.HTTP_HEADER.value: "metadata",
    EvidenceType.HTTP_METADATA.value: "metadata",
}


def priority_for_source(source: str) -> float:
    """Return configured priority weight for a version source label."""
    normalized = source.lower().strip()
    return VERSION_SOURCE_PRIORITIES.get(normalized, 30.0)


def source_from_evidence_type(evidence_type: str) -> str:
    """Map evidence type to a version source category."""
    return _EVIDENCE_TYPE_SOURCES.get(evidence_type, "content")
