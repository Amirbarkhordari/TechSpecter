"""Source map evidence generation."""

from __future__ import annotations

import re

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.models import ExtractionFinding
from techspecter.fingerprinting.javascript.sourcemap.parser import SourceMapParseResult

_NODE_MODULES = re.compile(r"node_modules/(@?[\w./-]+)")
_PACKAGE_VERSION_PATH = re.compile(
    r"node_modules/(?:@?[\w.-]+/[\w.-]+|@?[\w.-]+)@(\d{1,4}(?:\.\d{1,4}){0,3}(?:[-+][\w.-]+)?)"
)
_PACKAGE_PATH = re.compile(r"(?:src|packages|lib)/[\w./-]+")
_VERSION_IN_NAME = re.compile(
    r"(?:react|vue|angular|next|webpack|vite|bootstrap|tailwind)[^0-9@/]*@?"
    r"(\d{1,4}(?:\.\d{1,4}){0,3}(?:[-+][\w.-]+)?)",
    re.IGNORECASE,
)
_PACKAGE_JSON_VERSION = re.compile(r'"version"\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"')


def extract_source_map_findings(
    *,
    source_map_url: str,
    parsed: SourceMapParseResult,
) -> tuple[ExtractionFinding, ...]:
    """Generate evidence from parsed source map metadata."""
    findings: list[ExtractionFinding] = []

    if parsed.file:
        findings.append(
            ExtractionFinding(
                category="sourcemap",
                evidence_type=EvidenceType.SOURCE_MAP_METADATA.value,
                matched_value=parsed.file,
                reason="Original file name from source map",
                metadata={"source_map_url": source_map_url, "kind": "file"},
            ),
        )
        for match in _VERSION_IN_NAME.finditer(parsed.file):
            findings.append(
                ExtractionFinding(
                    category="sourcemap",
                    evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                    matched_value=match.group(1),
                    reason="Version hint from source map file name",
                    metadata={"source_map_url": source_map_url, "origin": "sourcemap"},
                ),
            )

    seen_packages: set[str] = set()
    seen_versions: set[str] = set()
    for source in parsed.sources[:500]:
        findings.append(
            ExtractionFinding(
                category="sourcemap",
                evidence_type=EvidenceType.SOURCE_MAP_METADATA.value,
                matched_value=source,
                reason="Original source path from source map",
                metadata={"source_map_url": source_map_url, "kind": "source_path"},
            ),
        )
        for match in _PACKAGE_VERSION_PATH.finditer(source):
            version = match.group(1)
            if version not in seen_versions:
                seen_versions.add(version)
                findings.append(
                    ExtractionFinding(
                        category="sourcemap",
                        evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                        matched_value=version,
                        reason="Version from node_modules path in source map",
                        metadata={"source_map_url": source_map_url, "origin": "sourcemap"},
                    ),
                )
        for match in _VERSION_IN_NAME.finditer(source):
            version = match.group(1)
            if version not in seen_versions:
                seen_versions.add(version)
                findings.append(
                    ExtractionFinding(
                        category="sourcemap",
                        evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                        matched_value=version,
                        reason="Version hint from source map source path",
                        metadata={"source_map_url": source_map_url, "origin": "sourcemap"},
                    ),
                )
        module_match = _NODE_MODULES.search(source)
        if module_match is not None:
            package_name = module_match.group(1)
            if package_name not in seen_packages:
                seen_packages.add(package_name)
                findings.append(
                    ExtractionFinding(
                        category="sourcemap",
                        evidence_type=EvidenceType.PACKAGE_REFERENCE.value,
                        matched_value=package_name,
                        reason="Package path inferred from source map source",
                        metadata={"source_map_url": source_map_url},
                    ),
                )
        if _PACKAGE_PATH.search(source):
            findings.append(
                ExtractionFinding(
                    category="sourcemap",
                    evidence_type=EvidenceType.METADATA.value,
                    matched_value=source,
                    reason="Repository or package path hint from source map",
                    metadata={"source_map_url": source_map_url, "kind": "path_hint"},
                ),
            )

    for index, content in enumerate(parsed.sources_content[:20]):
        if not content:
            continue
        snippet = content[:512]
        findings.append(
            ExtractionFinding(
                category="sourcemap",
                evidence_type=EvidenceType.SOURCE_MAP_METADATA.value,
                matched_value=snippet,
                reason="Embedded source content metadata from source map",
                metadata={"source_map_url": source_map_url, "index": index},
            ),
        )
        pkg_match = _PACKAGE_JSON_VERSION.search(content[:4096])
        if pkg_match is not None:
            version = pkg_match.group(1)
            if version not in seen_versions:
                seen_versions.add(version)
                findings.append(
                    ExtractionFinding(
                        category="sourcemap",
                        evidence_type=EvidenceType.VERSION_CANDIDATE.value,
                        matched_value=version,
                        reason="Version from embedded package.json in source map",
                        metadata={
                            "source_map_url": source_map_url,
                            "origin": "package",
                            "kind": "package_json",
                        },
                    ),
                )

    return tuple(findings)
