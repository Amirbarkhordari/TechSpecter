"""Source map evidence generation."""

from __future__ import annotations

import re

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.models import ExtractionFinding
from techspecter.fingerprinting.javascript.sourcemap.parser import SourceMapParseResult

_NODE_MODULES = re.compile(r"node_modules/(@?[\w./-]+)")
_PACKAGE_PATH = re.compile(r"(?:src|packages|lib)/[\w./-]+")


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

    seen_packages: set[str] = set()
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
        match = _NODE_MODULES.search(source)
        if match is not None:
            package_name = match.group(1)
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

    return tuple(findings)
