"""Import and export extraction findings."""

from __future__ import annotations

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.models import ExtractionFinding, ParsedScript


def extract_import_export_findings(parsed: ParsedScript) -> tuple[ExtractionFinding, ...]:
    """Convert parsed imports and exports into evidence findings."""
    findings: list[ExtractionFinding] = []

    for imp in parsed.imports:
        findings.append(
            ExtractionFinding(
                category="ast",
                evidence_type=EvidenceType.IMPORT_EXPORT.value,
                matched_value=imp.module,
                reason="Import statement extracted from JavaScript",
                line_number=imp.line_number,
                metadata={"raw": imp.raw, "kind": "import"},
            ),
        )
        findings.append(
            ExtractionFinding(
                category="ast",
                evidence_type=EvidenceType.AST_EXTRACTION.value,
                matched_value=imp.raw,
                reason="Structured import extraction",
                line_number=imp.line_number,
                metadata={"kind": "import"},
            ),
        )

    for export in parsed.exports:
        findings.append(
            ExtractionFinding(
                category="ast",
                evidence_type=EvidenceType.IMPORT_EXPORT.value,
                matched_value=export.name or export.raw,
                reason="Export statement extracted from JavaScript",
                line_number=export.line_number,
                metadata={"raw": export.raw, "kind": "export"},
            ),
        )

    return tuple(findings)
