"""Convert JavaScript findings into Evidence objects."""

from __future__ import annotations

from datetime import UTC, datetime

from techspecter.fingerprinting.evidence.models import Evidence, EvidenceSource, EvidenceType
from techspecter.fingerprinting.javascript.models import ExtractionFinding, JavaScriptResource


def _source_for_category(category: str) -> EvidenceSource:
    """Map finding category to evidence source."""
    mapping = {
        "bundle": EvidenceSource.BUNDLE,
        "package": EvidenceSource.PACKAGE,
        "manifest": EvidenceSource.BUNDLE,
        "sourcemap": EvidenceSource.JAVASCRIPT,
    }
    return mapping.get(category, EvidenceSource.JAVASCRIPT)


def build_evidence(
    *,
    findings: tuple[ExtractionFinding, ...],
    resource: JavaScriptResource,
    collector: str,
    timestamp: datetime | None = None,
) -> tuple[Evidence, ...]:
    """Convert extraction findings into strongly typed Evidence objects."""
    ts = timestamp or datetime.now(UTC)
    items: list[Evidence] = []
    for finding in findings:
        items.append(
            Evidence(
                source=_source_for_category(finding.category),
                evidence_type=EvidenceType(finding.evidence_type),
                collector=collector,
                url=resource.url,
                file=resource.filename,
                matched_value=finding.matched_value,
                matched_pattern=finding.matched_pattern,
                line_number=finding.line_number,
                category=finding.category,
                reason=finding.reason,
                timestamp=ts,
                metadata=dict(finding.metadata),
            ),
        )
    return tuple(items)


def build_script_content_evidence(
    *,
    resource: JavaScriptResource,
    collector: str,
    timestamp: datetime | None = None,
    extra_metadata: dict[str, object] | None = None,
) -> Evidence:
    """Emit baseline script content availability evidence."""
    ts = timestamp or datetime.now(UTC)
    metadata: dict[str, object] = {
        "content_length": resource.content_length,
        "is_minified": resource.is_minified,
        "parse_strategy": resource.parse_strategy.value,
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    return Evidence(
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.SCRIPT_CONTENT,
        collector=collector,
        url=resource.url,
        file=resource.filename,
        matched_value=str(resource.content_length),
        category="javascript",
        reason="JavaScript resource analyzed by intelligence engine",
        timestamp=ts,
        metadata=metadata,
    )


def build_source_map_reference_evidence(
    *,
    resource: JavaScriptResource,
    source_map_url: str,
    collector: str,
    timestamp: datetime | None = None,
) -> Evidence:
    """Emit source map reference evidence."""
    ts = timestamp or datetime.now(UTC)
    return Evidence(
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.SOURCE_MAP,
        collector=collector,
        url=resource.url,
        file=resource.filename,
        matched_value=source_map_url,
        category="javascript",
        reason="Source map reference detected in JavaScript resource",
        timestamp=ts,
    )
