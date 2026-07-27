"""Shared helpers for passive artifact analyzers."""

from __future__ import annotations

from techspecter.analysis.models.evidence import Evidence
from techspecter.analysis.models.finding import Finding, FindingCategory, Severity
from techspecter.models.artifact import ArtifactReference


def build_artifact_finding(
    *,
    finding_id: str,
    analyzer_id: str,
    category: FindingCategory | str,
    title: str,
    description: str,
    severity: Severity = Severity.INFO,
    confidence: float = 100.0,
    recommendation: str | None = None,
    location: str | None = None,
    url: str | None = None,
    snippet: str | None = None,
    source: str = "passive-artifact",
    references: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> Finding:
    """Build a normalized artifact finding."""
    evidence: list[Evidence] = []
    if snippet is not None:
        evidence.append(Evidence(snippet=snippet, url=url))
    elif url is not None:
        evidence.append(Evidence(url=url))

    finding_metadata: dict[str, object] = {"source": source}
    if references:
        finding_metadata["references"] = references
    if metadata:
        finding_metadata.update(metadata)

    return Finding(
        id=finding_id,
        analyzer=analyzer_id,
        category=category,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        location=location,
        recommendation=recommendation,
        metadata=finding_metadata,
    )


def finding_from_reference(
    *,
    analyzer_id: str,
    reference: ArtifactReference,
    index: int,
    title_prefix: str,
    recommendation: str | None = None,
    severity: Severity = Severity.INFO,
    confidence: float = 90.0,
    category: FindingCategory | str = FindingCategory.SENSITIVE_ARTIFACT,
) -> Finding:
    """Build a finding from an artifact reference."""
    return build_artifact_finding(
        finding_id=f"{analyzer_id}:{reference.artifact_type}:{index}",
        analyzer_id=analyzer_id,
        category=category,
        title=f"{title_prefix}: {reference.artifact_type}",
        description=(
            f"Passive {reference.artifact_type} indicator detected in " f"{reference.source}."
        ),
        severity=severity,
        confidence=confidence,
        recommendation=recommendation,
        location=reference.location,
        url=reference.location,
        snippet=reference.snippet or reference.value[:200],
        metadata={
            "artifact_type": reference.artifact_type,
            "category": reference.category,
            "reference_source": reference.source,
            "value": reference.value,
            **reference.metadata,
        },
    )
