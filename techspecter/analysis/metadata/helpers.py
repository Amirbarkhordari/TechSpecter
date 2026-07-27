"""Shared helpers for passive metadata analyzers."""

from __future__ import annotations

from techspecter.analysis.models.evidence import Evidence
from techspecter.analysis.models.finding import Finding, FindingCategory, Severity
from techspecter.models.discovery import DiscoveryResult
from techspecter.models.metadata import MetadataDiscoveryObservation, WellKnownResourceObservation


def get_metadata_observation(
    discovery: DiscoveryResult,
) -> MetadataDiscoveryObservation | None:
    """Return metadata observation from a discovery result."""
    return discovery.metadata_observation


def build_metadata_finding(
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
    html_element: str | None = None,
    snippet: str | None = None,
    source: str = "passive-metadata",
    references: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> Finding:
    """Build a normalized metadata finding."""
    evidence: list[Evidence] = []
    if html_element is not None:
        evidence.append(Evidence(html_element=html_element, url=url, snippet=snippet))
    elif snippet is not None:
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


def find_well_known(
    observation: MetadataDiscoveryObservation,
    resource_type: str,
) -> list[WellKnownResourceObservation]:
    """Return well-known resources matching a resource type."""
    return [
        item for item in observation.well_known_resources if item.resource_type == resource_type
    ]
