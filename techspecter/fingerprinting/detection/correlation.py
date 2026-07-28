"""Evidence correlation engine."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.models import (
    NormalizedEvidence,
    RuleMatch,
    TechnologyEvaluation,
)
from techspecter.fingerprinting.detection.weights import ScoringWeights


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    """Correlated evidence context for a technology evaluation."""

    technology_id: str
    matches: tuple[RuleMatch, ...]
    sources: frozenset[str] = frozenset()
    resources: frozenset[str] = frozenset()
    domains: frozenset[str] = frozenset()
    evidence_types: frozenset[str] = frozenset()
    supporting_count: int = 0
    conflicting_versions: tuple[str, ...] = field(default_factory=tuple)


def correlate_evaluation(
    evaluation: TechnologyEvaluation,
    *,
    weights: ScoringWeights | None = None,
) -> CorrelationContext:
    """Build correlation context from a technology evaluation."""
    _ = weights
    matches = evaluation.matched_rules
    sources: set[str] = set()
    resources: set[str] = set()
    domains: set[str] = set()
    evidence_types: set[str] = set()
    for match in matches:
        item = match.evidence
        sources.add(item.source.value)
        if item.url:
            resources.add(item.url)
        if item.file:
            resources.add(item.file)
        evidence_types.add(item.evidence_type.value)
        domains.add(_resource_domain(item.url))

    return CorrelationContext(
        technology_id=evaluation.signature.id,
        matches=matches,
        sources=frozenset(sources),
        resources=frozenset(resources),
        domains=frozenset(domains),
        evidence_types=frozenset(evidence_types),
        supporting_count=len(matches),
    )


def correlation_bonus(
    context: CorrelationContext, *, weights: ScoringWeights | None = None
) -> float:
    """Calculate correlation bonus from cross-source and cross-resource evidence."""
    scoring = weights or ScoringWeights()
    if context.supporting_count <= 1:
        return 0.0
    bonus = len(context.sources) * scoring.correlation_per_source
    bonus += max(0, len(context.resources) - 1) * scoring.correlation_per_resource
    return min(scoring.max_correlation_bonus, bonus)


def group_evidence_by_resource(
    items: tuple[NormalizedEvidence, ...],
) -> dict[str, tuple[NormalizedEvidence, ...]]:
    """Group normalized evidence by resource key."""
    groups: dict[str, list[NormalizedEvidence]] = defaultdict(list)
    for item in items:
        groups[item.resource_key].append(item)
    return {key: tuple(values) for key, values in groups.items()}


def _resource_domain(url: str | None) -> str:
    """Return a coarse domain key for cross-domain correlation."""
    if not url:
        return "unknown"
    if url.startswith("inline://"):
        return "inline"
    from urllib.parse import urlparse

    return urlparse(url).netloc.lower() or "unknown"
