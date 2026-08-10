"""Detection engine models."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.fingerprinting.evidence.models import Evidence
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch
from techspecter.fingerprinting.signatures.models import SignatureRule, TechnologySignature


@dataclass(frozen=True, slots=True)
class NormalizedEvidence:
    """Evidence item prepared for detection evaluation."""

    evidence: Evidence
    normalized_value: str
    resource_key: str
    domain_key: str
    base_weight: float


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A signature rule matched against evidence."""

    rule: SignatureRule
    evidence: Evidence
    matched_text: str
    weight: float


@dataclass(frozen=True, slots=True)
class TechnologyEvaluation:
    """Evaluation outcome for one technology signature."""

    signature: TechnologySignature
    matched_rules: tuple[RuleMatch, ...] = field(default_factory=tuple)
    negative_matches: tuple[RuleMatch, ...] = field(default_factory=tuple)
    required_matches: tuple[RuleMatch, ...] = field(default_factory=tuple)
    raw_score: float = 0.0
    correlation_bonus: float = 0.0
    penalty: float = 0.0
    rejected: bool = False
    rejection_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ScoringBreakdown:
    """Explainable confidence scoring components."""

    evidence_score: float = 0.0
    correlation_bonus: float = 0.0
    priority_bonus: float = 0.0
    penalty: float = 0.0
    final_confidence: float = 0.0
    components: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VersionResolution:
    """Resolved version with provenance and attribution state."""

    version: str
    confidence: float
    source: str
    reason: str
    rejected_candidates: tuple[str, ...] = field(default_factory=tuple)
    candidate_count: int = 0
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    winning_candidate: str | None = None
    attribution_state: str = "candidate"
    ownership_class: str | None = None
    ownership_confidence: float = 0.0
    version_confidence: float = 0.0
    technology_confidence: float | None = None
    candidates: tuple[object, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ExplainableDetectionResult:
    """Detection output with explainability metadata."""

    detection: DetectionResult
    evaluations: dict[str, TechnologyEvaluation] = field(default_factory=dict)
    scoring: dict[str, ScoringBreakdown] = field(default_factory=dict)
    version_resolutions: dict[str, VersionResolution] = field(default_factory=dict)


def technology_match_from_evaluation(
    evaluation: TechnologyEvaluation,
    *,
    version: VersionResolution,
    confidence: float,
    breakdown: ScoringBreakdown,
) -> TechnologyMatch:
    """Build an explainable technology match from evaluation data."""
    signature = evaluation.signature
    from techspecter.fingerprinting.models import Technology

    evidence_ids = sorted(
        {match.evidence.id for match in evaluation.matched_rules},
    )
    resources = sorted(
        {match.evidence.url or match.evidence.file or "" for match in evaluation.matched_rules},
    )
    resources = [item for item in resources if item]
    patterns = sorted({match.rule.pattern for match in evaluation.matched_rules})
    reasons = sorted(
        {match.rule.description or match.rule.id for match in evaluation.matched_rules},
    )
    evidence_sources = sorted(
        {match.evidence.source.value for match in evaluation.matched_rules},
    )
    from techspecter.fingerprinting.detection.knowledge import DetectionBasis
    from techspecter.fingerprinting.match_attribution import apply_match_attribution
    from techspecter.fingerprinting.models import PatternEvidence

    source_file = next(
        (match.evidence.file for match in evaluation.matched_rules if match.evidence.file),
        None,
    )
    source_url = next(
        (match.evidence.url for match in evaluation.matched_rules if match.evidence.url),
        None,
    )
    structured_evidence: list[PatternEvidence] = []
    for rule_match in evaluation.matched_rules:
        structured_evidence.append(
            PatternEvidence(
                matcher=rule_match.evidence.source.value,
                pattern=rule_match.rule.pattern,
                weight=rule_match.weight,
                detail=rule_match.matched_text,
                source_file=rule_match.evidence.file,
                asset_id=rule_match.evidence.id,
                matched_value=rule_match.matched_text,
                evidence_type=rule_match.evidence.evidence_type.value,
            ),
        )

    match = TechnologyMatch(
        technology=Technology(
            id=signature.id,
            name=signature.name,
            category=signature.category,
            description=signature.description,
        ),
        version=version.version,
        confidence=confidence,
        matched_patterns=patterns,
        source_url=source_url or (resources[0] if resources else None),
        filename=source_file,
        source_file=source_file,
        evidence=structured_evidence,
        detection_reason=(
            "; ".join(reasons) if reasons else f"Matched {len(evaluation.matched_rules)} rules"
        ),
        version_source=version.source,
        version_reason=version.reason,
        version_confidence=version.confidence,
        supporting_evidence_ids=evidence_ids,
        evidence_count=len(structured_evidence) or len(evidence_ids),
        matched_resources=resources,
        rejected_version_candidates=list(version.rejected_candidates),
        evidence_sources=evidence_sources,
        confidence_breakdown=dict(breakdown.components),
        providers=["techspecter"],
        detection_methods=["evidence-engine"],
        detection_basis=DetectionBasis.EVIDENCE,
    )
    return apply_match_attribution(match)
