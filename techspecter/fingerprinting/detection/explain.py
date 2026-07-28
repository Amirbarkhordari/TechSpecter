"""Explainable detection output builder."""

from __future__ import annotations

from techspecter.fingerprinting.detection.models import (
    ExplainableDetectionResult,
    ScoringBreakdown,
    TechnologyEvaluation,
    VersionResolution,
    technology_match_from_evaluation,
)
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch


def build_detection_result(
    *,
    target_url: str,
    matches: list[TechnologyMatch],
    elapsed_ms: float,
    evaluations: dict[str, TechnologyEvaluation],
    scoring: dict[str, ScoringBreakdown],
    version_resolutions: dict[str, VersionResolution],
) -> ExplainableDetectionResult:
    """Build explainable detection output."""
    return ExplainableDetectionResult(
        detection=DetectionResult(
            target_url=target_url,
            matches=matches,
            scripts_analyzed=0,
            elapsed_ms=elapsed_ms,
        ),
        evaluations=evaluations,
        scoring=scoring,
        version_resolutions=version_resolutions,
    )


def build_matches(
    evaluations: list[TechnologyEvaluation],
    scoring: dict[str, ScoringBreakdown],
    versions: dict[str, VersionResolution],
) -> list[TechnologyMatch]:
    """Convert accepted evaluations into technology matches."""
    matches: list[TechnologyMatch] = []
    for evaluation in evaluations:
        tech_id = evaluation.signature.id
        breakdown = scoring.get(tech_id)
        version = versions.get(tech_id)
        if breakdown is None or version is None:
            continue
        if breakdown.final_confidence <= 0:
            continue
        matches.append(
            technology_match_from_evaluation(
                evaluation,
                version=version,
                confidence=breakdown.final_confidence,
                breakdown=breakdown,
            ),
        )
    return matches
