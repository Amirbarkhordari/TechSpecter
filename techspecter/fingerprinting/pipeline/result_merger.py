"""Merge detection results from multiple fingerprint pipelines."""

from __future__ import annotations

import logging

from techspecter.fingerprinting.detection.merger import TechnologyMerger
from techspecter.fingerprinting.match_attribution import apply_match_attribution
from techspecter.fingerprinting.match_quality import MatchQualityGate, apply_match_quality_gate
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch

logger = logging.getLogger(__name__)


def merge_detection_results(
    *results: DetectionResult,
    apply_quality_gate: bool = True,
) -> DetectionResult:
    """Merge multiple detection results into one confirmed output."""
    if not results:
        raise ValueError("At least one detection result is required")

    target_url = results[0].target_url
    scripts_analyzed = max(item.scripts_analyzed for item in results)
    elapsed_ms = sum(item.elapsed_ms for item in results)

    raw_matches: list[TechnologyMatch] = []
    prior_ignored: list[TechnologyMatch] = []
    for result in results:
        raw_matches.extend(result.matches)
        prior_ignored.extend(result.ignored_matches)

    attributed = [apply_match_attribution(match) for match in raw_matches]
    merged = TechnologyMerger().merge_matches(attributed)

    logger.info(
        "Detection merge for %s: %d raw matches -> %d merged technologies",
        target_url,
        len(raw_matches),
        len(merged),
    )

    if not apply_quality_gate:
        return DetectionResult(
            target_url=target_url,
            matches=merged,
            ignored_matches=prior_ignored,
            scripts_analyzed=scripts_analyzed,
            elapsed_ms=elapsed_ms,
        )

    confirmed, ignored = apply_match_quality_gate(merged)
    gate = MatchQualityGate()
    for match in ignored:
        logger.debug(
            "Rejected technology candidate",
            extra={
                "technology": match.technology.id,
                "confidence": match.confidence,
                "source_file": match.source_file or match.filename,
                "reason": gate.rejection_reason(match),
            },
        )

    logger.info(
        "Detection quality gate for %s: %d confirmed, %d rejected",
        target_url,
        len(confirmed),
        len(ignored) + len(prior_ignored),
    )

    return DetectionResult(
        target_url=target_url,
        matches=confirmed,
        ignored_matches=[*prior_ignored, *ignored],
        scripts_analyzed=scripts_analyzed,
        elapsed_ms=elapsed_ms,
    )
