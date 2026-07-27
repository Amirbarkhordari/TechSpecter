"""Report generation engine."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime

from techspecter import __version__
from techspecter.fingerprinting.models import UNKNOWN_VERSION, DetectionResult, TechnologyMatch
from techspecter.reporting.models import (
    Report,
    ReportEvidence,
    ReportMetadata,
    ReportStatistics,
    ReportSummary,
    ReportTarget,
    ReportTechnology,
    TechnologyGroup,
)

logger = logging.getLogger(__name__)


class ReportEngine:
    """Transform detection results into structured scan reports."""

    def __init__(self, *, tool_name: str = "TechSpecter", tool_version: str | None = None) -> None:
        """Initialize the report engine.

        Args:
            tool_name: Name of the reporting tool.
            tool_version: Optional tool version override.
        """
        self._tool_name = tool_name
        self._tool_version = tool_version or __version__

    def generate(
        self,
        detection: DetectionResult,
        *,
        scan_duration_ms: float | None = None,
        scan_timestamp: datetime | None = None,
    ) -> Report:
        """Generate a report from a detection result.

        Args:
            detection: Fingerprint detection output.
            scan_duration_ms: Optional total scan duration override.
            scan_timestamp: Optional scan timestamp override.

        Returns:
            Structured scan report.
        """
        logger.info("Generating report for %s", detection.target_url)
        technologies = [_map_technology(match) for match in detection.matches]
        technologies.sort(key=lambda item: (-item.confidence, item.name.lower()))
        groups = _group_by_category(technologies)
        statistics = _calculate_statistics(detection, technologies)
        timestamp = scan_timestamp or datetime.now(UTC)
        duration_ms = scan_duration_ms if scan_duration_ms is not None else detection.elapsed_ms

        metadata = ReportMetadata(
            tool_name=self._tool_name,
            tool_version=self._tool_version,
            scan_timestamp=timestamp,
            target_url=detection.target_url,
            scan_duration_ms=duration_ms,
            scripts_analyzed=detection.scripts_analyzed,
            technologies_detected=len(technologies),
            categories_detected=statistics.category_count,
        )
        summary = ReportSummary(
            headline=_build_headline(len(technologies)),
            technologies_detected=len(technologies),
            categories_detected=statistics.category_count,
        )
        return Report(
            metadata=metadata,
            target=ReportTarget(url=detection.target_url),
            summary=summary,
            statistics=statistics,
            technologies=technologies,
            groups=groups,
        )


def _map_technology(match: TechnologyMatch) -> ReportTechnology:
    """Map a technology match to a report technology entry."""
    source_file = match.filename or match.source_url
    evidence = [
        ReportEvidence(
            matched_file=source_file,
            matched_pattern=item.pattern,
            matcher_type=item.matcher,
            version=match.version,
            confidence=match.confidence,
        )
        for item in match.evidence
    ]
    if not evidence and match.matched_patterns:
        for entry in match.matched_patterns:
            matcher_type, _, pattern = entry.partition(":")
            evidence.append(
                ReportEvidence(
                    matched_file=source_file,
                    matched_pattern=pattern or entry,
                    matcher_type=matcher_type or "unknown",
                    version=match.version,
                    confidence=match.confidence,
                )
            )

    return ReportTechnology(
        id=match.technology.id,
        name=match.technology.name,
        category=match.technology.category,
        version=match.version,
        confidence=match.confidence,
        source_file=source_file,
        website=match.technology.website,
        description=match.technology.description,
        evidence=evidence,
    )


def _group_by_category(technologies: list[ReportTechnology]) -> list[TechnologyGroup]:
    """Group technologies by category."""
    grouped: dict[str, list[ReportTechnology]] = defaultdict(list)
    for technology in technologies:
        grouped[technology.category].append(technology)
    return [
        TechnologyGroup(category=category, technologies=items)
        for category, items in sorted(grouped.items())
    ]


def _calculate_statistics(
    detection: DetectionResult,
    technologies: list[ReportTechnology],
) -> ReportStatistics:
    """Calculate report statistics from detected technologies."""
    if not technologies:
        return ReportStatistics(scripts_analyzed=detection.scripts_analyzed)

    category_counts: dict[str, int] = defaultdict(int)
    known_versions = 0
    confidences: list[float] = []

    for technology in technologies:
        category_counts[technology.category] += 1
        confidences.append(technology.confidence)
        if technology.version != UNKNOWN_VERSION:
            known_versions += 1

    return ReportStatistics(
        total_technologies=len(technologies),
        category_counts=dict(sorted(category_counts.items())),
        category_count=len(category_counts),
        average_confidence=round(sum(confidences) / len(confidences), 2),
        highest_confidence=max(confidences),
        known_versions=known_versions,
        unknown_versions=len(technologies) - known_versions,
        scripts_analyzed=detection.scripts_analyzed,
    )


def _build_headline(technology_count: int) -> str:
    """Build a summary headline for the report."""
    if technology_count == 0:
        return "No JavaScript technologies detected"
    if technology_count == 1:
        return "1 JavaScript technology detected"
    return f"{technology_count} JavaScript technologies detected"
