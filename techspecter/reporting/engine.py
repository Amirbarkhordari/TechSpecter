"""Report generation engine."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime

from techspecter import __version__
from techspecter.analysis.models.finding import Finding
from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.fingerprinting.models import UNKNOWN_VERSION, DetectionResult, TechnologyMatch
from techspecter.reporting.artifact_sections import build_artifact_report_sections
from techspecter.reporting.http_sections import build_http_report_sections
from techspecter.reporting.metadata_sections import build_metadata_report_sections
from techspecter.reporting.models import (
    Report,
    ReportEvidence,
    ReportFinding,
    ReportMetadata,
    ReportStatistics,
    ReportSummary,
    ReportTarget,
    ReportTechnology,
    TechnologyGroup,
)
from techspecter.reporting.performance_sections import build_performance_report_sections

logger = logging.getLogger(__name__)


class ReportEngine:
    """Transform detection and analysis results into structured scan reports."""

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
            findings_detected=len(technologies),
            categories_detected=statistics.category_count,
        )
        summary = ReportSummary(
            headline=_build_headline(len(technologies)),
            technologies_detected=len(technologies),
            findings_detected=len(technologies),
            categories_detected=statistics.category_count,
        )
        return Report(
            metadata=metadata,
            target=ReportTarget(url=detection.target_url),
            summary=summary,
            statistics=statistics,
            technologies=technologies,
            findings=[],
            groups=groups,
        )

    def generate_from_analysis(
        self,
        analysis: AnalysisResult,
        *,
        scan_duration_ms: float | None = None,
        scan_timestamp: datetime | None = None,
    ) -> Report:
        """Generate a report from a generic analysis result."""
        if analysis.detection is not None:
            report = self.generate(
                analysis.detection,
                scan_duration_ms=scan_duration_ms or analysis.elapsed_ms,
                scan_timestamp=scan_timestamp or analysis.metadata.timestamp,
            )
        else:
            report = self._empty_report(
                target_url=analysis.target_url,
                scan_duration_ms=scan_duration_ms or analysis.elapsed_ms,
                scan_timestamp=scan_timestamp or analysis.metadata.timestamp,
            )

        findings = [_map_finding(finding) for finding in analysis.findings]
        statistics = _calculate_analysis_statistics(analysis, report.technologies, findings)
        metadata = report.metadata.model_copy(
            update={
                "findings_detected": len(findings),
                "technologies_detected": len(report.technologies),
                "categories_detected": len(
                    {finding.category for finding in findings}
                    or {group.category for group in report.groups}
                ),
            }
        )
        summary = report.summary.model_copy(
            update={
                "findings_detected": len(findings),
                "headline": _build_analysis_headline(len(findings), len(report.technologies)),
            }
        )
        return report.model_copy(
            update={
                "metadata": metadata,
                "summary": summary,
                "statistics": statistics,
                "findings": findings,
                "sections": [
                    *build_http_report_sections(analysis, findings),
                    *build_metadata_report_sections(analysis, findings),
                    *build_artifact_report_sections(analysis, findings),
                    *build_performance_report_sections(analysis),
                ],
            }
        )

    def _empty_report(
        self,
        *,
        target_url: str,
        scan_duration_ms: float,
        scan_timestamp: datetime | None = None,
    ) -> Report:
        """Build an empty report shell for non-fingerprint analysis."""
        timestamp = scan_timestamp or datetime.now(UTC)
        metadata = ReportMetadata(
            tool_name=self._tool_name,
            tool_version=self._tool_version,
            scan_timestamp=timestamp,
            target_url=target_url,
            scan_duration_ms=scan_duration_ms,
        )
        summary = ReportSummary(
            headline="No findings detected",
            technologies_detected=0,
            findings_detected=0,
            categories_detected=0,
        )
        return Report(
            metadata=metadata,
            target=ReportTarget(url=target_url),
            summary=summary,
            statistics=ReportStatistics(),
            technologies=[],
            findings=[],
            groups=[],
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
        version_source=match.version_source,
        version_confidence=match.version_confidence,
        evidence_count=match.evidence_count,
        detection_reason=match.detection_reason,
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
        total_findings=len(technologies),
        category_counts=dict(sorted(category_counts.items())),
        category_count=len(category_counts),
        average_confidence=round(sum(confidences) / len(confidences), 2),
        highest_confidence=max(confidences),
        known_versions=known_versions,
        unknown_versions=len(technologies) - known_versions,
        scripts_analyzed=detection.scripts_analyzed,
    )


def _map_finding(finding: Finding) -> ReportFinding:
    """Map a generic finding to a report finding entry."""
    evidence = [
        ReportEvidence(
            matched_file=item.file,
            matched_pattern=item.snippet,
            matcher_type=finding.analyzer,
            url=item.url,
            line=item.line,
            column=item.column,
            snippet=item.snippet,
            header=item.header,
            cookie=item.cookie,
            html_element=item.html_element,
            javascript_location=item.javascript_location,
            confidence=finding.confidence,
            version=(
                str(finding.metadata.get("version")) if finding.metadata.get("version") else None
            ),
        )
        for item in finding.evidence
    ]
    return ReportFinding(
        id=finding.id,
        analyzer=finding.analyzer,
        category=str(finding.category),
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        confidence=finding.confidence,
        location=finding.location,
        recommendation=finding.recommendation,
        evidence=evidence,
        metadata=dict(finding.metadata),
    )


def _calculate_analysis_statistics(
    analysis: AnalysisResult,
    technologies: list[ReportTechnology],
    findings: list[ReportFinding],
) -> ReportStatistics:
    """Calculate report statistics from analysis output."""
    base = _calculate_statistics(
        analysis.detection or DetectionResult(target_url=analysis.target_url),
        technologies,
    )
    severity_counts: dict[str, int] = defaultdict(int)
    analyzer_counts: dict[str, int] = defaultdict(int)
    category_counts: dict[str, int] = defaultdict(int)
    confidences = [finding.confidence for finding in findings]

    for finding in findings:
        severity_counts[finding.severity] += 1
        analyzer_counts[finding.analyzer] += 1
        category_counts[finding.category] += 1

    return base.model_copy(
        update={
            "total_findings": len(findings),
            "severity_counts": dict(sorted(severity_counts.items())),
            "analyzer_counts": dict(sorted(analyzer_counts.items())),
            "category_counts": dict(sorted(category_counts.items())) or base.category_counts,
            "category_count": len(category_counts) or base.category_count,
            "average_confidence": (
                round(sum(confidences) / len(confidences), 2)
                if confidences
                else base.average_confidence
            ),
            "highest_confidence": max(confidences) if confidences else base.highest_confidence,
            "scripts_analyzed": analysis.statistics.scripts_analyzed or base.scripts_analyzed,
        }
    )


def _build_analysis_headline(findings_count: int, technology_count: int) -> str:
    """Build a summary headline for generic analysis reports."""
    if findings_count == 0:
        return "No findings detected"
    if technology_count and findings_count == technology_count:
        return _build_headline(technology_count)
    return f"{findings_count} findings detected"


def _build_headline(technology_count: int) -> str:
    """Build a summary headline for the report."""
    if technology_count == 0:
        return "No JavaScript technologies detected"
    if technology_count == 1:
        return "1 JavaScript technology detected"
    return f"{technology_count} JavaScript technologies detected"
