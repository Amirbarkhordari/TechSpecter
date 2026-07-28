"""Performance and execution summary report sections."""

from __future__ import annotations

from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.reporting.models import ReportSection


def build_performance_report_sections(analysis: AnalysisResult) -> list[ReportSection]:
    """Build performance, timing, and execution summary sections."""
    extra = analysis.metadata.extra
    performance = extra.get("performance", {})
    if not isinstance(performance, dict):
        performance = {}

    timing = extra.get("timing", {})
    if not isinstance(timing, dict):
        timing = {}

    cache_stats = extra.get("cache", {})
    if not isinstance(cache_stats, dict):
        cache_stats = {}

    plugin_summary = extra.get("plugins", {})
    if not isinstance(plugin_summary, dict):
        plugin_summary = {}

    sections: list[ReportSection] = []

    stage_lines: list[str] = []
    stages = timing.get("stages", {})
    if isinstance(stages, dict):
        for name, elapsed in sorted(stages.items()):
            stage_lines.append(f"{name}: {elapsed} ms")
    analyzer_timings = timing.get("analyzer_timings", {})
    analyzer_lines: list[str] = []
    if isinstance(analyzer_timings, dict):
        for analyzer_id, elapsed in sorted(analyzer_timings.items()):
            analyzer_lines.append(f"{analyzer_id}: {elapsed} ms")

    sections.append(
        ReportSection(
            id="execution-summary",
            title="Execution Summary",
            summary=(
                f"Total {analysis.elapsed_ms:.0f} ms across "
                f"{analysis.statistics.analyzers_run} analyzers and "
                f"{analysis.statistics.total_findings} findings."
            ),
            metadata={
                "target_url": analysis.target_url,
                "total_elapsed_ms": analysis.elapsed_ms,
                "discovery_elapsed_ms": analysis.metadata.discovery_elapsed_ms,
                "analysis_elapsed_ms": analysis.metadata.analysis_elapsed_ms,
                "analyzers_run": analysis.statistics.analyzers_run,
                "total_findings": analysis.statistics.total_findings,
            },
        ),
    )

    if stage_lines or analyzer_lines:
        sections.append(
            ReportSection(
                id="timing-summary",
                title="Timing Summary",
                summary="Pipeline stage and analyzer timings.",
                metadata={
                    "stages": stages if isinstance(stages, dict) else {},
                    "analyzer_timings": (
                        analyzer_timings if isinstance(analyzer_timings, dict) else {}
                    ),
                    "total_stage_ms": timing.get("total_stage_ms", 0),
                },
            ),
        )

    if performance or cache_stats:
        sections.append(
            ReportSection(
                id="performance-statistics",
                title="Performance Statistics",
                summary="Resource usage and cache effectiveness.",
                metadata={
                    "performance": performance,
                    "cache": cache_stats,
                },
            ),
        )

    if plugin_summary:
        sections.append(
            ReportSection(
                id="plugin-execution-summary",
                title="Plugin Execution Summary",
                summary="Loaded plugin inventory for this run.",
                metadata=dict(plugin_summary),
            ),
        )

    sections.append(
        ReportSection(
            id="finding-statistics",
            title="Finding Statistics",
            summary=(
                f"{analysis.statistics.total_findings} findings across "
                f"{len(analysis.statistics.findings_by_category)} categories."
            ),
            metadata={
                "findings_by_category": analysis.statistics.findings_by_category,
                "findings_by_severity": analysis.statistics.findings_by_severity,
                "findings_by_analyzer": analysis.statistics.findings_by_analyzer,
                "average_confidence": analysis.statistics.average_confidence,
                "highest_confidence": analysis.statistics.highest_confidence,
                "scripts_analyzed": analysis.statistics.scripts_analyzed,
            },
        ),
    )

    return sections
