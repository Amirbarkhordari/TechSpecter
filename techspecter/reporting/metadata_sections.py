"""Metadata report section builders."""

from __future__ import annotations

from collections import defaultdict

from techspecter.analysis.metadata.analyzer_ids import METADATA_ANALYZER_IDS, is_metadata_analyzer
from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.reporting.models import ReportFinding, ReportSection


def build_metadata_report_sections(
    analysis: AnalysisResult,
    findings: list[ReportFinding],
    *,
    plugin_ids: list[str] | None = None,
) -> list[ReportSection]:
    """Build metadata-focused report sections from analysis output."""
    metadata_findings = [finding for finding in findings if is_metadata_analyzer(finding.analyzer)]
    html_findings = [
        finding
        for finding in metadata_findings
        if finding.analyzer
        in {
            "html-metadata-analyzer",
            "html-comment-analyzer",
            "opengraph-analyzer",
            "twitter-card-analyzer",
            "canonical-link-analyzer",
            "alternate-link-analyzer",
            "generator-meta-analyzer",
            "theme-color-analyzer",
            "application-metadata-analyzer",
            "language-analyzer",
            "favicon-analyzer",
        }
    ]
    framework_findings = [
        finding
        for finding in metadata_findings
        if finding.analyzer == "framework-metadata-analyzer"
    ]
    well_known_findings = [
        finding
        for finding in metadata_findings
        if finding.analyzer
        in {
            "robots-analyzer",
            "sitemap-analyzer",
            "security-txt-analyzer",
            "humans-txt-analyzer",
            "ads-txt-analyzer",
            "assetlinks-analyzer",
            "apple-app-site-association-analyzer",
        }
    ]
    manifest_findings = [
        finding
        for finding in metadata_findings
        if finding.analyzer
        in {"manifest-analyzer", "web-app-manifest-analyzer", "browserconfig-analyzer"}
    ]
    pwa_findings = [
        finding
        for finding in metadata_findings
        if finding.analyzer in {"service-worker-analyzer", "web-app-manifest-analyzer"}
    ]
    sourcemap_findings = [
        finding for finding in metadata_findings if finding.analyzer == "sourcemap-analyzer"
    ]

    analyzer_errors: dict[str, list[str]] = defaultdict(list)
    for analyzer_result in analysis.analyzer_results:
        if analyzer_result.errors:
            analyzer_errors[analyzer_result.analyzer_id].extend(analyzer_result.errors)

    metadata_observation = (
        analysis.discovery.metadata_observation if analysis.discovery is not None else None
    )
    resource_stats: dict[str, object] = {
        "well_known_resources": (
            len(metadata_observation.well_known_resources) if metadata_observation else 0
        ),
        "available_resources": (
            sum(1 for item in metadata_observation.well_known_resources if item.available)
            if metadata_observation
            else 0
        ),
        "sourcemap_references": (
            len(metadata_observation.sourcemap_references) if metadata_observation else 0
        ),
        "service_worker_references": (
            len(metadata_observation.service_worker_references) if metadata_observation else 0
        ),
    }

    analyzer_summary = {
        analyzer_id: sum(1 for finding in metadata_findings if finding.analyzer == analyzer_id)
        for analyzer_id in METADATA_ANALYZER_IDS
    }

    return [
        ReportSection(
            id="metadata-summary",
            title="Metadata Summary",
            summary=f"{len(metadata_findings)} passive metadata findings observed.",
            findings=metadata_findings,
            metadata={"analyzer_ids": list(METADATA_ANALYZER_IDS)},
        ),
        ReportSection(
            id="html-metadata",
            title="HTML Metadata",
            summary=f"{len(html_findings)} HTML metadata findings observed.",
            findings=html_findings,
        ),
        ReportSection(
            id="framework-metadata",
            title="Framework Metadata",
            summary=f"{len(framework_findings)} framework metadata findings observed.",
            findings=framework_findings,
        ),
        ReportSection(
            id="well-known-resources",
            title="Well-Known Resources",
            summary=f"{len(well_known_findings)} well-known resource findings observed.",
            findings=well_known_findings,
        ),
        ReportSection(
            id="manifest-information",
            title="Manifest Information",
            summary=f"{len(manifest_findings)} manifest findings observed.",
            findings=manifest_findings,
        ),
        ReportSection(
            id="pwa-information",
            title="PWA Information",
            summary=f"{len(pwa_findings)} PWA-related findings observed.",
            findings=pwa_findings,
        ),
        ReportSection(
            id="sourcemap-summary",
            title="SourceMap Summary",
            summary=f"{len(sourcemap_findings)} SourceMap findings observed.",
            findings=sourcemap_findings,
        ),
        ReportSection(
            id="passive-resource-summary",
            title="Passive Resource Summary",
            summary="Passive metadata resource collection statistics.",
            metadata=resource_stats,
        ),
        ReportSection(
            id="plugin-execution-summary",
            title="Plugin Execution Summary",
            summary="Findings produced per metadata analyzer.",
            metadata={"analyzer_counts": analyzer_summary, "errors": dict(analyzer_errors)},
        ),
        ReportSection(
            id="metadata-plugin-summary",
            title="Plugin Summary",
            summary="Built-in metadata analyzer plugins contributing to this report.",
            metadata={"plugin_ids": plugin_ids or []},
        ),
    ]
