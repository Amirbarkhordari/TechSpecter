"""Artifact report section builders."""

from __future__ import annotations

from collections import defaultdict

from techspecter.analysis.artifact.analyzer_ids import (
    ARTIFACT_ANALYZER_IDS,
    SENSITIVE_ARTIFACT_ANALYZER_IDS,
    is_artifact_analyzer,
)
from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.reporting.models import ReportFinding, ReportSection


def build_artifact_report_sections(
    analysis: AnalysisResult,
    findings: list[ReportFinding],
    *,
    plugin_ids: list[str] | None = None,
) -> list[ReportSection]:
    """Build artifact-focused report sections from analysis output."""
    artifact_findings = [finding for finding in findings if is_artifact_analyzer(finding.analyzer)]
    cloud_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer
        in {
            "firebase-analyzer",
            "aws-metadata-analyzer",
            "azure-metadata-analyzer",
            "google-cloud-metadata-analyzer",
            "cdn-analyzer",
        }
    ]
    identity_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer
        in {
            "api-key-analyzer",
            "jwt-analyzer",
            "oauth-metadata-analyzer",
            "openid-connect-analyzer",
        }
    ]
    api_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer in {"graphql-metadata-analyzer", "openapi-analyzer"}
    ]
    graphql_findings = [
        finding for finding in artifact_findings if finding.analyzer == "graphql-metadata-analyzer"
    ]
    openapi_findings = [
        finding for finding in artifact_findings if finding.analyzer == "openapi-analyzer"
    ]
    auth_findings = identity_findings
    third_party_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer == "third-party-service-analyzer"
    ]
    analytics_findings = [
        finding for finding in artifact_findings if finding.analyzer == "analytics-service-analyzer"
    ]
    monitoring_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer == "monitoring-service-analyzer"
    ]
    technology_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer == "technology-exposure-analyzer"
    ]
    secret_findings = [
        finding for finding in artifact_findings if finding.analyzer == "secret-pattern-analyzer"
    ]
    config_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer
        in {
            "configuration-artifact-analyzer",
            "environment-artifact-analyzer",
            "client-configuration-analyzer",
        }
    ]
    build_findings = [
        finding for finding in artifact_findings if finding.analyzer == "build-artifact-analyzer"
    ]
    debug_findings = [
        finding for finding in artifact_findings if finding.analyzer == "debug-artifact-analyzer"
    ]
    backup_findings = [
        finding for finding in artifact_findings if finding.analyzer == "backup-artifact-analyzer"
    ]
    classification_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer == "exposure-classification-analyzer"
    ]
    risk_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer == "risk-classification-analyzer"
    ]
    sensitive_findings = [
        finding
        for finding in artifact_findings
        if finding.analyzer in SENSITIVE_ARTIFACT_ANALYZER_IDS
    ]

    analyzer_errors: dict[str, list[str]] = defaultdict(list)
    for analyzer_result in analysis.analyzer_results:
        if analyzer_result.errors:
            analyzer_errors[analyzer_result.analyzer_id].extend(analyzer_result.errors)

    artifact_observation = (
        analysis.discovery.artifact_observation if analysis.discovery is not None else None
    )
    artifact_stats: dict[str, object] = {
        "references_detected": (
            len(artifact_observation.references) if artifact_observation else 0
        ),
        "sources_scanned": (
            len(artifact_observation.sources_scanned) if artifact_observation else 0
        ),
    }

    analyzer_summary = {
        analyzer_id: sum(1 for finding in artifact_findings if finding.analyzer == analyzer_id)
        for analyzer_id in ARTIFACT_ANALYZER_IDS
    }

    return [
        ReportSection(
            id="cloud-services",
            title="Cloud Services",
            summary=f"{len(cloud_findings)} cloud service findings observed.",
            findings=cloud_findings,
        ),
        ReportSection(
            id="identity-services",
            title="Identity Services",
            summary=f"{len(identity_findings)} identity service findings observed.",
            findings=identity_findings,
        ),
        ReportSection(
            id="api-technologies",
            title="API Technologies",
            summary=f"{len(api_findings)} API technology findings observed.",
            findings=api_findings,
        ),
        ReportSection(
            id="graphql",
            title="GraphQL",
            summary=f"{len(graphql_findings)} GraphQL findings observed.",
            findings=graphql_findings,
        ),
        ReportSection(
            id="openapi",
            title="OpenAPI",
            summary=f"{len(openapi_findings)} OpenAPI findings observed.",
            findings=openapi_findings,
        ),
        ReportSection(
            id="authentication-metadata",
            title="Authentication Metadata",
            summary=f"{len(auth_findings)} authentication metadata findings observed.",
            findings=auth_findings,
        ),
        ReportSection(
            id="third-party-services",
            title="Third-Party Services",
            summary=f"{len(third_party_findings)} third-party service findings observed.",
            findings=third_party_findings,
        ),
        ReportSection(
            id="analytics",
            title="Analytics",
            summary=f"{len(analytics_findings)} analytics findings observed.",
            findings=analytics_findings,
        ),
        ReportSection(
            id="monitoring",
            title="Monitoring",
            summary=f"{len(monitoring_findings)} monitoring findings observed.",
            findings=monitoring_findings,
        ),
        ReportSection(
            id="technology-exposure",
            title="Technology Exposure",
            summary=f"{len(technology_findings)} technology exposure findings observed.",
            findings=technology_findings,
        ),
        ReportSection(
            id="sensitive-secrets",
            title="Sensitive Secrets",
            summary=f"{len(secret_findings)} secret pattern findings observed.",
            findings=secret_findings,
        ),
        ReportSection(
            id="configuration-artifacts",
            title="Configuration Artifacts",
            summary=f"{len(config_findings)} configuration artifact findings observed.",
            findings=config_findings,
        ),
        ReportSection(
            id="build-artifacts",
            title="Build Artifacts",
            summary=f"{len(build_findings)} build artifact findings observed.",
            findings=build_findings,
        ),
        ReportSection(
            id="debug-artifacts",
            title="Debug Artifacts",
            summary=f"{len(debug_findings)} debug artifact findings observed.",
            findings=debug_findings,
        ),
        ReportSection(
            id="backup-artifacts",
            title="Backup Artifacts",
            summary=f"{len(backup_findings)} backup artifact findings observed.",
            findings=backup_findings,
        ),
        ReportSection(
            id="risk-classification",
            title="Risk Classification",
            summary=f"{len(risk_findings)} risk classification findings observed.",
            findings=risk_findings,
        ),
        ReportSection(
            id="artifact-categories",
            title="Artifact Categories",
            summary=f"{len(classification_findings)} exposure classification findings observed.",
            findings=classification_findings,
        ),
        ReportSection(
            id="exposure-summary",
            title="Exposure Summary",
            summary=f"{len(sensitive_findings)} sensitive artifact findings across all categories.",
            findings=sensitive_findings,
            metadata=artifact_stats,
        ),
        ReportSection(
            id="executive-summary",
            title="Executive Summary",
            summary=(
                f"{len(artifact_findings)} total artifact findings across "
                f"{len(ARTIFACT_ANALYZER_IDS)} analyzers."
            ),
            metadata={
                "total_findings": len(artifact_findings),
                "secret_findings": len(secret_findings),
                "config_findings": len(config_findings),
                "high_risk_findings": len(
                    [f for f in risk_findings if f.severity in {"HIGH", "CRITICAL"}]
                ),
            },
        ),
        ReportSection(
            id="analyzer-statistics",
            title="Analyzer Statistics",
            summary="Detailed analyzer execution statistics.",
            metadata={
                "analyzer_counts": analyzer_summary,
                "sensitive_analyzer_ids": list(SENSITIVE_ARTIFACT_ANALYZER_IDS),
            },
        ),
        ReportSection(
            id="artifact-analyzer-summary",
            title="Analyzer Summary",
            summary="Findings produced per artifact analyzer.",
            metadata={
                "analyzer_counts": analyzer_summary,
                "errors": dict(analyzer_errors),
                "artifact_stats": artifact_stats,
            },
        ),
        ReportSection(
            id="artifact-plugin-summary",
            title="Plugin Summary",
            summary="Built-in artifact analyzer plugins contributing to this report.",
            metadata={"plugin_ids": plugin_ids or []},
        ),
    ]
