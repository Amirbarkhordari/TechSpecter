"""HTTP report section builders."""

from __future__ import annotations

from collections import defaultdict

from techspecter.analysis.http.analyzer_ids import HTTP_ANALYZER_IDS, is_http_analyzer
from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.reporting.models import ReportFinding, ReportSection


def build_http_report_sections(
    analysis: AnalysisResult,
    findings: list[ReportFinding],
    *,
    plugin_ids: list[str] | None = None,
) -> list[ReportSection]:
    """Build HTTP-focused report sections from analysis output."""
    http_findings = [finding for finding in findings if is_http_analyzer(finding.analyzer)]
    header_findings = [
        finding
        for finding in http_findings
        if finding.analyzer
        in {"http-header-analyzer", "cache-control-analyzer", "content-type-analyzer"}
    ]
    cookie_findings = [
        finding for finding in http_findings if finding.analyzer == "cookie-analyzer"
    ]
    security_findings = [
        finding
        for finding in http_findings
        if finding.analyzer in {"security-header-analyzer", "csp-analyzer", "cors-analyzer"}
    ]
    redirect_findings = [
        finding for finding in http_findings if finding.analyzer == "redirect-analyzer"
    ]

    analyzer_errors: dict[str, list[str]] = defaultdict(list)
    for analyzer_result in analysis.analyzer_results:
        if analyzer_result.errors:
            analyzer_errors[analyzer_result.analyzer_id].extend(analyzer_result.errors)

    http_response = analysis.discovery.http_response if analysis.discovery is not None else None
    http_stats: dict[str, object] = {
        "status_code": http_response.status_code if http_response else None,
        "redirect_hops": len(http_response.redirects) if http_response else 0,
        "cookie_count": len(http_response.cookies) if http_response else 0,
        "header_count": len(http_response.headers) if http_response else 0,
    }

    analyzer_summary = {
        analyzer_id: sum(1 for finding in http_findings if finding.analyzer == analyzer_id)
        for analyzer_id in HTTP_ANALYZER_IDS
    }

    sections = [
        ReportSection(
            id="http-analysis",
            title="HTTP Analysis",
            summary=f"{len(http_findings)} passive HTTP findings observed.",
            findings=http_findings,
            metadata={"analyzer_ids": list(HTTP_ANALYZER_IDS)},
        ),
        ReportSection(
            id="header-analysis",
            title="Header Analysis",
            summary=f"{len(header_findings)} header-related findings observed.",
            findings=header_findings,
        ),
        ReportSection(
            id="cookie-analysis",
            title="Cookie Analysis",
            summary=f"{len(cookie_findings)} cookie findings observed.",
            findings=cookie_findings,
        ),
        ReportSection(
            id="security-header-summary",
            title="Security Header Summary",
            summary=f"{len(security_findings)} security header findings observed.",
            findings=security_findings,
        ),
        ReportSection(
            id="http-statistics",
            title="HTTP Statistics",
            summary="Passive HTTP response statistics.",
            metadata=http_stats,
        ),
        ReportSection(
            id="analyzer-execution-summary",
            title="Analyzer Execution Summary",
            summary="Findings produced per HTTP analyzer.",
            metadata={"analyzer_counts": analyzer_summary, "errors": dict(analyzer_errors)},
        ),
        ReportSection(
            id="plugin-summary",
            title="Plugin Summary",
            summary="Built-in HTTP analyzer plugins contributing to this report.",
            metadata={"plugin_ids": plugin_ids or []},
        ),
    ]

    if redirect_findings:
        sections.insert(
            1,
            ReportSection(
                id="redirect-analysis",
                title="Redirect Analysis",
                summary=f"{len(redirect_findings)} redirect findings observed.",
                findings=redirect_findings,
            ),
        )

    return sections
