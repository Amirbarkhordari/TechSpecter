"""CSP analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.helpers import build_http_finding, header_value
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class CspAnalyzer(PassiveHttpAnalyzer):
    """Analyze Content-Security-Policy headers."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="csp-analyzer",
            name="CSP Analyzer",
            version="1.0.0",
            description="Analyzes Content-Security-Policy response headers.",
            category=FindingCategory.HEADERS.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        csp = header_value(observation, "content-security-policy")
        report_only = header_value(observation, "content-security-policy-report-only")
        findings = []
        if csp is None and report_only is None:
            findings.append(
                build_http_finding(
                    finding_id="csp:missing",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.HEADERS,
                    title="Content-Security-Policy not observed",
                    description="Neither CSP nor CSP-Report-Only headers were present.",
                    recommendation="Review whether a Content-Security-Policy should be published.",
                    url=observation.final_url,
                )
            )
        else:
            if csp is not None:
                findings.append(
                    build_http_finding(
                        finding_id="csp:policy",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.HEADERS,
                        title="Content-Security-Policy observed",
                        description=f"CSP policy observed: {csp}",
                        header=f"content-security-policy: {csp}",
                        url=observation.final_url,
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    )
                )
            if report_only is not None:
                findings.append(
                    build_http_finding(
                        finding_id="csp:report-only",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.HEADERS,
                        title="Content-Security-Policy-Report-Only observed",
                        description=f"CSP report-only policy observed: {report_only}",
                        header=f"content-security-policy-report-only: {report_only}",
                        url=observation.final_url,
                    )
                )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
