"""Security header analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.constants import SECURITY_HEADERS
from techspecter.analysis.http.helpers import build_http_finding, header_value
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class SecurityHeaderAnalyzer(PassiveHttpAnalyzer):
    """Analyze security-related HTTP response headers."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="security-header-analyzer",
            name="Security Header Analyzer",
            version="1.0.0",
            description="Analyzes security headers and missing security controls.",
            category=FindingCategory.HEADERS.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        findings = []
        for index, header_name in enumerate(SECURITY_HEADERS, start=1):
            value = header_value(observation, header_name)
            if value is None:
                title = f"Security header missing: {header_name}"
                description = (
                    f"The security header `{header_name}` was not present in the passive response."
                )
                recommendation = (
                    f"Review whether `{header_name}` should be configured for this application."
                )
            else:
                title = f"Security header present: {header_name}"
                description = f"The `{header_name}` header is configured with value `{value}`."
                recommendation = (
                    f"Review the `{header_name}` policy for expected passive configuration."
                )
            findings.append(
                build_http_finding(
                    finding_id=f"security-header:{header_name}:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.HEADERS,
                    title=title,
                    description=description,
                    recommendation=recommendation,
                    header=f"{header_name}: {value}" if value is not None else header_name,
                    url=observation.final_url,
                    metadata={
                        "header_name": header_name,
                        "header_value": value,
                        "present": value is not None,
                    },
                    references=["https://owasp.org/www-project-secure-headers/"],
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
