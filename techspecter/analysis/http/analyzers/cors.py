"""CORS analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.constants import CORS_HEADERS
from techspecter.analysis.http.helpers import build_http_finding, header_value
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class CorsAnalyzer(PassiveHttpAnalyzer):
    """Analyze Cross-Origin Resource Sharing headers."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="cors-analyzer",
            name="CORS Analyzer",
            version="1.0.0",
            description="Analyzes CORS-related response headers.",
            category=FindingCategory.HTTP.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        findings = []
        for index, header_name in enumerate(CORS_HEADERS, start=1):
            value = header_value(observation, header_name)
            if value is None:
                title = f"CORS header not present: {header_name}"
                description = f"The `{header_name}` header was not observed."
            else:
                title = f"CORS header observed: {header_name}"
                description = f"The `{header_name}` header was observed with value `{value}`."
            findings.append(
                build_http_finding(
                    finding_id=f"cors:{header_name}:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.HTTP,
                    title=title,
                    description=description,
                    header=f"{header_name}: {value}" if value is not None else header_name,
                    url=observation.final_url,
                    metadata={
                        "header_name": header_name,
                        "header_value": value,
                        "present": value is not None,
                    },
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
