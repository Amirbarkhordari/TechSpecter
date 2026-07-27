"""Cache-Control analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.constants import CACHE_HEADERS
from techspecter.analysis.http.helpers import build_http_finding, header_value
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class CacheControlAnalyzer(PassiveHttpAnalyzer):
    """Analyze cache-related HTTP response headers."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="cache-control-analyzer",
            name="Cache-Control Analyzer",
            version="1.0.0",
            description="Analyzes cache and freshness response headers.",
            category=FindingCategory.HEADERS.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        findings = []
        for index, header_name in enumerate(CACHE_HEADERS, start=1):
            value = header_value(observation, header_name)
            if value is None:
                title = f"Cache header not present: {header_name}"
                description = f"The `{header_name}` header was not observed."
            else:
                title = f"Cache header observed: {header_name}"
                description = f"The `{header_name}` header was observed with value `{value}`."
            findings.append(
                build_http_finding(
                    finding_id=f"cache:{header_name}:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.HEADERS,
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
