"""Content-Type analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.helpers import build_http_finding, header_value
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class ContentTypeAnalyzer(PassiveHttpAnalyzer):
    """Analyze Content-Type and encoding headers."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="content-type-analyzer",
            name="Content-Type Analyzer",
            version="1.0.0",
            description="Analyzes content type and encoding headers.",
            category=FindingCategory.HTTP.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        content_type = header_value(observation, "content-type") or observation.content_type
        encoding = header_value(observation, "content-encoding") or observation.content_encoding
        findings = [
            build_http_finding(
                finding_id="content-type:primary",
                analyzer_id=self.metadata.id,
                category=FindingCategory.HTTP,
                title="Content-Type observed" if content_type else "Content-Type missing",
                description=(
                    f"Content-Type is `{content_type}`."
                    if content_type
                    else "The response did not include a Content-Type header."
                ),
                header=f"content-type: {content_type}" if content_type else "content-type",
                url=observation.final_url,
                metadata={"content_type": content_type},
            ),
            build_http_finding(
                finding_id="content-type:encoding",
                analyzer_id=self.metadata.id,
                category=FindingCategory.HTTP,
                title="Content-Encoding observed" if encoding else "Content-Encoding not observed",
                description=(
                    f"Content-Encoding is `{encoding}`."
                    if encoding
                    else "No Content-Encoding header was observed."
                ),
                header=f"content-encoding: {encoding}" if encoding else "content-encoding",
                url=observation.final_url,
                metadata={"content_encoding": encoding},
            ),
        ]
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
