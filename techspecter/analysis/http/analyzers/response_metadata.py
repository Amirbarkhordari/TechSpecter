"""HTTP response metadata analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.helpers import build_http_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class HttpResponseMetadataAnalyzer(PassiveHttpAnalyzer):
    """Analyze passive HTTP response metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="http-response-metadata-analyzer",
            name="HTTP Response Metadata Analyzer",
            version="1.0.0",
            description="Analyzes status code, size, encoding, protocol, and timing metadata.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        findings = [
            build_http_finding(
                finding_id="http-metadata:status",
                analyzer_id=self.metadata.id,
                category=FindingCategory.METADATA,
                title=f"HTTP status code {observation.status_code}",
                description=(
                    f"The final passive response returned status {observation.status_code}."
                ),
                url=observation.final_url,
                metadata={"status_code": observation.status_code},
            ),
            build_http_finding(
                finding_id="http-metadata:size",
                analyzer_id=self.metadata.id,
                category=FindingCategory.METADATA,
                title="Response size observed",
                description=f"Response body size is {observation.body_size} bytes.",
                url=observation.final_url,
                metadata={
                    "body_size": observation.body_size,
                    "content_length": observation.content_length,
                },
            ),
            build_http_finding(
                finding_id="http-metadata:protocol",
                analyzer_id=self.metadata.id,
                category=FindingCategory.METADATA,
                title="Protocol metadata",
                description=(
                    f"Protocol `{observation.protocol}` with encoding "
                    f"`{observation.content_encoding or 'none'}`."
                ),
                url=observation.final_url,
                metadata={
                    "protocol": observation.protocol,
                    "content_encoding": observation.content_encoding,
                    "transfer_encoding": observation.transfer_encoding,
                    "elapsed_ms": observation.elapsed_ms,
                },
            ),
        ]
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
