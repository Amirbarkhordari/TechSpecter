"""Server fingerprint analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.helpers import build_http_finding, header_value
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class ServerFingerprintAnalyzer(PassiveHttpAnalyzer):
    """Analyze server and framework disclosure headers."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="server-fingerprint-analyzer",
            name="Server Fingerprint Analyzer",
            version="1.0.0",
            description="Analyzes server and framework disclosure headers.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        headers = ("server", "x-powered-by", "via")
        findings = []
        for index, header_name in enumerate(headers, start=1):
            value = header_value(observation, header_name)
            if value is None:
                title = f"Fingerprint header not present: {header_name}"
                description = f"The `{header_name}` header was not observed."
            else:
                title = f"Fingerprint header observed: {header_name}"
                description = f"The `{header_name}` header exposes `{value}`."
            findings.append(
                build_http_finding(
                    finding_id=f"server-fingerprint:{header_name}:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.INFRASTRUCTURE,
                    title=title,
                    description=description,
                    header=f"{header_name}: {value}" if value is not None else header_name,
                    url=observation.final_url,
                    metadata={"header_name": header_name, "header_value": value},
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
