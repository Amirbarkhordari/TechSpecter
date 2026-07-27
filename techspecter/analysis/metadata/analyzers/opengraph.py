"""OpenGraph analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class OpenGraphAnalyzer(PassiveMetadataAnalyzer):
    """Analyze OpenGraph metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="opengraph-analyzer",
            name="OpenGraph Analyzer",
            version="1.0.0",
            description="Analyzes OpenGraph meta properties.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        if not html.opengraph:
            findings = [
                build_metadata_finding(
                    finding_id="opengraph:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="OpenGraph metadata not observed",
                    description="No OpenGraph properties were found in the HTML metadata.",
                    url=html.url,
                )
            ]
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

        findings = []
        for index, (key, value) in enumerate(sorted(html.opengraph.items()), start=1):
            findings.append(
                build_metadata_finding(
                    finding_id=f"opengraph:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title=f"OpenGraph property observed: {key}",
                    description=f"OpenGraph `{key}` is set to `{value}`.",
                    url=html.url,
                    html_element=f'<meta property="{key}">',
                    snippet=value,
                    metadata={"property": key, "value": value},
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
