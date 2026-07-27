"""Twitter Card analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class TwitterCardAnalyzer(PassiveMetadataAnalyzer):
    """Analyze Twitter Card metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="twitter-card-analyzer",
            name="Twitter Card Analyzer",
            version="1.0.0",
            description="Analyzes Twitter Card meta properties.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        if not html.twitter_cards:
            findings = [
                build_metadata_finding(
                    finding_id="twitter-card:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Twitter Card metadata not observed",
                    description="No Twitter Card properties were found in the HTML metadata.",
                    url=html.url,
                )
            ]
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

        findings = []
        for index, (key, value) in enumerate(sorted(html.twitter_cards.items()), start=1):
            findings.append(
                build_metadata_finding(
                    finding_id=f"twitter-card:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title=f"Twitter Card property observed: {key}",
                    description=f"Twitter Card `{key}` is set to `{value}`.",
                    url=html.url,
                    html_element=f'<meta name="{key}">',
                    snippet=value,
                    metadata={"property": key, "value": value},
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
