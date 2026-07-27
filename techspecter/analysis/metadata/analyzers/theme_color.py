"""Theme color analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class ThemeColorAnalyzer(PassiveMetadataAnalyzer):
    """Analyze theme-color metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="theme-color-analyzer",
            name="Theme Color Analyzer",
            version="1.0.0",
            description="Analyzes theme-color meta tags.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        if html.theme_color is None:
            findings = [
                build_metadata_finding(
                    finding_id="theme-color:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Theme color not observed",
                    description="No theme-color meta tag was found.",
                    url=html.url,
                )
            ]
        else:
            findings = [
                build_metadata_finding(
                    finding_id="theme-color:observed",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Theme color observed",
                    description=f"Theme color is `{html.theme_color}`.",
                    url=html.url,
                    html_element='<meta name="theme-color">',
                    snippet=html.theme_color,
                    metadata={"theme_color": html.theme_color},
                )
            ]
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
