"""Generator meta analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class GeneratorMetaAnalyzer(PassiveMetadataAnalyzer):
    """Analyze generator meta tags."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="generator-meta-analyzer",
            name="Generator Meta Analyzer",
            version="1.0.0",
            description="Analyzes HTML generator meta tags.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        if html.generator is None:
            findings = [
                build_metadata_finding(
                    finding_id="generator:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Generator meta tag not observed",
                    description="No generator meta tag was found in the HTML metadata.",
                    url=html.url,
                )
            ]
        else:
            findings = [
                build_metadata_finding(
                    finding_id="generator:observed",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Generator meta tag observed",
                    description=f"Generator metadata indicates `{html.generator}`.",
                    url=html.url,
                    html_element='<meta name="generator">',
                    snippet=html.generator,
                    metadata={"generator": html.generator},
                )
            ]
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
