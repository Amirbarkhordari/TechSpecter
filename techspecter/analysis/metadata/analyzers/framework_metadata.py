"""Framework metadata analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class FrameworkMetadataAnalyzer(PassiveMetadataAnalyzer):
    """Analyze passive framework and CMS metadata indicators."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="framework-metadata-analyzer",
            name="Framework Metadata Analyzer",
            version="1.0.0",
            description="Analyzes generator tags, framework hints, SSR and CMS metadata.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        findings = []
        if not html.framework_hints:
            findings.append(
                build_metadata_finding(
                    finding_id="framework:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Framework metadata not observed",
                    description="No passive framework indicators were detected.",
                    url=html.url,
                )
            )
        else:
            for index, hint in enumerate(html.framework_hints, start=1):
                findings.append(
                    build_metadata_finding(
                        finding_id=f"framework:hint:{index}",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.METADATA,
                        title=f"Framework hint observed: {hint}",
                        description=f"Passive framework indicator `{hint}` was detected.",
                        url=html.url,
                        metadata={"hint": hint},
                    )
                )

        if html.ssr_indicators:
            findings.append(
                build_metadata_finding(
                    finding_id="framework:ssr",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="SSR indicators observed",
                    description=f"SSR indicators: {', '.join(html.ssr_indicators)}.",
                    url=html.url,
                    metadata={"ssr_indicators": html.ssr_indicators},
                )
            )
        if html.generator:
            findings.append(
                build_metadata_finding(
                    finding_id="framework:generator",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Generator metadata observed",
                    description=f"Generator tag reports `{html.generator}`.",
                    url=html.url,
                    metadata={"generator": html.generator},
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
