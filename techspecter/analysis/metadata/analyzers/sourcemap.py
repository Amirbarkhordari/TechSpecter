"""SourceMap analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class SourceMapAnalyzer(PassiveMetadataAnalyzer):
    """Analyze passive SourceMap references."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="sourcemap-analyzer",
            name="SourceMap Analyzer",
            version="1.0.0",
            description="Detects sourceMappingURL references without analyzing source code.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        references = observation.sourcemap_references
        if not references:
            url = observation.html.url if observation.html else None
            findings = [
                build_metadata_finding(
                    finding_id="sourcemap:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="SourceMap references not observed",
                    description="No sourceMappingURL references were detected passively.",
                    url=url,
                )
            ]
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

        findings = []
        for index, reference in enumerate(references, start=1):
            map_type = "inline" if reference.inline else "external"
            findings.append(
                build_metadata_finding(
                    finding_id=f"sourcemap:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title=f"SourceMap reference observed ({map_type})",
                    description=(
                        f"A {map_type} SourceMap reference was detected via " f"{reference.source}."
                    ),
                    url=reference.url,
                    location=reference.location,
                    metadata={
                        "inline": reference.inline,
                        "reference_source": reference.source,
                        "location": reference.location,
                    },
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
