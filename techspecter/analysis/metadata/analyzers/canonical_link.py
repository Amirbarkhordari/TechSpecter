"""Canonical link analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class CanonicalLinkAnalyzer(PassiveMetadataAnalyzer):
    """Analyze canonical link metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="canonical-link-analyzer",
            name="Canonical Link Analyzer",
            version="1.0.0",
            description="Analyzes canonical link elements.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        if not html.canonical_links:
            findings = [
                build_metadata_finding(
                    finding_id="canonical:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Canonical link not observed",
                    description="No canonical link was found in the HTML metadata.",
                    url=html.url,
                )
            ]
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

        findings = []
        for index, link in enumerate(html.canonical_links, start=1):
            findings.append(
                build_metadata_finding(
                    finding_id=f"canonical:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Canonical link observed",
                    description=f"Canonical URL `{link}` was observed.",
                    url=link,
                    html_element='<link rel="canonical">',
                    metadata={"canonical_url": link},
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
