"""Alternate link analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class AlternateLinkAnalyzer(PassiveMetadataAnalyzer):
    """Analyze alternate link metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="alternate-link-analyzer",
            name="Alternate Link Analyzer",
            version="1.0.0",
            description="Analyzes alternate link elements including hreflang and RSS.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        links = html.alternate_links
        if not links:
            findings = [
                build_metadata_finding(
                    finding_id="alternate:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Alternate links not observed",
                    description="No alternate link elements were found.",
                    url=html.url,
                )
            ]
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

        findings = []
        for index, link in enumerate(links, start=1):
            findings.append(
                build_metadata_finding(
                    finding_id=f"alternate:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title=f"Alternate link observed: {link.rel}",
                    description=f"Alternate link `{link.href}` was observed.",
                    url=link.href,
                    html_element=f'<link rel="{link.rel}">',
                    metadata={
                        "rel": link.rel,
                        "hreflang": link.hreflang,
                        "type": link.type,
                    },
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
