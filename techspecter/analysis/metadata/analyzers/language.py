"""Language analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class LanguageAnalyzer(PassiveMetadataAnalyzer):
    """Analyze HTML language metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="language-analyzer",
            name="Language Analyzer",
            version="1.0.0",
            description="Analyzes HTML lang attribute and hreflang alternate links.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        findings = []
        if html.language is None:
            findings.append(
                build_metadata_finding(
                    finding_id="language:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="HTML language not observed",
                    description="The html element did not declare a lang attribute.",
                    url=html.url,
                )
            )
        else:
            findings.append(
                build_metadata_finding(
                    finding_id="language:html",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="HTML language observed",
                    description=f"Document language is `{html.language}`.",
                    url=html.url,
                    html_element='<html lang="...">',
                    metadata={"language": html.language},
                )
            )

        hreflang_links = [link for link in html.alternate_links if link.hreflang]
        if hreflang_links:
            for index, link in enumerate(hreflang_links, start=1):
                findings.append(
                    build_metadata_finding(
                        finding_id=f"language:hreflang:{index}",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.METADATA,
                        title=f"Hreflang alternate observed: {link.hreflang}",
                        description=(
                            f"Alternate link for `{link.hreflang}` points to `{link.href}`."
                        ),
                        url=link.href,
                        metadata={"hreflang": link.hreflang},
                    )
                )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
