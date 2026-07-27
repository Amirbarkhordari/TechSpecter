"""HTML comment analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class HtmlCommentAnalyzer(PassiveMetadataAnalyzer):
    """Analyze HTML comments passively."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="html-comment-analyzer",
            name="HTML Comment Analyzer",
            version="1.0.0",
            description="Analyzes HTML comments in the passive page response.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        if not html.comments:
            findings = [
                build_metadata_finding(
                    finding_id="html-comment:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="No HTML comments observed",
                    description="The HTML document did not contain parseable comments.",
                    url=html.url,
                )
            ]
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

        findings = []
        for comment in html.comments[:20]:
            findings.append(
                build_metadata_finding(
                    finding_id=f"html-comment:{comment.index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title=f"HTML comment {comment.index + 1}",
                    description="An HTML comment was observed in the passive response.",
                    url=html.url,
                    html_element="<!-- ... -->",
                    snippet=comment.content[:200],
                    metadata={"index": comment.index},
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
