"""HTML metadata analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class HtmlMetadataAnalyzer(PassiveMetadataAnalyzer):
    """Analyze core HTML metadata fields."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="html-metadata-analyzer",
            name="HTML Metadata Analyzer",
            version="1.0.0",
            description="Analyzes title, description, and core HTML metadata.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(
                analyzer_id=self.metadata.id,
                findings=[],
                errors=["HTML metadata not available."],
            )
        fields = {
            "title": html.title,
            "description": html.description,
            "keywords": html.keywords,
            "author": html.author,
            "viewport": html.viewport,
            "charset": html.charset,
        }
        findings = []
        for field_name, value in fields.items():
            if value is None:
                title = f"HTML {field_name} not observed"
                description = f"The HTML document did not include `{field_name}` metadata."
            else:
                title = f"HTML {field_name} observed"
                description = f"The HTML `{field_name}` metadata is `{value}`."
            findings.append(
                build_metadata_finding(
                    finding_id=f"html-metadata:{field_name}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title=title,
                    description=description,
                    url=html.url,
                    html_element=(
                        f'<meta name="{field_name}">' if field_name != "title" else "<title>"
                    ),
                    snippet=str(value) if value is not None else None,
                    metadata={"field": field_name, "value": value},
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
