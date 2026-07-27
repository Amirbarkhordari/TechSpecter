"""Favicon analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding, find_well_known
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class FaviconAnalyzer(PassiveMetadataAnalyzer):
    """Analyze favicon metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="favicon-analyzer",
            name="Favicon Analyzer",
            version="1.0.0",
            description="Analyzes favicon links and favicon.ico resources.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        findings = []
        if html and html.icons:
            for index, icon in enumerate(html.icons, start=1):
                findings.append(
                    build_metadata_finding(
                        finding_id=f"favicon:link:{index}",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.METADATA,
                        title=f"Favicon link observed: {icon.rel}",
                        description=f"Icon link points to `{icon.href}`.",
                        url=icon.href,
                        html_element=f'<link rel="{icon.rel}">',
                        metadata={"rel": icon.rel, "sizes": icon.sizes},
                    )
                )

        favicon_resources = find_well_known(observation, "favicon.ico")
        for index, resource in enumerate(favicon_resources, start=1):
            if resource.available:
                findings.append(
                    build_metadata_finding(
                        finding_id=f"favicon:resource:{index}",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.METADATA,
                        title="favicon.ico observed",
                        description=f"favicon.ico is available at `{resource.url}`.",
                        url=resource.url,
                        metadata={"status_code": resource.status_code},
                    )
                )

        if not findings:
            findings.append(
                build_metadata_finding(
                    finding_id="favicon:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Favicon not observed",
                    description="No favicon links or favicon.ico resource were observed.",
                    url=html.url if html else None,
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
