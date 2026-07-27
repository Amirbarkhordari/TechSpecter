"""Web app manifest analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import Finding, FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation, WellKnownResourceObservation


class WebAppManifestAnalyzer(WellKnownResourceAnalyzer):
    """Analyze web app manifest passive observations."""

    resource_type = "site.webmanifest"
    display_name = "web app manifest"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="web-app-manifest-analyzer",
            name="Web App Manifest Analyzer",
            version="1.0.0",
            description="Analyzes web app manifest resources and HTML manifest links.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        findings = []
        resources = [
            item
            for item in observation.well_known_resources
            if item.resource_type in {"site.webmanifest", "manifest.json"}
        ]
        if observation.html and observation.html.manifest_links:
            for index, link in enumerate(observation.html.manifest_links, start=1):
                findings.append(
                    build_metadata_finding(
                        finding_id=f"web-app-manifest:link:{index}",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.METADATA,
                        title="Web app manifest link observed",
                        description=f"HTML references manifest at `{link}`.",
                        url=link,
                        metadata={"manifest_link": link},
                    )
                )
        if not resources:
            findings.append(
                build_metadata_finding(
                    finding_id="web-app-manifest:missing",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Web app manifest not observed",
                    description="No web app manifest resource was passively collected.",
                    url=observation.html.url if observation.html else None,
                )
            )
        else:
            for index, resource in enumerate(resources, start=1):
                findings.extend(self._findings_for_resource(resource, index=index))
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

    def _findings_for_resource(
        self,
        resource: WellKnownResourceObservation,
        *,
        index: int,
    ) -> list[Finding]:
        return super()._findings_for_resource(resource, index=index)
