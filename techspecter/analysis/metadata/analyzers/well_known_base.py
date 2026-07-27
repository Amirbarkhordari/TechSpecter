"""Well-known resource analyzer base helpers."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding, find_well_known
from techspecter.analysis.models.finding import Finding, FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation, WellKnownResourceObservation


class WellKnownResourceAnalyzer(PassiveMetadataAnalyzer):
    """Analyze a specific well-known resource type."""

    resource_type: str = ""
    display_name: str = ""

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        resources = find_well_known(observation, self.resource_type)
        findings = []
        if not resources:
            findings.append(
                build_metadata_finding(
                    finding_id=f"{self.resource_type}:missing",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title=f"{self.display_name} not observed",
                    description=(
                        f"The passive collection did not retrieve an available "
                        f"{self.display_name} resource."
                    ),
                    url=observation.html.url if observation.html else None,
                    metadata={"resource_type": self.resource_type, "available": False},
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
        """Build findings for a single resource observation."""
        status = resource.status_code if resource.status_code is not None else "unknown"
        return [
            build_metadata_finding(
                finding_id=f"{self.resource_type}:observed:{index}",
                analyzer_id=self.metadata.id,
                category=FindingCategory.METADATA,
                title=f"{self.display_name} observed",
                description=(
                    f"{self.display_name} is available at `{resource.url}` "
                    f"with status {status} (discovered via {resource.discovered_via})."
                ),
                url=resource.url,
                snippet=_content_preview(resource.content),
                metadata={
                    "resource_type": self.resource_type,
                    "available": resource.available,
                    "status_code": resource.status_code,
                    "content_type": resource.content_type,
                    "discovered_via": resource.discovered_via,
                },
            )
        ]


def _content_preview(content: str | None, *, limit: int = 200) -> str | None:
    """Return a short content preview."""
    if content is None:
        return None
    trimmed = content.strip()
    if len(trimmed) <= limit:
        return trimmed
    return f"{trimmed[:limit]}..."
