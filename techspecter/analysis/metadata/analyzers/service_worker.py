"""Service worker analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class ServiceWorkerAnalyzer(PassiveMetadataAnalyzer):
    """Analyze passive service worker references."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="service-worker-analyzer",
            name="Service Worker Analyzer",
            version="1.0.0",
            description="Detects service worker registration metadata passively.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        references = observation.service_worker_references
        html = observation.html
        if not references:
            findings = [
                build_metadata_finding(
                    finding_id="service-worker:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Service worker references not observed",
                    description="No service worker registration metadata was detected.",
                    url=html.url if html else None,
                )
            ]
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

        findings = []
        for index, reference in enumerate(references, start=1):
            findings.append(
                build_metadata_finding(
                    finding_id=f"service-worker:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Service worker reference observed",
                    description=(
                        f"Service worker reference detected via {reference.source} "
                        f"pointing to `{reference.script_url}`."
                    ),
                    url=reference.script_url,
                    metadata={
                        "inline": reference.inline,
                        "reference_source": reference.source,
                        "scope": reference.scope,
                    },
                )
            )

        if html and html.pwa_indicators:
            findings.append(
                build_metadata_finding(
                    finding_id="service-worker:pwa-indicators",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="PWA indicators observed",
                    description=f"PWA indicators: {', '.join(html.pwa_indicators)}.",
                    url=html.url,
                    metadata={"pwa_indicators": html.pwa_indicators},
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
