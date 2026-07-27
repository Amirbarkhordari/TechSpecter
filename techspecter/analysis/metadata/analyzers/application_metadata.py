"""Application metadata analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.helpers import build_metadata_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class ApplicationMetadataAnalyzer(PassiveMetadataAnalyzer):
    """Analyze application-name and verification metadata."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="application-metadata-analyzer",
            name="Application Metadata Analyzer",
            version="1.0.0",
            description="Analyzes application-name and site verification metadata.",
            category=FindingCategory.METADATA.value,
        )

    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        html = observation.html
        if html is None:
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=[], errors=["No HTML."])
        findings = []
        if html.application_name is None:
            findings.append(
                build_metadata_finding(
                    finding_id="application-name:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Application name not observed",
                    description="No application-name meta tag was found.",
                    url=html.url,
                )
            )
        else:
            findings.append(
                build_metadata_finding(
                    finding_id="application-name:observed",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Application name observed",
                    description=f"Application name is `{html.application_name}`.",
                    url=html.url,
                    metadata={"application_name": html.application_name},
                )
            )

        if not html.verification:
            findings.append(
                build_metadata_finding(
                    finding_id="verification:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.METADATA,
                    title="Verification metadata not observed",
                    description="No site verification meta tags were found.",
                    url=html.url,
                )
            )
        else:
            for index, (key, value) in enumerate(sorted(html.verification.items()), start=1):
                findings.append(
                    build_metadata_finding(
                        finding_id=f"verification:{index}",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.METADATA,
                        title=f"Verification metadata observed: {key}",
                        description=f"Verification tag `{key}` is present.",
                        url=html.url,
                        snippet=value,
                        metadata={"verification_key": key},
                    )
                )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
