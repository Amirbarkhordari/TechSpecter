"""Third-party service artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class ThirdPartyServiceAnalyzer(TypedArtifactAnalyzer):
    """Detect passive third-party service integration references."""

    artifact_types = (
        "hotjar",
        "intercom",
        "zendesk",
        "stripe",
        "paypal",
        "recaptcha",
        "hcaptcha",
    )
    display_name = "Third-Party Service"
    finding_category = FindingCategory.INFORMATION

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="third-party-service-analyzer",
            name="Third-Party Service Analyzer",
            version="1.0.0",
            description="Detects passive third-party integration references.",
            category=FindingCategory.INFORMATION.value,
        )
