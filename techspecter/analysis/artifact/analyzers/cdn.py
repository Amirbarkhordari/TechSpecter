"""CDN artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class CdnAnalyzer(TypedArtifactAnalyzer):
    """Detect passive CDN and edge hosting indicators."""

    artifact_types = ("cloudflare", "fastly", "akamai", "netlify", "vercel", "github-pages")
    display_name = "CDN"
    finding_category = FindingCategory.INFRASTRUCTURE

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="cdn-analyzer",
            name="CDN Analyzer",
            version="1.0.0",
            description="Detects passive CDN and static hosting provider references.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )
