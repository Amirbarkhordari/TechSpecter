"""OpenID Connect artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class OpenIdConnectAnalyzer(TypedArtifactAnalyzer):
    """Detect passive OpenID Connect metadata indicators."""

    artifact_types = ("oidc", "openid", "jwks", "issuer")
    display_name = "OpenID Connect"
    finding_category = FindingCategory.INFRASTRUCTURE

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="openid-connect-analyzer",
            name="OpenID Connect Analyzer",
            version="1.0.0",
            description="Detects passive OIDC discovery and JWKS metadata.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )
