"""Artifact analyzer identifiers and grouping helpers."""

from __future__ import annotations

ARTIFACT_ANALYZER_IDS: tuple[str, ...] = (
    "api-key-analyzer",
    "jwt-analyzer",
    "oauth-metadata-analyzer",
    "openid-connect-analyzer",
    "graphql-metadata-analyzer",
    "openapi-analyzer",
    "firebase-analyzer",
    "aws-metadata-analyzer",
    "azure-metadata-analyzer",
    "google-cloud-metadata-analyzer",
    "cdn-analyzer",
    "third-party-service-analyzer",
    "analytics-service-analyzer",
    "monitoring-service-analyzer",
    "technology-exposure-analyzer",
)

CLI_FLAG_ARTIFACT_MAP: dict[str, tuple[str, ...]] = {
    "artifact_analysis": ARTIFACT_ANALYZER_IDS,
    "cloud_analysis": (
        "firebase-analyzer",
        "aws-metadata-analyzer",
        "azure-metadata-analyzer",
        "google-cloud-metadata-analyzer",
        "cdn-analyzer",
    ),
    "identity_analysis": (
        "jwt-analyzer",
        "oauth-metadata-analyzer",
        "openid-connect-analyzer",
        "api-key-analyzer",
    ),
    "graphql": ("graphql-metadata-analyzer",),
    "openapi": ("openapi-analyzer",),
    "firebase": ("firebase-analyzer",),
    "oauth": ("oauth-metadata-analyzer", "openid-connect-analyzer"),
    "third_party": ("third-party-service-analyzer",),
    "analytics": ("analytics-service-analyzer",),
    "monitoring": ("monitoring-service-analyzer",),
}


def is_artifact_analyzer(analyzer_id: str) -> bool:
    """Return whether an analyzer ID belongs to the artifact analyzer set."""
    return analyzer_id in ARTIFACT_ANALYZER_IDS
