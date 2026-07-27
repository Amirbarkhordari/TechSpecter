"""Metadata analyzer identifiers and grouping helpers."""

from __future__ import annotations

METADATA_ANALYZER_IDS: tuple[str, ...] = (
    "robots-analyzer",
    "sitemap-analyzer",
    "security-txt-analyzer",
    "manifest-analyzer",
    "web-app-manifest-analyzer",
    "browserconfig-analyzer",
    "humans-txt-analyzer",
    "ads-txt-analyzer",
    "assetlinks-analyzer",
    "apple-app-site-association-analyzer",
    "html-metadata-analyzer",
    "html-comment-analyzer",
    "opengraph-analyzer",
    "twitter-card-analyzer",
    "canonical-link-analyzer",
    "alternate-link-analyzer",
    "generator-meta-analyzer",
    "theme-color-analyzer",
    "application-metadata-analyzer",
    "language-analyzer",
    "favicon-analyzer",
    "sourcemap-analyzer",
    "service-worker-analyzer",
    "framework-metadata-analyzer",
)

CLI_FLAG_METADATA_MAP: dict[str, tuple[str, ...]] = {
    "metadata_analysis": METADATA_ANALYZER_IDS,
    "well_known": (
        "robots-analyzer",
        "sitemap-analyzer",
        "security-txt-analyzer",
        "humans-txt-analyzer",
        "ads-txt-analyzer",
        "assetlinks-analyzer",
        "apple-app-site-association-analyzer",
    ),
    "manifest": ("manifest-analyzer", "web-app-manifest-analyzer"),
    "robots": ("robots-analyzer",),
    "sitemap": ("sitemap-analyzer",),
    "security_txt": ("security-txt-analyzer",),
    "html_meta": ("html-metadata-analyzer",),
    "framework_meta": ("framework-metadata-analyzer",),
    "sourcemaps": ("sourcemap-analyzer",),
    "service_workers": ("service-worker-analyzer",),
}


def is_metadata_analyzer(analyzer_id: str) -> bool:
    """Return whether an analyzer ID belongs to the metadata analyzer set."""
    return analyzer_id in METADATA_ANALYZER_IDS
