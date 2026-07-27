"""Shared fixtures for metadata analysis tests."""

from __future__ import annotations

from techspecter.models.discovery import DiscoveryResult, Target
from techspecter.models.metadata import (
    HtmlCommentObservation,
    HtmlLinkObservation,
    HtmlMetadataObservation,
    MetadataDiscoveryObservation,
    ServiceWorkerReferenceObservation,
    SourceMapReferenceObservation,
    WellKnownResourceObservation,
)


def sample_html_metadata(**overrides: object) -> HtmlMetadataObservation:
    """Return representative HTML metadata."""
    data = {
        "url": "https://example.com/",
        "title": "Example Site",
        "description": "An example website",
        "keywords": "example, demo",
        "author": "Example Author",
        "generator": "WordPress 6.0",
        "viewport": "width=device-width, initial-scale=1",
        "theme_color": "#ffffff",
        "application_name": "Example App",
        "language": "en",
        "charset": "utf-8",
        "opengraph": {"og:title": "Example", "og:description": "An example website"},
        "twitter_cards": {"twitter:card": "summary"},
        "verification": {"google-site-verification": "abc123"},
        "canonical_links": ["https://example.com/"],
        "alternate_links": [
            HtmlLinkObservation(
                rel="alternate", href="https://example.com/feed", type="application/rss+xml"
            ),
        ],
        "manifest_links": ["https://example.com/manifest.json"],
        "icons": [HtmlLinkObservation(rel="icon", href="https://example.com/favicon.ico")],
        "comments": [HtmlCommentObservation(index=0, content="Built with Example CMS")],
        "framework_hints": ["wordpress", "generator:WordPress 6.0"],
        "pwa_indicators": ["manifest-link-present"],
        "ssr_indicators": ["framework-metadata-present"],
    }
    data.update(overrides)
    return HtmlMetadataObservation(**data)  # type: ignore[arg-type]


def sample_metadata_observation(**overrides: object) -> MetadataDiscoveryObservation:
    """Return a full metadata discovery observation."""
    data = {
        "html": sample_html_metadata(),
        "well_known_resources": [
            WellKnownResourceObservation(
                resource_type="robots.txt",
                url="https://example.com/robots.txt",
                status_code=200,
                content="User-agent: *\nDisallow:",
                available=True,
                discovered_via="well-known-path",
            ),
            WellKnownResourceObservation(
                resource_type="security.txt",
                url="https://example.com/.well-known/security.txt",
                status_code=200,
                content="Contact: security@example.com",
                available=True,
                discovered_via="well-known-path",
            ),
        ],
        "sourcemap_references": [
            SourceMapReferenceObservation(
                url="https://example.com/app.js.map",
                inline=False,
                source="inline-script",
                location="inline-script:0",
            )
        ],
        "service_worker_references": [
            ServiceWorkerReferenceObservation(
                script_url="https://example.com/sw.js",
                source="inline-script-registration",
                inline=True,
            )
        ],
    }
    data.update(overrides)
    return MetadataDiscoveryObservation(**data)  # type: ignore[arg-type]


def sample_discovery_with_metadata(**overrides: object) -> DiscoveryResult:
    """Return a discovery result with metadata observation."""
    data = {
        "target": Target(original_url="https://example.com", url="https://example.com/"),
        "metadata_observation": sample_metadata_observation(),
        "elapsed_ms": 100.0,
    }
    data.update(overrides)
    return DiscoveryResult(**data)  # type: ignore[arg-type]
