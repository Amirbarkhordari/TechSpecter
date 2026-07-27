"""Metadata observation models for passive analysis."""

from __future__ import annotations

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class HtmlMetaTagObservation(TechSpecterModel):
    """Parsed HTML meta tag."""

    name: str | None = None
    property: str | None = None
    content: str
    http_equiv: str | None = None
    charset: str | None = None


class HtmlLinkObservation(TechSpecterModel):
    """Parsed HTML link element."""

    rel: str
    href: str
    type: str | None = None
    sizes: str | None = None
    title: str | None = None
    hreflang: str | None = None


class HtmlCommentObservation(TechSpecterModel):
    """Parsed HTML comment."""

    index: int
    content: str


class SourceMapReferenceObservation(TechSpecterModel):
    """Passive SourceMap reference observation."""

    url: str | None = None
    inline: bool = False
    source: str
    location: str | None = None


class ServiceWorkerReferenceObservation(TechSpecterModel):
    """Passive service worker registration reference."""

    script_url: str | None = None
    source: str
    inline: bool = False
    scope: str | None = None


class HtmlMetadataObservation(TechSpecterModel):
    """Extracted HTML page metadata."""

    url: str
    title: str | None = None
    description: str | None = None
    keywords: str | None = None
    author: str | None = None
    generator: str | None = None
    viewport: str | None = None
    theme_color: str | None = None
    application_name: str | None = None
    language: str | None = None
    charset: str | None = None
    meta_tags: list[HtmlMetaTagObservation] = Field(default_factory=list)
    links: list[HtmlLinkObservation] = Field(default_factory=list)
    comments: list[HtmlCommentObservation] = Field(default_factory=list)
    opengraph: dict[str, str] = Field(default_factory=dict)
    twitter_cards: dict[str, str] = Field(default_factory=dict)
    verification: dict[str, str] = Field(default_factory=dict)
    icons: list[HtmlLinkObservation] = Field(default_factory=list)
    rss_feeds: list[HtmlLinkObservation] = Field(default_factory=list)
    canonical_links: list[str] = Field(default_factory=list)
    alternate_links: list[HtmlLinkObservation] = Field(default_factory=list)
    manifest_links: list[str] = Field(default_factory=list)
    framework_hints: list[str] = Field(default_factory=list)
    pwa_indicators: list[str] = Field(default_factory=list)
    ssr_indicators: list[str] = Field(default_factory=list)


class WellKnownResourceObservation(TechSpecterModel):
    """Passive well-known resource observation."""

    resource_type: str
    url: str
    status_code: int | None = None
    content_type: str | None = None
    content: str | None = None
    available: bool = False
    discovered_via: str = "well-known-path"


class MetadataDiscoveryObservation(TechSpecterModel):
    """Complete passive metadata discovery observation."""

    html: HtmlMetadataObservation | None = None
    well_known_resources: list[WellKnownResourceObservation] = Field(default_factory=list)
    sourcemap_references: list[SourceMapReferenceObservation] = Field(default_factory=list)
    service_worker_references: list[ServiceWorkerReferenceObservation] = Field(default_factory=list)
