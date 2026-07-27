"""Shared text source collection for passive artifact extraction."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.models.discovery import DiscoveryResult


@dataclass(frozen=True, slots=True)
class ArtifactTextSource:
    """A text source scanned for passive artifact indicators."""

    content: str
    source: str
    location: str | None = None


def collect_artifact_text_sources(discovery: DiscoveryResult) -> list[ArtifactTextSource]:
    """Gather text from HTTP, HTML, metadata, scripts, and well-known resources."""
    sources: list[ArtifactTextSource] = []
    target_url = str(discovery.target.url)

    if discovery.http_response is not None:
        http = discovery.http_response
        header_text = "\n".join(f"{k}: {v}" for k, v in http.headers.items())
        if header_text:
            sources.append(
                ArtifactTextSource(content=header_text, source="http-headers", location=target_url),
            )
        for redirect in http.redirects:
            sources.append(
                ArtifactTextSource(
                    content=redirect.url,
                    source="http-redirect",
                    location=redirect.url,
                ),
            )

    if discovery.metadata_observation is not None:
        metadata = discovery.metadata_observation
        if metadata.html is not None:
            html = metadata.html
            html_fields = [
                html.title,
                html.description,
                html.keywords,
                html.author,
                html.generator,
                *html.framework_hints,
                *html.pwa_indicators,
                *html.ssr_indicators,
            ]
            for key, value in html.opengraph.items():
                html_fields.append(f"{key}={value}")
            for key, value in html.twitter_cards.items():
                html_fields.append(f"{key}={value}")
            combined = "\n".join(item for item in html_fields if item)
            if combined:
                sources.append(
                    ArtifactTextSource(content=combined, source="html-metadata", location=html.url),
                )
            for link in html.links:
                sources.append(
                    ArtifactTextSource(
                        content=f"{link.rel} {link.href}",
                        source="html-link",
                        location=html.url,
                    ),
                )
            for comment in html.comments:
                sources.append(
                    ArtifactTextSource(
                        content=comment.content,
                        source="html-comment",
                        location=html.url,
                    ),
                )

        for resource in metadata.well_known_resources:
            if resource.content:
                sources.append(
                    ArtifactTextSource(
                        content=resource.content,
                        source=f"well-known:{resource.resource_type}",
                        location=resource.url,
                    ),
                )

    for script in discovery.inline_scripts:
        sources.append(
            ArtifactTextSource(
                content=script.content,
                source="inline-script",
                location=f"inline-script:{script.index}",
            ),
        )

    for download in discovery.downloads:
        if download.content:
            sources.append(
                ArtifactTextSource(
                    content=download.content,
                    source="external-script",
                    location=str(download.url),
                ),
            )
        sources.append(
            ArtifactTextSource(
                content=str(download.url),
                source="external-script-url",
                location=str(download.url),
            ),
        )

    for external in discovery.external_scripts:
        sources.append(
            ArtifactTextSource(
                content=str(external.url),
                source="external-script-url",
                location=str(external.url),
            ),
        )

    return sources
