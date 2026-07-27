"""HTML metadata extraction for passive analysis."""

from __future__ import annotations

import logging
import re
from contextlib import suppress
from dataclasses import dataclass

from bs4 import BeautifulSoup, Comment
from bs4.element import Tag

from techspecter.exceptions import ParserError
from techspecter.models.metadata import (
    HtmlCommentObservation,
    HtmlLinkObservation,
    HtmlMetadataObservation,
    HtmlMetaTagObservation,
    ServiceWorkerReferenceObservation,
    SourceMapReferenceObservation,
)
from techspecter.parser.sourcemap import detect_source_map_url
from techspecter.utils.url import resolve_url

logger = logging.getLogger(__name__)

_SERVICE_WORKER_PATTERN = re.compile(
    r"navigator\.serviceWorker\.register\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_FRAMEWORK_HINTS: dict[str, tuple[str, ...]] = {
    "next.js": ("__NEXT_DATA__", "_next/static", "next/dist"),
    "nuxt": ("__NUXT__", "nuxt", "_nuxt/"),
    "react": ("data-reactroot", "react-root", "__REACT_DEVTOOLS"),
    "vue": ("data-v-", "vue-app", "__VUE__"),
    "angular": ("ng-version", "ng-app", "angular"),
    "wordpress": ("wp-content", "wp-includes", "WordPress"),
    "drupal": ("Drupal", "drupal-settings"),
}


@dataclass(frozen=True, slots=True)
class HtmlMetadataParseResult:
    """Parsed HTML metadata and passive references."""

    html_metadata: HtmlMetadataObservation
    sourcemap_references: list[SourceMapReferenceObservation]
    service_worker_references: list[ServiceWorkerReferenceObservation]
    linked_resource_urls: dict[str, list[str]]


class HtmlMetadataParser:
    """Extract passive HTML metadata from a document."""

    def parse(self, html: str, *, base_url: str) -> HtmlMetadataParseResult:
        """Parse HTML and extract metadata observations."""
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception as exc:
            msg = f"Failed to parse HTML metadata: {exc}"
            raise ParserError(msg) from exc

        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else None
        language = _attr_str(soup.html.get("lang")) if soup.html is not None else None

        meta_tags: list[HtmlMetaTagObservation] = []
        description = keywords = author = generator = viewport = None
        theme_color = application_name = charset = None
        opengraph: dict[str, str] = {}
        twitter_cards: dict[str, str] = {}
        verification: dict[str, str] = {}

        for meta in soup.find_all("meta"):
            if not isinstance(meta, Tag):
                continue
            meta_observation = _parse_meta_tag(meta)
            meta_tags.append(meta_observation)

            name = (meta_observation.name or "").lower()
            prop = (meta_observation.property or "").lower()
            content = meta_observation.content

            if meta_observation.charset:
                charset = meta_observation.charset
            if name == "description":
                description = content
            elif name == "keywords":
                keywords = content
            elif name == "author":
                author = content
            elif name == "generator":
                generator = content
            elif name == "viewport":
                viewport = content
            elif name == "theme-color":
                theme_color = content
            elif name == "application-name":
                application_name = content
            elif prop.startswith("og:"):
                opengraph[prop] = content
            elif name.startswith("twitter:") or prop.startswith("twitter:"):
                key = name or prop
                twitter_cards[key] = content
            elif name.endswith("-site-verification") or "verification" in name:
                verification[name or prop] = content

        links: list[HtmlLinkObservation] = []
        icons: list[HtmlLinkObservation] = []
        rss_feeds: list[HtmlLinkObservation] = []
        alternate_links: list[HtmlLinkObservation] = []
        canonical_links: list[str] = []
        manifest_links: list[str] = []
        linked_resources: dict[str, list[str]] = {
            "manifest": [],
            "browserconfig": [],
            "favicon": [],
            "site.webmanifest": [],
        }

        for link in soup.find_all("link"):
            if not isinstance(link, Tag):
                continue
            link_observation = _parse_link_tag(link, base_url=base_url)
            if link_observation is None:
                continue
            links.append(link_observation)
            rel_tokens = {token.strip().lower() for token in link_observation.rel.split()}
            if "canonical" in rel_tokens:
                canonical_links.append(link_observation.href)
            if "alternate" in rel_tokens:
                alternate_links.append(link_observation)
            if "icon" in rel_tokens or "shortcut icon" in link_observation.rel.lower():
                icons.append(link_observation)
                linked_resources["favicon"].append(link_observation.href)
            if link_observation.type and "rss" in link_observation.type.lower():
                rss_feeds.append(link_observation)
            if (
                "alternate" in rel_tokens
                and link_observation.type
                and "rss" in link_observation.type.lower()
            ):
                rss_feeds.append(link_observation)
            if "manifest" in rel_tokens:
                manifest_links.append(link_observation.href)
                linked_resources["manifest"].append(link_observation.href)
            if "serviceworker" in rel_tokens:
                linked_resources.setdefault("serviceworker", []).append(link_observation.href)
            if any(token in rel_tokens for token in ("apple-touch-icon",)):
                icons.append(link_observation)

        comments = [
            HtmlCommentObservation(index=index, content=str(comment).strip())
            for index, comment in enumerate(
                soup.find_all(string=lambda text: isinstance(text, Comment))
            )
            if str(comment).strip()
        ]

        sourcemap_refs = _collect_sourcemap_references(soup, base_url=base_url)
        service_worker_refs = _collect_service_worker_references(
            soup, base_url=base_url, links=links
        )
        framework_hints = _detect_framework_hints(html, generator=generator)
        pwa_indicators = _detect_pwa_indicators(manifest_links, service_worker_refs, meta_tags)
        ssr_indicators = _detect_ssr_indicators(html, framework_hints)

        html_metadata = HtmlMetadataObservation(
            url=base_url,
            title=title,
            description=description,
            keywords=keywords,
            author=author,
            generator=generator,
            viewport=viewport,
            theme_color=theme_color,
            application_name=application_name,
            language=language,
            charset=charset,
            meta_tags=meta_tags,
            links=links,
            comments=comments,
            opengraph=opengraph,
            twitter_cards=twitter_cards,
            verification=verification,
            icons=icons,
            rss_feeds=rss_feeds,
            canonical_links=canonical_links,
            alternate_links=alternate_links,
            manifest_links=manifest_links,
            framework_hints=framework_hints,
            pwa_indicators=pwa_indicators,
            ssr_indicators=ssr_indicators,
        )

        logger.info(
            "Extracted HTML metadata for %s: %d meta tags, %d links, %d comments",
            base_url,
            len(meta_tags),
            len(links),
            len(comments),
        )
        return HtmlMetadataParseResult(
            html_metadata=html_metadata,
            sourcemap_references=sourcemap_refs,
            service_worker_references=service_worker_refs,
            linked_resource_urls=linked_resources,
        )


def _parse_meta_tag(meta: Tag) -> HtmlMetaTagObservation:
    """Parse a meta tag into an observation."""
    return HtmlMetaTagObservation(
        name=_attr_str(meta.get("name")),
        property=_attr_str(meta.get("property")),
        content=str(meta.get("content", "")).strip(),
        http_equiv=_attr_str(meta.get("http-equiv")),
        charset=_attr_str(meta.get("charset")),
    )


def _parse_link_tag(link: Tag, *, base_url: str) -> HtmlLinkObservation | None:
    """Parse a link tag into an observation."""
    href = link.get("href")
    rel = link.get("rel")
    if href is None or rel is None:
        return None
    href_value = str(href).strip()
    if not href_value:
        return None
    rel_value = " ".join(rel) if isinstance(rel, list) else str(rel)
    try:
        absolute_href = resolve_url(base_url, href_value)
    except Exception:
        absolute_href = href_value
    return HtmlLinkObservation(
        rel=rel_value.strip(),
        href=absolute_href,
        type=_attr_str(link.get("type")),
        sizes=_attr_str(link.get("sizes")),
        title=_attr_str(link.get("title")),
        hreflang=_attr_str(link.get("hreflang")),
    )


def _attr_str(value: object | None) -> str | None:
    """Coerce a BeautifulSoup attribute value to a string."""
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _collect_sourcemap_references(
    soup: BeautifulSoup,
    *,
    base_url: str,
) -> list[SourceMapReferenceObservation]:
    """Collect passive SourceMap references from scripts."""
    references: list[SourceMapReferenceObservation] = []
    for index, script in enumerate(soup.find_all("script")):
        if not isinstance(script, Tag):
            continue
        src = script.get("src")
        if src:
            references.append(
                SourceMapReferenceObservation(
                    url=str(src),
                    inline=False,
                    source="external-script",
                    location=str(src),
                )
            )
            continue
        content = script.string or script.get_text()
        if not content:
            continue
        source_map = detect_source_map_url(content, base_url=base_url)
        if source_map:
            references.append(
                SourceMapReferenceObservation(
                    url=source_map,
                    inline=source_map.startswith("data:"),
                    source="inline-script",
                    location=f"inline-script:{index}",
                )
            )
    return references


def _collect_service_worker_references(
    soup: BeautifulSoup,
    *,
    base_url: str,
    links: list[HtmlLinkObservation],
) -> list[ServiceWorkerReferenceObservation]:
    """Collect passive service worker references."""
    references: list[ServiceWorkerReferenceObservation] = []
    for link in links:
        if "serviceworker" in link.rel.lower():
            references.append(
                ServiceWorkerReferenceObservation(
                    script_url=link.href,
                    source="link-rel-serviceworker",
                    inline=False,
                    scope=None,
                )
            )

    for _index, script in enumerate(soup.find_all("script")):
        if not isinstance(script, Tag):
            continue
        content = script.string or script.get_text()
        if not content:
            continue
        for match in _SERVICE_WORKER_PATTERN.finditer(content):
            script_url = match.group(1)
            with suppress(Exception):
                script_url = resolve_url(base_url, script_url)
            references.append(
                ServiceWorkerReferenceObservation(
                    script_url=script_url,
                    source="inline-script-registration",
                    inline=True,
                    scope=None,
                )
            )
    return references


def _detect_framework_hints(html: str, *, generator: str | None) -> list[str]:
    """Detect passive framework hints."""
    hints: list[str] = []
    if generator:
        hints.append(f"generator:{generator}")
    lowered = html.lower()
    for framework, markers in _FRAMEWORK_HINTS.items():
        if any(marker.lower() in lowered for marker in markers):
            hints.append(framework)
    return sorted(set(hints))


def _detect_pwa_indicators(
    manifest_links: list[str],
    service_workers: list[ServiceWorkerReferenceObservation],
    meta_tags: list[HtmlMetaTagObservation],
) -> list[str]:
    """Detect passive PWA indicators."""
    indicators: list[str] = []
    if manifest_links:
        indicators.append("manifest-link-present")
    if service_workers:
        indicators.append("service-worker-reference-present")
    for meta in meta_tags:
        name = (meta.name or "").lower()
        if name == "mobile-web-app-capable" or name == "apple-mobile-web-app-capable":
            indicators.append(name)
    return indicators


def _detect_ssr_indicators(html: str, framework_hints: list[str]) -> list[str]:
    """Detect passive SSR indicators."""
    indicators: list[str] = []
    if "__NEXT_DATA__" in html:
        indicators.append("next-data-ssr")
    if "__NUXT__" in html:
        indicators.append("nuxt-ssr")
    if "window.__INITIAL_STATE__" in html:
        indicators.append("initial-state-hydration")
    if framework_hints:
        indicators.append("framework-metadata-present")
    return indicators
