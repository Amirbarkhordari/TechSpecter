"""Passive asset reference extraction from HTML."""

from __future__ import annotations

import logging
import re

from bs4 import BeautifulSoup, Comment
from bs4.element import Tag

from techspecter.asset_discovery.models import AssetCategory, AssetDiscoverySource, AssetReference
from techspecter.utils.url import filename_from_url, resolve_url

logger = logging.getLogger(__name__)

_IMPORTMAP_PATTERN = re.compile(r"""['"]([^'"]+)['"]\s*:\s*['"]([^'"]+)['"]""")


def extract_html_references(html: str, *, base_url: str) -> list[AssetReference]:
    """Extract publicly referenced assets from HTML."""
    references: list[AssetReference] = []
    seen: set[str] = set()

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception as exc:
        logger.warning("Failed to parse HTML for asset discovery: %s", exc)
        return references

    def add(
        raw: str,
        *,
        source: AssetDiscoverySource,
        referenced_by: str,
        category_hint: AssetCategory | None = None,
        detail: str | None = None,
    ) -> None:
        candidate = raw.strip()
        if not candidate or candidate.startswith(("data:", "blob:", "javascript:", "#")):
            return
        try:
            absolute = resolve_url(base_url, candidate)
        except Exception as exc:
            logger.debug("Skipping invalid HTML asset reference %r: %s", candidate, exc)
            return
        if absolute in seen:
            return
        seen.add(absolute)
        references.append(
            AssetReference(
                url=absolute,
                original_url=candidate,
                category_hint=category_hint,
                source=source,
                referenced_by=referenced_by,
                detail=detail,
            ),
        )

    for script in soup.find_all("script"):
        if not isinstance(script, Tag):
            continue
        src = script.get("src")
        if isinstance(src, str):
            add(
                src,
                source=AssetDiscoverySource.HTML,
                referenced_by=base_url,
                category_hint=AssetCategory.JAVASCRIPT,
                detail="script[src]",
            )
        script_type = str(script.get("type") or "").lower()
        if script_type == "importmap" and script.string:
            for match in _IMPORTMAP_PATTERN.finditer(script.string):
                add(
                    match.group(2),
                    source=AssetDiscoverySource.IMPORT_MAP,
                    referenced_by=base_url,
                    category_hint=AssetCategory.JAVASCRIPT,
                    detail=f"importmap:{match.group(1)}",
                )

    for link in soup.find_all("link"):
        if not isinstance(link, Tag):
            continue
        href = link.get("href")
        if not isinstance(href, str):
            continue
        rel = " ".join(str(token) for token in (link.get("rel") or [])).lower()
        link_type = str(link.get("type") or "").lower()
        as_attr = str(link.get("as") or "").lower()
        category = _category_from_link(rel, link_type, as_attr, href)
        source = AssetDiscoverySource.MANIFEST if "manifest" in rel else AssetDiscoverySource.HTML
        if "serviceworker" in rel:
            source = AssetDiscoverySource.SERVICE_WORKER
        add(
            href,
            source=source,
            referenced_by=base_url,
            category_hint=category,
            detail=f"link[rel={rel or 'stylesheet'}]",
        )

    for tag_name, attr in (("img", "src"), ("video", "src"), ("audio", "src"), ("source", "src")):
        for element in soup.find_all(tag_name):
            if not isinstance(element, Tag):
                continue
            value = element.get(attr)
            if isinstance(value, str):
                add(
                    value,
                    source=AssetDiscoverySource.HTML,
                    referenced_by=base_url,
                    category_hint=AssetCategory.IMAGE,
                    detail=f"{tag_name}[{attr}]",
                )

    for style in soup.find_all("style"):
        if isinstance(style, Tag) and style.string:
            from techspecter.asset_discovery.sources.css import extract_css_references

            for css_ref in extract_css_references(style.string, base_url=base_url):
                if css_ref.url in seen:
                    continue
                seen.add(css_ref.url)
                css_ref = css_ref.model_copy(
                    update={
                        "referenced_by": base_url,
                        "detail": "inline-style",
                    },
                )
                references.append(css_ref)

    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        text = str(comment)
        if "sourceMappingURL=" in text:
            from techspecter.parser.sourcemap import detect_source_map_url

            source_map = detect_source_map_url(text)
            if source_map:
                add(
                    source_map,
                    source=AssetDiscoverySource.SOURCE_MAP,
                    referenced_by=base_url,
                    category_hint=AssetCategory.MAP,
                    detail="html-comment",
                )

    logger.debug("Extracted %d HTML asset references from %s", len(references), base_url)
    return references


def _category_from_link(rel: str, link_type: str, as_attr: str, href: str) -> AssetCategory:
    """Infer category from link attributes."""
    if "stylesheet" in rel or link_type == "text/css":
        return AssetCategory.CSS
    if "manifest" in rel or href.endswith((".webmanifest", "manifest.json")):
        return AssetCategory.MANIFEST
    if "icon" in rel or as_attr == "image":
        return AssetCategory.IMAGE
    if as_attr == "font":
        return AssetCategory.FONT
    if as_attr == "script":
        return AssetCategory.JAVASCRIPT
    filename = filename_from_url(href).lower()
    if filename.endswith(".css"):
        return AssetCategory.CSS
    return AssetCategory.UNKNOWN
