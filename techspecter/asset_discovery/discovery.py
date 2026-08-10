"""Passive asset discovery orchestration."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from techspecter.asset_discovery.inventory import AssetInventoryBuilder
from techspecter.asset_discovery.models import (
    AssetCategory,
    AssetDiscoverySource,
    AssetReference,
)
from techspecter.asset_discovery.sources.html import extract_html_references
from techspecter.asset_discovery.sources.javascript import extract_javascript_references
from techspecter.asset_discovery.sources.manifest import extract_manifest_references
from techspecter.models.metadata import MetadataDiscoveryObservation, WellKnownResourceObservation
from techspecter.utils.url import resolve_url

logger = logging.getLogger(__name__)

_MAX_RECURSIVE_ROUNDS = 3


@dataclass(slots=True)
class AssetDiscoveryEngine:
    """Discover publicly referenced assets from passive sources."""

    max_recursive_rounds: int = _MAX_RECURSIVE_ROUNDS

    def collect_references(
        self,
        *,
        html: str,
        base_url: str,
        javascript_index: object | None = None,
        metadata_observation: MetadataDiscoveryObservation | None = None,
        http_link_header: str | None = None,
    ) -> list[AssetReference]:
        """Collect asset references from all passive sources."""
        references: list[AssetReference] = []
        references.extend(extract_html_references(html, base_url=base_url))

        if http_link_header:
            references.extend(
                _references_from_link_header(http_link_header, base_url=base_url),
            )

        if metadata_observation is not None:
            references.extend(
                _references_from_metadata(metadata_observation, base_url=base_url),
            )

        if javascript_index is not None:
            references.extend(
                _references_from_javascript_index(javascript_index, base_url=base_url),
            )

        logger.info(
            "Asset discovery collected %d references for %s",
            len(references),
            base_url,
        )
        return references

    def populate_inventory(
        self,
        builder: AssetInventoryBuilder,
        references: list[AssetReference],
    ) -> None:
        """Add references to an inventory builder."""
        for reference in references:
            builder.add_reference(reference)


def _references_from_javascript_index(index: object, *, base_url: str) -> list[AssetReference]:
    """Build asset references from the JavaScript index."""
    from techspecter.javascript.index.javascript_index import JavaScriptIndex

    if not isinstance(index, JavaScriptIndex):
        return []

    references: list[AssetReference] = []
    for resource in index.all_resources():
        parent_url = str(resource.url)
        content = resource.normalized_content or resource.content or ""
        if resource.inline:
            references.extend(
                extract_javascript_references(
                    content,
                    base_url=base_url,
                    parent_url=f"inline-script:{resource.inline_index}",
                ),
            )
            continue

        absolute_parent = _absolute_or_none(parent_url, base_url=base_url)
        if absolute_parent is None:
            logger.debug("Skipping non-absolute javascript index URL: %s", parent_url)
            continue
        parent_url = absolute_parent

        references.append(
            AssetReference(
                url=parent_url,
                original_url=resource.original_url,
                category_hint=AssetCategory.JAVASCRIPT,
                source=AssetDiscoverySource.JAVASCRIPT,
                referenced_by=base_url,
                detail="javascript-index",
            ),
        )
        if resource.metadata.source_map_url:
            map_url = _absolute_or_none(resource.metadata.source_map_url, base_url=parent_url)
            if map_url is not None:
                references.append(
                    AssetReference(
                        url=map_url,
                        original_url=resource.metadata.source_map_url,
                        category_hint=AssetCategory.MAP,
                        source=AssetDiscoverySource.SOURCE_MAP,
                        referenced_by=parent_url,
                        detail="javascript-source-map",
                    ),
                )
        references.extend(
            extract_javascript_references(
                content,
                base_url=parent_url,
                parent_url=parent_url,
            ),
        )
    return references


def _references_from_metadata(
    observation: MetadataDiscoveryObservation,
    *,
    base_url: str,
) -> list[AssetReference]:
    """Convert metadata observations into asset references."""
    references: list[AssetReference] = []

    for resource in observation.well_known_resources:
        references.extend(_reference_from_well_known(resource, base_url=base_url))

    for source_map in observation.sourcemap_references:
        if not source_map.url:
            continue
        map_url = _absolute_or_none(source_map.url, base_url=base_url)
        if map_url is None:
            continue
        references.append(
            AssetReference(
                url=map_url,
                original_url=source_map.url,
                category_hint=AssetCategory.MAP,
                source=AssetDiscoverySource.SOURCE_MAP,
                referenced_by=source_map.location or base_url,
                detail=source_map.source,
            ),
        )

    for worker in observation.service_worker_references:
        script_url = worker.script_url
        if not script_url:
            continue
        absolute = _absolute_or_none(script_url, base_url=base_url)
        if absolute is None:
            continue
        references.append(
            AssetReference(
                url=absolute,
                original_url=script_url,
                category_hint=AssetCategory.SERVICE_WORKER,
                source=AssetDiscoverySource.SERVICE_WORKER,
                referenced_by=worker.source or base_url,
                detail=worker.scope,
            ),
        )

    return references


def _reference_from_well_known(
    resource: WellKnownResourceObservation,
    *,
    base_url: str,
) -> list[AssetReference]:
    """Map a well-known resource observation to asset references."""
    source = AssetDiscoverySource.WELL_KNOWN
    if resource.resource_type == "robots.txt":
        source = AssetDiscoverySource.ROBOTS
    elif resource.resource_type == "sitemap.xml":
        source = AssetDiscoverySource.SITEMAP

    category = _category_from_well_known(resource.resource_type)
    references = [
        AssetReference(
            url=resource.url,
            original_url=resource.url,
            category_hint=category,
            source=source,
            referenced_by=base_url,
            detail=resource.discovered_via,
        ),
    ]

    if resource.content and resource.resource_type == "robots.txt":
        for line in resource.content.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("sitemap:"):
                sitemap_url = stripped.split(":", 1)[1].strip()
                absolute = _absolute_or_none(sitemap_url, base_url=resource.url)
                if absolute is None:
                    continue
                references.append(
                    AssetReference(
                        url=absolute,
                        original_url=sitemap_url,
                        category_hint=AssetCategory.XML,
                        source=AssetDiscoverySource.SITEMAP,
                        referenced_by=resource.url,
                        detail="robots-sitemap",
                    ),
                )

    if resource.content and resource.resource_type in {"manifest.json", "site.webmanifest"}:
        references.extend(
            extract_manifest_references(
                resource.content,
                base_url=resource.url,
                manifest_url=resource.url,
            ),
        )

    return references


def _absolute_or_none(url: str, *, base_url: str) -> str | None:
    """Resolve *url* against *base_url* and return only downloadable http(s) URLs."""
    from urllib.parse import urlparse

    candidate = (url or "").strip()
    if not candidate or candidate.startswith(("data:", "blob:", "javascript:")):
        return None
    try:
        if candidate.startswith(("http://", "https://")):
            absolute = candidate
        else:
            absolute = resolve_url(base_url, candidate)
    except Exception:
        return None
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return absolute


def _category_from_well_known(resource_type: str) -> AssetCategory:
    """Map well-known resource type to asset category."""
    mapping = {
        "robots.txt": AssetCategory.TEXT,
        "sitemap.xml": AssetCategory.XML,
        "security.txt": AssetCategory.TEXT,
        "humans.txt": AssetCategory.TEXT,
        "ads.txt": AssetCategory.TEXT,
        "assetlinks.json": AssetCategory.JSON,
        "apple-app-site-association": AssetCategory.JSON,
        "favicon.ico": AssetCategory.IMAGE,
        "site.webmanifest": AssetCategory.MANIFEST,
        "browserconfig.xml": AssetCategory.XML,
        "manifest.json": AssetCategory.MANIFEST,
    }
    return mapping.get(resource_type, AssetCategory.UNKNOWN)


def _references_from_link_header(header: str, *, base_url: str) -> list[AssetReference]:
    """Parse Link HTTP header values into asset references."""
    references: list[AssetReference] = []
    for part in header.split(","):
        segment = part.strip()
        if not segment.startswith("<"):
            continue
        end = segment.find(">")
        if end <= 1:
            continue
        raw_url = segment[1:end]
        try:
            absolute = resolve_url(base_url, raw_url)
        except Exception:
            continue
        references.append(
            AssetReference(
                url=absolute,
                original_url=raw_url,
                source=AssetDiscoverySource.HTTP_HEADER,
                referenced_by=base_url,
                detail="Link header",
            ),
        )
    return references


def well_known_default_urls(base_url: str) -> list[AssetReference]:
    """Return default well-known path references without fetching."""
    from urllib.parse import urljoin, urlparse

    from techspecter.crawler.metadata_collector import WELL_KNOWN_PATHS

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    references: list[AssetReference] = []
    for resource_type, path in WELL_KNOWN_PATHS.items():
        references.append(
            AssetReference(
                url=urljoin(origin, path),
                original_url=path,
                category_hint=_category_from_well_known(resource_type),
                source=AssetDiscoverySource.WELL_KNOWN,
                referenced_by=base_url,
                detail="well-known-path",
            ),
        )
    return references
