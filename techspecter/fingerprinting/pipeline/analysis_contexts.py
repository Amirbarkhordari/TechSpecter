"""Build fingerprint analysis contexts from discovery results."""

from __future__ import annotations

from techspecter.asset_discovery.inventory import inventory_key
from techspecter.asset_discovery.models import AssetCategory, AssetInventory
from techspecter.asset_discovery.hash import asset_id_from_url
from techspecter.fingerprinting.context import MatchContext
from techspecter.models.discovery import DiscoveryResult, DownloadResult, InlineScript

_FINGERPRINT_CATEGORIES = frozenset(
    {
        AssetCategory.JAVASCRIPT,
        AssetCategory.CSS,
        AssetCategory.JSON,
        AssetCategory.MAP,
        AssetCategory.MANIFEST,
        AssetCategory.WORKER,
        AssetCategory.SERVICE_WORKER,
        AssetCategory.XML,
        AssetCategory.TEXT,
        AssetCategory.UNKNOWN,
    },
)


def iter_analysis_contexts(discovery: DiscoveryResult) -> list[MatchContext]:
    """Build deduplicated analysis contexts from all analyzable discovery assets."""
    contexts: list[MatchContext] = []
    seen_urls: set[str] = set()

    for download in discovery.downloads:
        context = _context_from_download(download)
        if context is None:
            continue
        if context.url in seen_urls:
            continue
        seen_urls.add(context.url)
        contexts.append(context)

    for inline in discovery.inline_scripts:
        context = _context_from_inline(inline)
        if context.url in seen_urls:
            continue
        seen_urls.add(context.url)
        contexts.append(context)

    if discovery.javascript_index is not None:
        for resource in discovery.javascript_index.all_resources():
            if resource.inline:
                continue
            content = resource.content or resource.normalized_content
            if not content:
                continue
            url = str(resource.url)
            if url in seen_urls:
                continue
            seen_urls.add(url)
            contexts.append(
                MatchContext(
                    content=content,
                    filename=resource.metadata.filename,
                    url=url,
                    source_map_url=resource.metadata.source_map_url,
                    asset_id=_asset_id_for_url(discovery.asset_inventory, url),
                ),
            )

    if discovery.asset_inventory is not None:
        contexts.extend(
            _contexts_from_inventory(
                discovery.asset_inventory,
                seen_urls=seen_urls,
            ),
        )

    if discovery.metadata_observation is not None:
        for resource in discovery.metadata_observation.well_known_resources:
            if not resource.content:
                continue
            url = resource.url
            if url in seen_urls:
                continue
            seen_urls.add(url)
            contexts.append(
                MatchContext(
                    content=resource.content,
                    filename=resource.resource_type or url.rsplit("/", 1)[-1],
                    url=url,
                    asset_id=_asset_id_for_url(discovery.asset_inventory, url),
                ),
            )

    return contexts


def _contexts_from_inventory(
    inventory: AssetInventory,
    *,
    seen_urls: set[str],
) -> list[MatchContext]:
    """Create match contexts from downloaded asset inventory text bodies."""
    contexts: list[MatchContext] = []
    for record in inventory.assets:
        if record.category not in _FINGERPRINT_CATEGORIES:
            continue
        if record.category in {AssetCategory.IMAGE, AssetCategory.FONT, AssetCategory.WASM}:
            continue
        key = inventory_key(record.url)
        content = inventory.text_bodies.get(key)
        if not content or not content.strip():
            continue
        if record.url in seen_urls:
            continue
        seen_urls.add(record.url)
        contexts.append(
            MatchContext(
                content=content,
                filename=record.filename,
                url=record.url,
                asset_id=record.asset_id or asset_id_from_url(record.url),
            ),
        )
    return contexts


def _context_from_download(download: DownloadResult) -> MatchContext | None:
    """Create a match context from a download result."""
    if not download.download_success or not download.content:
        return None
    url = str(download.url)
    return MatchContext(
        content=download.content,
        filename=download.filename,
        url=url,
        source_map_url=download.source_map_url,
        asset_id=asset_id_from_url(url),
    )


def _context_from_inline(inline: InlineScript) -> MatchContext:
    """Create a match context from an inline script block."""
    url = f"inline://script/{inline.index}"
    return MatchContext(
        content=inline.content,
        filename=f"inline-script-{inline.index}.js",
        url=url,
        source_map_url=inline.source_map_url,
        asset_id=asset_id_from_url(url),
    )


def _asset_id_for_url(inventory: AssetInventory | None, url: str) -> str:
    if inventory is None:
        return asset_id_from_url(url)
    key = inventory_key(url)
    for record in inventory.assets:
        if inventory_key(record.url) == key and record.asset_id:
            return record.asset_id
    return asset_id_from_url(url)
