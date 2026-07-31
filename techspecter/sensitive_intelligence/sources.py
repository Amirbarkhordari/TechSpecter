"""Text asset collection for sensitive intelligence analysis."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.asset_discovery.inventory import inventory_key
from techspecter.asset_discovery.models import AssetCategory, AssetInventory
from techspecter.models.discovery import DiscoveryResult
from techspecter.utils.url import filename_from_url

_TEXT_CATEGORIES = {
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
}


@dataclass(frozen=True, slots=True)
class TextAssetSource:
    """A textual asset available for passive analysis."""

    url: str
    filename: str
    content: str
    asset_id: str | None = None
    category: str | None = None


def collect_text_assets(discovery: DiscoveryResult) -> list[TextAssetSource]:
    """Collect all downloaded textual assets from a discovery result."""
    sources: list[TextAssetSource] = []
    seen: set[str] = set()

    def add(
        url: str, content: str, *, asset_id: str | None = None, category: str | None = None
    ) -> None:
        if not content or not content.strip():
            return
        key = inventory_key(url)
        if key in seen:
            return
        seen.add(key)
        sources.append(
            TextAssetSource(
                url=url,
                filename=filename_from_url(url),
                content=content,
                asset_id=asset_id,
                category=category,
            ),
        )

    if discovery.asset_inventory is not None:
        sources.extend(_from_asset_inventory(discovery.asset_inventory, seen))

    for download in discovery.downloads:
        if download.content:
            asset_id = _asset_id_for_url(discovery.asset_inventory, str(download.url))
            add(str(download.url), download.content, asset_id=asset_id, category="javascript")

    for script in discovery.inline_scripts:
        add(
            f"inline://script/{script.index}",
            script.content,
            category="inline-javascript",
        )

    if discovery.javascript_index is not None:
        for js_resource in discovery.javascript_index.all_resources():
            content = js_resource.content or js_resource.normalized_content
            if not content or js_resource.inline:
                continue
            url = str(js_resource.url)
            asset_id = _asset_id_for_url(discovery.asset_inventory, url)
            add(url, content, asset_id=asset_id, category="javascript")

    if discovery.metadata_observation is not None:
        for well_known in discovery.metadata_observation.well_known_resources:
            if well_known.content:
                asset_id = _asset_id_for_url(discovery.asset_inventory, well_known.url)
                add(
                    well_known.url,
                    well_known.content,
                    asset_id=asset_id,
                    category=well_known.resource_type,
                )

    if discovery.http_response is not None:
        headers = "\n".join(f"{k}: {v}" for k, v in discovery.http_response.headers.items())
        if headers:
            add(str(discovery.target.url), headers, category="http-headers")

    return sources


def _from_asset_inventory(
    inventory: AssetInventory,
    seen: set[str],
) -> list[TextAssetSource]:
    sources: list[TextAssetSource] = []
    for record in inventory.assets:
        if record.category not in _TEXT_CATEGORIES:
            continue
        if record.category in {AssetCategory.IMAGE, AssetCategory.FONT, AssetCategory.WASM}:
            continue
        key = inventory_key(record.url)
        content = inventory.text_bodies.get(key)
        if not content:
            continue
        if key in seen:
            continue
        seen.add(key)
        sources.append(
            TextAssetSource(
                url=record.url,
                filename=record.filename,
                content=content,
                asset_id=record.asset_id,
                category=record.category.value,
            ),
        )
    return sources


def _asset_id_for_url(inventory: AssetInventory | None, url: str) -> str | None:
    if inventory is None:
        return None
    key = inventory_key(url)
    for record in inventory.assets:
        if inventory_key(record.url) == key:
            return record.asset_id
    return None
