"""Asset attribution for technology evidence."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from techspecter.asset_discovery.inventory import inventory_key
from techspecter.asset_discovery.models import AssetInventory, AssetRecord

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AssetAttributor:
    """Resolve technology evidence URLs to asset inventory records."""

    inventory: AssetInventory | None = None
    _index: dict[str, AssetRecord] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        """Build URL lookup index from inventory."""
        if self.inventory is None:
            return
        for record in self.inventory.assets:
            self._index[inventory_key(record.url)] = record
            if record.original_url:
                self._index[inventory_key(record.original_url)] = record

    def resolve(self, url: str | None) -> AssetRecord | None:
        """Return the asset record for a URL, if present in inventory."""
        if not url or not self._index:
            return None
        return self._index.get(inventory_key(url))

    def asset_id(self, url: str | None) -> str | None:
        """Return asset ID for a URL."""
        record = self.resolve(url)
        return record.asset_id if record else None

    def source_file(self, url: str | None, filename: str | None = None) -> str | None:
        """Return the best display filename for an evidence source."""
        record = self.resolve(url)
        if record is not None:
            return record.filename
        if filename:
            return filename
        if url and url.startswith("inline://"):
            return url.rsplit("/", 1)[-1] + ".js"
        if url:
            path = url.rsplit("/", 1)[-1]
            if path and "." in path:
                return path
        return None

    def relative_path(self, url: str | None) -> str | None:
        """Return relative path for a URL when known in inventory."""
        record = self.resolve(url)
        return record.relative_path if record else None

    def discovery_method(self, url: str | None) -> str | None:
        """Return primary discovery method from asset inventory."""
        record = self.resolve(url)
        if record is None or not record.discovery_sources:
            return None
        return record.discovery_sources[0].value
