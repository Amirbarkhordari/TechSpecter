"""Asset inventory builder with deduplication."""

from __future__ import annotations

import logging
from urllib.parse import urlparse, urlunparse

from techspecter.asset_discovery.classifier import AssetClassifier
from techspecter.asset_discovery.download_status import build_download_summary
from techspecter.asset_discovery.hash import asset_id_from_url
from techspecter.asset_discovery.models import (
    AssetCategory,
    AssetDownloadStatus,
    AssetInventory,
    AssetInventorySummary,
    AssetRecord,
    AssetReference,
    AssetRelationship,
)
from techspecter.utils.url import filename_from_url, normalize_url

logger = logging.getLogger(__name__)


def inventory_key(url: str) -> str:
    """Normalize a URL for inventory deduplication (fragments removed)."""
    parsed = urlparse(normalize_url(url))
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            "",
        ),
    )


class AssetInventoryBuilder:
    """Build a deduplicated asset inventory."""

    def __init__(self, *, classifier: AssetClassifier | None = None) -> None:
        """Initialize builder."""
        self._classifier = classifier or AssetClassifier()
        self._records: dict[str, AssetRecord] = {}

    def add_reference(self, reference: AssetReference) -> AssetRecord:
        """Add or merge an asset reference into the inventory."""
        key = inventory_key(reference.url)
        filename = filename_from_url(reference.url)
        extension = self._classifier.extension_from_filename(filename)
        category = self._classifier.classify(
            url=reference.url,
            filename=filename,
            source_hint=reference.category_hint,
        )
        relationship = AssetRelationship(
            source=reference.source,
            referenced_by=reference.referenced_by,
            detail=reference.detail,
        )

        existing = self._records.get(key)
        if existing is not None:
            return self._merge_record(existing, reference, relationship, category)

        record = AssetRecord(
            asset_id=asset_id_from_url(key),
            url=reference.url,
            original_url=reference.original_url,
            relative_path=_relative_path(reference.url),
            filename=filename,
            extension=extension,
            category=category,
            discovery_sources=[reference.source],
            relationships=[relationship],
        )
        self._records[key] = record
        logger.debug("Inventory added asset %s (%s)", record.filename, record.category.value)
        return record

    def upsert_download(
        self,
        *,
        url: str,
        http_status: int | None,
        content_type: str | None,
        encoding: str | None,
        file_size: int | None,
        sha256: str | None,
        download_success: bool,
        download_duration_ms: float | None,
        response_time_ms: float | None,
        error_message: str | None,
        content: bytes | None = None,
        download_status: AssetDownloadStatus | None = None,
    ) -> AssetRecord:
        """Update an inventory record with download metadata."""
        key = inventory_key(url)
        record = self._records.get(key)
        filename = filename_from_url(url)
        category = self._classifier.classify(
            url=url,
            filename=filename,
            content_type=content_type,
        )
        if record is None:
            record = AssetRecord(
                asset_id=asset_id_from_url(key),
                url=url,
                filename=filename,
                extension=self._classifier.extension_from_filename(filename),
                category=category,
                discovery_sources=[],
                relationships=[],
            )
            self._records[key] = record

        mime = content_type.split(";", 1)[0].strip() if content_type else None
        resolved_size = (
            file_size if file_size is not None else (len(content) if content else record.file_size)
        )
        updated = record.model_copy(
            update={
                "http_status": http_status,
                "content_type": content_type,
                "mime_type": mime,
                "encoding": encoding,
                "file_size": resolved_size,
                "sha256": sha256,
                "download_success": download_success,
                "download_duration_ms": download_duration_ms,
                "response_time_ms": response_time_ms,
                "error_message": error_message,
                "download_status": download_status,
                "category": category if category != AssetCategory.UNKNOWN else record.category,
            },
        )
        self._records[key] = updated
        return updated

    def build(self, *, target_url: str, elapsed_ms: float = 0.0) -> AssetInventory:
        """Finalize the inventory with summary statistics."""
        assets = sorted(self._records.values(), key=lambda item: (item.category.value, item.url))
        summary = AssetInventorySummary()
        for asset in assets:
            summary.increment(asset.category)
        logger.info(
            "Asset inventory built for %s: %d assets across %d categories",
            target_url,
            summary.total_assets,
            len({asset.category for asset in assets}),
        )
        return AssetInventory(
            target_url=target_url,
            assets=assets,
            summary=summary,
            download_summary=build_download_summary(assets),
            elapsed_ms=elapsed_ms,
        )

    @property
    def records(self) -> dict[str, AssetRecord]:
        """Return indexed records."""
        return self._records

    def _merge_record(
        self,
        existing: AssetRecord,
        reference: AssetReference,
        relationship: AssetRelationship,
        category: AssetCategory,
    ) -> AssetRecord:
        sources = list(existing.discovery_sources)
        if reference.source not in sources:
            sources.append(reference.source)
        relationships = list(existing.relationships)
        if not any(
            item.source == relationship.source
            and item.referenced_by == relationship.referenced_by
            and item.detail == relationship.detail
            for item in relationships
        ):
            relationships.append(relationship)
        merged = existing.model_copy(
            update={
                "discovery_sources": sources,
                "relationships": relationships,
                "category": (
                    existing.category if existing.category != AssetCategory.UNKNOWN else category
                ),
            },
        )
        self._records[inventory_key(existing.url)] = merged
        return merged


def _relative_path(url: str) -> str | None:
    """Return path component of a URL."""
    path = urlparse(url).path
    return path or None
