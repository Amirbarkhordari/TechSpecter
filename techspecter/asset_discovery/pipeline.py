"""Asset discovery pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlparse

from techspecter.asset_discovery.collector import AssetCollector, AssetCollectorConfig
from techspecter.asset_discovery.discovery import AssetDiscoveryEngine
from techspecter.asset_discovery.hash import sha256_hex
from techspecter.asset_discovery.inventory import AssetInventoryBuilder, inventory_key
from techspecter.asset_discovery.models import AssetCategory, AssetInventory, AssetReference
from techspecter.asset_discovery.sources.css import extract_css_references
from techspecter.asset_discovery.sources.manifest import extract_manifest_references
from techspecter.crawler.metadata_collector import WellKnownResourceCollector
from techspecter.downloader.http_client import AsyncHttpClient
from techspecter.models.metadata import MetadataDiscoveryObservation

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AssetDiscoveryPipelineConfig:
    """Configuration for asset discovery pipeline."""

    collect_well_known: bool = True
    download_assets: bool = True
    max_concurrency: int = 8
    max_recursive_rounds: int = 3
    max_file_size: int = 10 * 1024 * 1024


@dataclass(slots=True)
class AssetDiscoveryPipeline:
    """End-to-end passive asset discovery and inventory pipeline."""

    config: AssetDiscoveryPipelineConfig = field(default_factory=AssetDiscoveryPipelineConfig)
    discovery_engine: AssetDiscoveryEngine | None = None

    async def run(
        self,
        *,
        base_url: str,
        html: str,
        client: AsyncHttpClient,
        javascript_index: object | None = None,
        metadata_observation: MetadataDiscoveryObservation | None = None,
        http_link_header: str | None = None,
        pre_downloaded_keys: frozenset[str] | None = None,
    ) -> AssetInventory:
        """Discover assets, download when configured, and build inventory."""
        started = time.perf_counter()
        started_at = datetime.now(tz=UTC)
        engine = self.discovery_engine or AssetDiscoveryEngine(
            max_recursive_rounds=self.config.max_recursive_rounds,
        )
        builder = AssetInventoryBuilder()
        metadata = metadata_observation

        if self.config.collect_well_known and metadata is None:
            well_known_collector = WellKnownResourceCollector(client)
            well_known = await well_known_collector.collect(base_url)
            metadata = MetadataDiscoveryObservation(
                well_known_resources=well_known,
            )

        references = engine.collect_references(
            html=html,
            base_url=base_url,
            javascript_index=javascript_index,
            metadata_observation=metadata,
            http_link_header=http_link_header,
        )

        engine.populate_inventory(builder, references)

        collector = AssetCollector(
            client=client,
            config=AssetCollectorConfig(
                max_concurrency=self.config.max_concurrency,
                max_file_size=self.config.max_file_size,
                download_assets=self.config.download_assets,
            ),
        )
        _seed_metadata_observation(builder, metadata, collector)
        _seed_javascript_index(builder, javascript_index, collector)
        skip = pre_downloaded_keys or frozenset()
        await collector.enrich_inventory(builder, skip_urls=skip)
        await self._recursive_expand(builder, collector, skip_urls=skip)
        elapsed_ms = (time.perf_counter() - started) * 1000
        inventory = builder.build(target_url=base_url, elapsed_ms=elapsed_ms)
        inventory = inventory.model_copy(update={"text_bodies": dict(collector.downloaded_text)})
        inventory.started_at = started_at
        inventory.completed_at = datetime.now(tz=UTC)
        download_summary = inventory.download_summary
        logger.info(
            "Asset discovery pipeline complete for %s: %d assets "
            "(downloaded=%d failed=%d skipped=%d timeout=%d forbidden=%d rate_limited=%d, %.0f ms)",
            base_url,
            inventory.summary.total_assets,
            download_summary.downloaded,
            download_summary.failed,
            download_summary.skipped,
            download_summary.timeout,
            download_summary.forbidden,
            download_summary.rate_limited,
            elapsed_ms,
        )
        return inventory

    async def _recursive_expand(
        self,
        builder: AssetInventoryBuilder,
        collector: AssetCollector,
        *,
        skip_urls: frozenset[str],
    ) -> None:
        """Expand inventory by parsing downloaded CSS and manifest bodies."""
        for round_index in range(self.config.max_recursive_rounds):
            new_refs = 0
            for record in list(builder.records.values()):
                if not record.download_success:
                    continue
                content = collector.downloaded_text.get(inventory_key(record.url))
                if not content:
                    continue
                child_refs: list[AssetReference] = []
                if record.category == AssetCategory.CSS:
                    child_refs = extract_css_references(content, base_url=record.url)
                elif record.category in {AssetCategory.MANIFEST, AssetCategory.JSON}:
                    child_refs = extract_manifest_references(
                        content,
                        base_url=record.url,
                        manifest_url=record.url,
                    )
                for child in child_refs:
                    key = inventory_key(child.url)
                    if key in builder.records:
                        continue
                    builder.add_reference(child)
                    new_refs += 1
            if new_refs == 0:
                break
            logger.debug(
                "Asset discovery recursive round %d discovered %d new references",
                round_index + 1,
                new_refs,
            )
            await collector.enrich_inventory(builder, skip_urls=skip_urls)


def _seed_metadata_observation(
    builder: AssetInventoryBuilder,
    metadata: MetadataDiscoveryObservation | None,
    collector: AssetCollector,
) -> None:
    """Reuse well-known resource bodies collected during metadata discovery."""
    if metadata is None:
        return
    for resource in metadata.well_known_resources:
        url = resource.url
        key = inventory_key(url)
        if resource.content:
            collector.downloaded_text[key] = resource.content
        digest = sha256_hex(resource.content.encode("utf-8")) if resource.content else None
        file_size = len(resource.content.encode("utf-8")) if resource.content else None
        builder.upsert_download(
            url=url,
            http_status=resource.status_code,
            content_type=resource.content_type,
            encoding=None,
            file_size=file_size,
            sha256=digest,
            download_success=resource.available,
            download_duration_ms=None,
            response_time_ms=None,
            error_message=None if resource.available else "Resource unavailable",
        )


def _seed_javascript_index(
    builder: AssetInventoryBuilder,
    javascript_index: object | None,
    collector: AssetCollector,
) -> None:
    """Copy download metadata from the JavaScript index into the asset inventory."""
    from techspecter.javascript.index.javascript_index import JavaScriptIndex

    if not isinstance(javascript_index, JavaScriptIndex):
        return
    for resource in javascript_index.all_resources():
        if resource.inline or not resource.download_success:
            continue
        url = str(resource.url)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        content = resource.content or ""
        key = inventory_key(url)
        if content:
            collector.downloaded_text[key] = content
        digest = sha256_hex(content.encode("utf-8")) if content else None
        builder.upsert_download(
            url=url,
            http_status=resource.status_code,
            content_type=resource.content_type,
            encoding=resource.encoding,
            file_size=resource.metadata.content_length,
            sha256=digest or resource.metadata.content_hash or None,
            download_success=True,
            download_duration_ms=resource.download_duration_ms,
            response_time_ms=resource.download_duration_ms,
            error_message=resource.error_message,
        )
