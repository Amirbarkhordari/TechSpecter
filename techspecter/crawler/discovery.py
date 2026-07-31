"""JavaScript discovery pipeline orchestration."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from techspecter.config import Settings, get_settings
from techspecter.crawler.metadata_collector import WellKnownResourceCollector
from techspecter.downloader.html_downloader import HtmlDownloader
from techspecter.downloader.http_client import AsyncHttpClient, HttpClientConfig
from techspecter.javascript.adapter import to_discovery_result
from techspecter.javascript.pipeline.config import JavaScriptPipelineConfig
from techspecter.javascript.pipeline.pipeline import JavaScriptPipeline
from techspecter.models.discovery import DiscoveryResult, DownloadResult, InlineScript
from techspecter.models.metadata import (
    MetadataDiscoveryObservation,
    SourceMapReferenceObservation,
)
from techspecter.parser.html_metadata_parser import HtmlMetadataParser
from techspecter.parser.html_parser import HtmlScriptParser
from techspecter.utils.url import validate_url
from techspecter.utils.validation import build_target

if TYPE_CHECKING:
    from techspecter.asset_discovery.pipeline import AssetDiscoveryPipeline

logger = logging.getLogger(__name__)


def _rebuild_discovery_result_models() -> None:
    """Resolve forward references on DiscoveryResult."""
    from techspecter.asset_discovery.models import AssetInventory
    from techspecter.javascript.index.javascript_index import JavaScriptIndex
    from techspecter.models.discovery import DiscoveryResult
    from techspecter.sensitive_intelligence.models import SensitiveIntelligenceReport

    DiscoveryResult.model_rebuild(
        _types_namespace={
            "JavaScriptIndex": JavaScriptIndex,
            "AssetInventory": AssetInventory,
            "SensitiveIntelligenceReport": SensitiveIntelligenceReport,
        },
    )


_rebuild_discovery_result_models()


@dataclass(slots=True)
class DiscoveryPipelineConfig:
    """Configuration for the JavaScript discovery pipeline.

    Attributes:
        settings: Application settings used to configure HTTP behavior.
        collect_metadata: Whether to collect passive metadata and well-known resources.
        collect_asset_inventory: Whether to build passive asset inventory (Phase 7.1).
        collect_sensitive_intelligence: Whether to analyze assets for sensitive data (Phase 7.3).
        javascript_pipeline: JavaScript v2 pipeline configuration.
    """

    settings: Settings | None = None
    collect_metadata: bool = False
    collect_asset_inventory: bool = True
    collect_sensitive_intelligence: bool = True
    javascript_pipeline: JavaScriptPipelineConfig | None = None


class DiscoveryPipeline:
    """End-to-end JavaScript discovery pipeline."""

    def __init__(
        self,
        config: DiscoveryPipelineConfig | None = None,
        *,
        http_client: AsyncHttpClient | None = None,
        html_parser: HtmlScriptParser | None = None,
        metadata_parser: HtmlMetadataParser | None = None,
        javascript_pipeline: JavaScriptPipeline | None = None,
        asset_pipeline: AssetDiscoveryPipeline | None = None,
    ) -> None:
        """Initialize the discovery pipeline.

        Args:
            config: Optional pipeline configuration.
            http_client: Optional preconfigured HTTP client for dependency injection.
            html_parser: Optional HTML parser for dependency injection.
            metadata_parser: Optional HTML metadata parser for dependency injection.
            javascript_pipeline: Optional JavaScript v2 pipeline for dependency injection.
            asset_pipeline: Optional asset discovery pipeline for dependency injection.
        """
        self._config = config or DiscoveryPipelineConfig()
        self._settings = self._config.settings or get_settings()
        self._http_client = http_client
        self._html_parser = html_parser or HtmlScriptParser()
        self._metadata_parser = metadata_parser or HtmlMetadataParser()
        self._owns_client = http_client is None
        js_config = self._config.javascript_pipeline or JavaScriptPipelineConfig(
            max_concurrency=self._settings.max_concurrency,
        )
        self._javascript_pipeline = javascript_pipeline or JavaScriptPipeline(config=js_config)
        self._asset_pipeline = asset_pipeline

    async def run(self, target_url: str) -> DiscoveryResult:
        """Execute the JavaScript discovery pipeline.

        Args:
            target_url: Raw target URL provided by the caller.

        Returns:
            Structured discovery result.

        Raises:
            ValidationError: If the target URL is invalid.
        """
        started_at = datetime.now(tz=UTC)
        started_perf = time.perf_counter()

        normalized_url = validate_url(target_url)
        target = build_target(url=normalized_url, original_url=target_url)
        logger.info("Starting JavaScript discovery for %s", normalized_url)

        client = self._http_client or AsyncHttpClient(
            HttpClientConfig(
                timeout=self._settings.request_timeout,
                user_agent=self._settings.user_agent,
                max_retries=self._settings.max_retries,
            )
        )

        try:
            html_downloader = HtmlDownloader(client)
            html_document = await html_downloader.download(normalized_url)

            metadata_parse = self._metadata_parser.parse(
                html_document.content,
                base_url=html_document.url,
            )
            metadata_observation = None

            pipeline_result = await self._javascript_pipeline.process_html(
                html=html_document.content,
                base_url=html_document.url,
                client=client,
            )

            if self._config.collect_metadata:
                metadata_collector = WellKnownResourceCollector(client)
                well_known_resources = await metadata_collector.collect(
                    html_document.url,
                    linked_urls=metadata_parse.linked_resource_urls,
                )
                metadata_observation = MetadataDiscoveryObservation(
                    html=metadata_parse.html_metadata,
                    well_known_resources=well_known_resources,
                    sourcemap_references=_merge_sourcemap_references(
                        metadata_parse.sourcemap_references,
                        _inline_scripts_from_index(pipeline_result.index),
                        _downloads_from_index(pipeline_result.index),
                    ),
                    service_worker_references=metadata_parse.service_worker_references,
                )

            elapsed_ms = (time.perf_counter() - started_perf) * 1000

            from techspecter.analysis.http.helpers import build_http_observation

            http_response = build_http_observation(
                url=html_document.request_url or normalized_url,
                final_url=html_document.url,
                status_code=html_document.status_code,
                headers=html_document.headers,
                raw_headers=html_document.raw_headers,
                set_cookies=html_document.set_cookies,
                redirects=html_document.redirects,
                content_type=html_document.content_type,
                encoding=html_document.encoding,
                body_size=html_document.body_size,
                elapsed_ms=html_document.elapsed_ms,
            )

            asset_inventory = None
            if self._config.collect_asset_inventory:
                from techspecter.asset_discovery.pipeline import AssetDiscoveryPipeline
                from techspecter.javascript.index.javascript_index import JavaScriptIndex

                asset_pipeline = self._asset_pipeline or AssetDiscoveryPipeline()
                pre_downloaded: frozenset[str] = frozenset()
                if isinstance(pipeline_result.index, JavaScriptIndex):
                    from techspecter.asset_discovery.inventory import inventory_key

                    pre_downloaded = frozenset(
                        inventory_key(str(resource.url))
                        for resource in pipeline_result.index.all_resources()
                        if resource.download_success and not resource.inline
                    )
                link_header = html_document.headers.get("link") or html_document.headers.get(
                    "Link",
                )
                asset_inventory = await asset_pipeline.run(
                    base_url=html_document.url,
                    html=html_document.content,
                    client=client,
                    javascript_index=pipeline_result.index,
                    metadata_observation=metadata_observation,
                    http_link_header=link_header,
                    pre_downloaded_keys=pre_downloaded,
                )

            result = to_discovery_result(
                target=target,
                pipeline_result=pipeline_result,
                http_response=http_response,
                metadata_observation=metadata_observation,
                asset_inventory=asset_inventory,
                elapsed_ms=elapsed_ms,
                started_at=started_at,
                completed_at=datetime.now(tz=UTC),
            )

            if self._config.collect_sensitive_intelligence:
                from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine

                sensitive_report = SensitiveIntelligenceEngine().build(result)
                result = result.model_copy(update={"sensitive_intelligence": sensitive_report})

            logger.info(
                "Discovery complete for %s: %d external, %d inline, %d downloaded, "
                "%d failed, %d indexed (%.0f ms)",
                normalized_url,
                len(result.external_scripts),
                len(result.inline_scripts),
                result.downloaded_count,
                result.failed_count,
                pipeline_result.index.count,
                elapsed_ms,
            )
            return result
        finally:
            if self._owns_client:
                await client.close()


def _inline_scripts_from_index(index: object) -> list[InlineScript]:
    """Extract inline scripts from JavaScript index for metadata merge."""
    from techspecter.javascript.index.javascript_index import JavaScriptIndex

    if not isinstance(index, JavaScriptIndex):
        return []
    scripts: list[InlineScript] = []
    for resource in index.all_resources():
        if not resource.inline:
            continue
        scripts.append(
            InlineScript(
                index=resource.inline_index or 0,
                content=resource.content or "",
                source_map_url=resource.metadata.source_map_url,
            ),
        )
    return scripts


def _downloads_from_index(index: object) -> list[DownloadResult]:
    """Extract download results from JavaScript index for metadata merge."""
    from techspecter.javascript.index.javascript_index import JavaScriptIndex

    if not isinstance(index, JavaScriptIndex):
        return []
    downloads: list[DownloadResult] = []
    for resource in index.all_resources():
        if resource.inline:
            continue
        downloads.append(
            DownloadResult(
                url=resource.url,  # type: ignore[arg-type]
                filename=resource.metadata.filename,
                status_code=resource.status_code,
                content_type=resource.content_type,
                encoding=resource.encoding,
                content_length=resource.metadata.content_length,
                download_success=resource.download_success,
                download_duration_ms=resource.download_duration_ms,
                error_message=resource.error_message,
                source_map_url=resource.metadata.source_map_url,
                content=resource.content,
            ),
        )
    return downloads


def _merge_sourcemap_references(
    existing: list[SourceMapReferenceObservation],
    inline_scripts: list[InlineScript],
    downloads: list[DownloadResult],
) -> list[SourceMapReferenceObservation]:
    """Merge SourceMap references from HTML parsing and script discovery."""
    from techspecter.models.metadata import SourceMapReferenceObservation

    references = list(existing)
    seen = {item.url for item in references if item.url}
    for script in inline_scripts:
        if script.source_map_url and script.source_map_url not in seen:
            references.append(
                SourceMapReferenceObservation(
                    url=script.source_map_url,
                    inline=False,
                    source="inline-script-discovery",
                    location=f"inline-script:{script.index}",
                )
            )
            seen.add(script.source_map_url)
    for download in downloads:
        if download.source_map_url and download.source_map_url not in seen:
            references.append(
                SourceMapReferenceObservation(
                    url=download.source_map_url,
                    inline=False,
                    source="external-script-discovery",
                    location=str(download.url),
                )
            )
            seen.add(download.source_map_url)
    return references
