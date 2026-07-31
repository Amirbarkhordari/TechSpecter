"""Staged JavaScript discovery and preprocessing pipeline."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime

from techspecter.downloader.http_client import AsyncHttpClient
from techspecter.downloader.js_downloader import JsDownloadConfig, JsDownloader
from techspecter.javascript.ast.preparation import AstPreparationStage
from techspecter.javascript.cache.resource_cache import (
    JavaScriptResourceCache,
    get_javascript_cache,
)
from techspecter.javascript.discovery.engine import JavaScriptDiscoveryEngine
from techspecter.javascript.index.javascript_index import JavaScriptIndex, JavaScriptPipelineResult
from techspecter.javascript.metadata.extractor import JavaScriptMetadataExtractor
from techspecter.javascript.models import (
    AstSnapshot,
    DiscoveredReference,
    DiscoverySource,
    IndexedJavaScriptResource,
    JavaScriptPipelineStatistics,
    ModuleType,
)
from techspecter.javascript.normalization.pipeline import (
    JavaScriptNormalizationPipeline,
    NormalizationResult,
)
from techspecter.javascript.pipeline.config import JavaScriptPipelineConfig
from techspecter.models.discovery import InlineScript, ScriptResource
from techspecter.utils.url import normalize_url

logger = logging.getLogger(__name__)

_HTML_ENTRY_SOURCES = {
    DiscoverySource.HTML_SCRIPT,
    DiscoverySource.HTML_MODULE,
    DiscoverySource.HTML_ASYNC,
    DiscoverySource.HTML_DEFERRED,
}


class JavaScriptPipeline:
    """Modular JavaScript discovery and preprocessing pipeline (Phase 5.7)."""

    def __init__(
        self,
        config: JavaScriptPipelineConfig | None = None,
        *,
        discovery_engine: JavaScriptDiscoveryEngine | None = None,
        normalizer: JavaScriptNormalizationPipeline | None = None,
        metadata_extractor: JavaScriptMetadataExtractor | None = None,
        ast_stage: AstPreparationStage | None = None,
        cache: JavaScriptResourceCache | None = None,
    ) -> None:
        """Initialize pipeline with injectable stages."""
        self._config = config or JavaScriptPipelineConfig()
        self._cache = cache if self._config.cache_enabled else None
        if self._cache is None and self._config.cache_enabled:
            self._cache = get_javascript_cache()
        self._discovery = discovery_engine or JavaScriptDiscoveryEngine(config=self._config)
        self._normalizer = normalizer or JavaScriptNormalizationPipeline(
            max_bytes=self._config.max_content_bytes,
        )
        self._metadata = metadata_extractor or JavaScriptMetadataExtractor()
        self._ast = ast_stage or AstPreparationStage(cache=self._cache)

    async def process_html(
        self,
        *,
        html: str,
        base_url: str,
        client: AsyncHttpClient,
    ) -> JavaScriptPipelineResult:
        """Run full pipeline starting from HTML content."""
        started_at = datetime.now(tz=UTC)
        started_perf = time.perf_counter()
        stats = JavaScriptPipelineStatistics()
        index = JavaScriptIndex()

        parse_result, seed_refs, inline_scripts = self._discovery.seed_from_html(
            html,
            base_url=base_url,
        )
        stats.inline_resources = len(inline_scripts)
        stats.discovered_urls = len(seed_refs)

        references, rounds = await self._discovery.discover_recursive(client, seed_refs)
        stats.recursive_rounds = rounds
        stats.discovered_urls = len(references)

        scripts = self._references_to_scripts(references)
        js_downloader = JsDownloader(
            client,
            JsDownloadConfig(max_concurrency=self._config.max_concurrency),
        )
        downloads = await js_downloader.download_all(scripts)

        ref_by_url = {normalize_url(str(item.url)): item for item in references}
        content_hashes: dict[str, str] = {}

        for download in downloads:
            self._process_download(
                download=download,
                ref_by_url=ref_by_url,
                index=index,
                stats=stats,
                content_hashes=content_hashes,
            )

        for inline in inline_scripts:
            self._process_inline(
                inline=inline,
                index=index,
                stats=stats,
                content_hashes=content_hashes,
            )

        stats.elapsed_ms = (time.perf_counter() - started_perf) * 1000
        if self._cache is not None:
            stats.cache_hits = self._cache.total_hits

        completed_at = datetime.now(tz=UTC)
        logger.info(
            "JavaScript pipeline complete: %d indexed, %d duplicates skipped, "
            "%d recursive rounds (%.0f ms)",
            index.count,
            stats.duplicate_skipped,
            stats.recursive_rounds,
            stats.elapsed_ms,
        )

        return JavaScriptPipelineResult(
            index=index,
            statistics=stats,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
        )

    def _process_download(
        self,
        *,
        download: object,
        ref_by_url: dict[str, DiscoveredReference],
        index: JavaScriptIndex,
        stats: JavaScriptPipelineStatistics,
        content_hashes: dict[str, str],
    ) -> None:
        """Process a downloaded external resource through all stages."""
        from techspecter.models.discovery import DownloadResult

        if not isinstance(download, DownloadResult):
            return

        url_key = normalize_url(str(download.url))
        if index.get_by_url(url_key) is not None:
            return

        reference = ref_by_url.get(url_key)
        module_type = reference.module_type if reference else ModuleType.UNKNOWN
        sources = [reference.source] if reference else [DiscoverySource.HTML_SCRIPT]
        is_entry = reference.source in _HTML_ENTRY_SOURCES if reference else False

        if not download.download_success or not download.content:
            stats.failed_downloads += 1
            resource = self._build_failed_resource(
                download=download,
                module_type=module_type,
                sources=sources,
                is_entry=is_entry,
            )
            index.add(resource)
            stats.downloaded_resources += 1
            return

        content_hash = JavaScriptResourceCache.content_hash(download.content)
        duplicate_id = self._check_duplicate(
            content_hash=content_hash,
            index=index,
            stats=stats,
            content_hashes=content_hashes,
        )
        if duplicate_id is not None:
            resource = self._build_duplicate_resource(
                download=download,
                duplicate_of=duplicate_id,
                content_hash=content_hash,
                module_type=module_type,
                sources=sources,
                is_entry=is_entry,
            )
            index.add(resource)
            return

        content_hashes[content_hash] = url_key
        normalized = self._normalize_with_cache(url_key, download.content)
        import_refs, export_refs, ast_snapshot = self._prepare_ast(
            url=url_key,
            filename=download.filename,
            content=normalized.content,
            is_minified=normalized.is_minified,
        )
        metadata = self._metadata.extract(
            url=url_key,
            filename=download.filename,
            content=download.content,
            normalized=normalized,
            module_type=module_type,
            discovery_sources=sources,
            is_entry=is_entry,
            import_refs=import_refs,
            export_refs=export_refs,
            cache=self._cache,
        )

        resource = IndexedJavaScriptResource(
            resource_id=str(uuid.uuid4()),
            url=str(download.url),
            original_url=reference.original_reference if reference else str(download.url),
            download_success=True,
            status_code=download.status_code,
            content_type=download.content_type,
            encoding=download.encoding,
            content=download.content,
            normalized_content=normalized.content,
            metadata=metadata,
            ast=ast_snapshot,
            download_duration_ms=download.download_duration_ms,
        )
        index.add(resource)
        stats.downloaded_resources += 1

    def _process_inline(
        self,
        *,
        inline: InlineScript,
        index: JavaScriptIndex,
        stats: JavaScriptPipelineStatistics,
        content_hashes: dict[str, str],
    ) -> None:
        """Process inline script through pipeline stages."""
        inline_url = f"inline://script/{inline.index}"
        if index.get_by_url(inline_url) is not None:
            return

        content_hash = JavaScriptResourceCache.content_hash(inline.content)
        duplicate_id = self._check_duplicate(
            content_hash=content_hash,
            index=index,
            stats=stats,
            content_hashes=content_hashes,
        )
        if duplicate_id is not None:
            metadata = self._metadata.extract(
                url=inline_url,
                filename=f"inline-{inline.index}.js",
                content=inline.content,
                normalized=self._normalizer.normalize(inline.content),
                module_type=ModuleType.CLASSIC,
                discovery_sources=[DiscoverySource.HTML_SCRIPT],
                is_entry=False,
                cache=self._cache,
            )
            index.add(
                IndexedJavaScriptResource(
                    resource_id=str(uuid.uuid4()),
                    url=inline_url,
                    original_url=inline_url,
                    inline=True,
                    inline_index=inline.index,
                    content=inline.content,
                    normalized_content=inline.content,
                    metadata=metadata,
                    duplicate_of=duplicate_id,
                ),
            )
            return

        content_hashes[content_hash] = inline_url
        normalized = self._normalize_with_cache(inline_url, inline.content)
        import_refs, export_refs, ast_snapshot = self._prepare_ast(
            url=inline_url,
            filename=f"inline-{inline.index}.js",
            content=normalized.content,
            is_minified=normalized.is_minified,
        )
        metadata = self._metadata.extract(
            url=inline_url,
            filename=f"inline-{inline.index}.js",
            content=inline.content,
            normalized=normalized,
            module_type=ModuleType.CLASSIC,
            discovery_sources=[DiscoverySource.HTML_SCRIPT],
            is_entry=False,
            import_refs=import_refs,
            export_refs=export_refs,
            cache=self._cache,
        )
        index.add(
            IndexedJavaScriptResource(
                resource_id=str(uuid.uuid4()),
                url=inline_url,
                original_url=inline_url,
                inline=True,
                inline_index=inline.index,
                content=inline.content,
                normalized_content=normalized.content,
                metadata=metadata,
                ast=ast_snapshot,
            ),
        )

    def _normalize_with_cache(self, url: str, content: str) -> NormalizationResult:
        """Normalize content with optional caching."""
        if self._cache is None:
            return self._normalizer.normalize(content)
        cache_key = JavaScriptResourceCache.content_key(url=url, content=content)
        cached = self._cache.normalized_cache.get(cache_key)
        if cached is not None:
            return cached
        normalized = self._normalizer.normalize(content)
        self._cache.normalized_cache.set(cache_key, normalized)
        return normalized

    def _prepare_ast(
        self,
        *,
        url: str,
        filename: str,
        content: str,
        is_minified: bool,
    ) -> tuple[list[str], list[str], AstSnapshot | None]:
        """Prepare AST when enabled."""
        if not self._config.enable_ast_preparation:
            return [], [], None
        prepared = self._ast.prepare(
            url=url,
            filename=filename,
            content=content,
            is_minified=is_minified,
        )
        import_refs = [item.module for item in prepared.parsed.imports]
        export_refs = [item.name or item.raw for item in prepared.parsed.exports]
        return import_refs, export_refs, prepared.snapshot

    def _check_duplicate(
        self,
        *,
        content_hash: str,
        index: JavaScriptIndex,
        stats: JavaScriptPipelineStatistics,
        content_hashes: dict[str, str],
    ) -> str | None:
        """Return existing resource id for duplicate content."""
        if not self._config.enable_content_hash_dedup:
            return None
        existing_url = content_hashes.get(content_hash)
        if existing_url is None:
            existing = index.get_by_hash(content_hash)
            if existing is None:
                return None
            return existing.resource_id
        existing = index.get_by_url(existing_url)
        if existing is None:
            return None
        stats.duplicate_skipped += 1
        return existing.resource_id

    def _build_failed_resource(
        self,
        *,
        download: object,
        module_type: ModuleType,
        sources: list[DiscoverySource],
        is_entry: bool,
    ) -> IndexedJavaScriptResource:
        """Build indexed resource for failed download."""
        from techspecter.models.discovery import DownloadResult

        assert isinstance(download, DownloadResult)
        url_key = normalize_url(str(download.url))
        metadata = self._metadata.extract(
            url=url_key,
            filename=download.filename,
            content="",
            normalized=self._normalizer.normalize(""),
            module_type=module_type,
            discovery_sources=sources,
            is_entry=is_entry,
            cache=self._cache,
        )
        return IndexedJavaScriptResource(
            resource_id=str(uuid.uuid4()),
            url=str(download.url),
            original_url=str(download.url),
            download_success=False,
            status_code=download.status_code,
            error_message=download.error_message,
            metadata=metadata,
            download_duration_ms=download.download_duration_ms,
        )

    def _build_duplicate_resource(
        self,
        *,
        download: object,
        duplicate_of: str,
        content_hash: str,
        module_type: ModuleType,
        sources: list[DiscoverySource],
        is_entry: bool,
    ) -> IndexedJavaScriptResource:
        """Build lightweight duplicate reference resource."""
        from techspecter.models.discovery import DownloadResult

        assert isinstance(download, DownloadResult)
        url_key = normalize_url(str(download.url))
        metadata = self._metadata.extract(
            url=url_key,
            filename=download.filename,
            content=download.content or "",
            normalized=self._normalizer.normalize(download.content or ""),
            module_type=module_type,
            discovery_sources=sources,
            is_entry=is_entry,
            cache=self._cache,
        )
        _ = content_hash
        return IndexedJavaScriptResource(
            resource_id=str(uuid.uuid4()),
            url=str(download.url),
            original_url=str(download.url),
            download_success=download.download_success,
            content=download.content,
            metadata=metadata,
            duplicate_of=duplicate_of,
            download_duration_ms=download.download_duration_ms,
        )

    @staticmethod
    def _references_to_scripts(references: list[DiscoveredReference]) -> list[ScriptResource]:
        """Convert discovered references to script resources for download."""
        scripts: list[ScriptResource] = []
        seen: set[str] = set()
        for reference in references:
            key = normalize_url(str(reference.url))
            if key in seen:
                continue
            seen.add(key)
            scripts.append(
                ScriptResource(
                    url=reference.url,
                    original_url=reference.original_reference,
                ),
            )
        return scripts
