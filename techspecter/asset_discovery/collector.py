"""Passive asset download collector."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from techspecter.asset_discovery.download_status import (
    classify_download_outcome,
    is_recoverable_download_error,
)
from techspecter.asset_discovery.hash import sha256_hex
from techspecter.asset_discovery.inventory import AssetInventoryBuilder, inventory_key
from techspecter.asset_discovery.models import AssetCategory, AssetDownloadStatus, AssetRecord
from techspecter.downloader.http_client import AsyncHttpClient
from techspecter.exceptions import DownloaderError

logger = logging.getLogger(__name__)

DEFAULT_MAX_CONCURRENCY = 8
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
_TEXT_PREFIXES = ("text/", "application/json", "application/xml", "application/javascript")

# Binary / media assets are discovered for inventory completeness but are not
# useful for text-based technology evidence and must not block fingerprinting.
_SKIP_DOWNLOAD_CATEGORIES = frozenset(
    {
        AssetCategory.IMAGE,
        AssetCategory.FONT,
        AssetCategory.WASM,
    },
)
_SKIP_DOWNLOAD_EXTENSIONS = frozenset(
    {
        ".mp4",
        ".webm",
        ".mkv",
        ".avi",
        ".mov",
        ".m4v",
        ".mp3",
        ".wav",
        ".ogg",
        ".flac",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".ico",
        ".bmp",
        ".avif",
    },
)


@dataclass(slots=True)
class AssetCollectorConfig:
    """Configuration for asset downloads."""

    max_concurrency: int = DEFAULT_MAX_CONCURRENCY
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    download_assets: bool = True


@dataclass(slots=True)
class AssetCollector:
    """Download discovered assets and enrich inventory metadata."""

    client: AsyncHttpClient
    config: AssetCollectorConfig = field(default_factory=AssetCollectorConfig)
    downloaded_text: dict[str, str] = field(default_factory=dict)

    async def enrich_inventory(
        self,
        builder: AssetInventoryBuilder,
        *,
        skip_urls: frozenset[str] | None = None,
    ) -> None:
        """Download assets and update inventory records."""
        if not self.config.download_assets:
            logger.info("Asset downloads disabled by configuration")
            return

        skip = skip_urls or frozenset()
        pending: list[str] = []
        skipped = 0
        for key, record in builder.records.items():
            if record.download_success and record.sha256:
                continue
            if key in skip:
                continue
            if _should_skip_asset_download(record):
                builder.upsert_download(
                    url=record.url,
                    http_status=record.http_status,
                    content_type=record.content_type,
                    encoding=record.encoding,
                    file_size=record.file_size,
                    sha256=record.sha256,
                    download_success=False,
                    download_duration_ms=0.0,
                    response_time_ms=0.0,
                    error_message="Skipped non-text asset (not required for technology evidence)",
                    download_status=AssetDownloadStatus.SKIPPED,
                )
                skipped += 1
                continue
            pending.append(record.url)

        if skipped:
            logger.info("Skipped %d non-text assets (image/font/media/wasm)", skipped)

        if not pending:
            logger.info("No pending assets to download")
            return

        logger.info("Downloading %d discovered assets", len(pending))
        semaphore = asyncio.Semaphore(max(1, self.config.max_concurrency))

        async def download_one(url: str) -> None:
            async with semaphore:
                await self._download_asset(builder, url)

        results = await asyncio.gather(
            *(download_one(url) for url in pending), return_exceptions=True
        )
        for item in results:
            if isinstance(item, BaseException) and not is_recoverable_download_error(item):
                raise item
            if isinstance(item, BaseException):
                logger.debug("Recovered unexpected asset download task failure: %s", item)

    async def _download_asset(self, builder: AssetInventoryBuilder, url: str) -> AssetRecord:
        """Download a single asset with graceful error handling."""
        started = time.perf_counter()
        try:
            response = await self.client.get(url)
            elapsed_ms = (time.perf_counter() - started) * 1000
            content = response.content
            if len(content) > self.config.max_file_size:
                logger.debug(
                    "Skipping asset %s: size %d exceeds limit %d",
                    url,
                    len(content),
                    self.config.max_file_size,
                )
                error_message = "File exceeds configured size limit"
                status = classify_download_outcome(
                    download_success=False,
                    http_status=response.status_code,
                    error_message=error_message,
                )
                return builder.upsert_download(
                    url=url,
                    http_status=response.status_code,
                    content_type=response.headers.get("content-type"),
                    encoding=response.encoding,
                    file_size=len(content),
                    sha256=None,
                    download_success=False,
                    download_duration_ms=elapsed_ms,
                    response_time_ms=elapsed_ms,
                    error_message=error_message,
                    download_status=status,
                )

            digest = sha256_hex(content)
            content_type = response.headers.get("content-type")
            self._maybe_cache_text(inventory_key(url), content, content_type)
            logger.debug(
                "Downloaded asset %s status=%s size=%d sha256=%s",
                url,
                response.status_code,
                len(content),
                digest[:12],
            )
            success = 200 <= response.status_code < 400
            failure_message = None if success else f"HTTP {response.status_code}"
            status = classify_download_outcome(
                download_success=success,
                http_status=response.status_code,
                error_message=failure_message,
            )
            if not success:
                logger.warning(
                    "Asset download failed for %s (%s): %s",
                    url,
                    status.value,
                    failure_message,
                )
            return builder.upsert_download(
                url=url,
                http_status=response.status_code,
                content_type=content_type,
                encoding=response.encoding,
                file_size=len(content),
                sha256=digest,
                download_success=success,
                download_duration_ms=elapsed_ms,
                response_time_ms=elapsed_ms,
                error_message=failure_message,
                download_status=status,
                content=content,
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000
            if not is_recoverable_download_error(exc):
                raise
            error_message = str(exc)
            status = classify_download_outcome(
                download_success=False,
                error_message=error_message,
                exc=exc,
            )
            logger.warning("Asset download failed for %s (%s): %s", url, status.value, exc)
            return builder.upsert_download(
                url=url,
                http_status=_status_from_exception(exc),
                content_type=None,
                encoding=None,
                file_size=None,
                sha256=None,
                download_success=False,
                download_duration_ms=elapsed_ms,
                response_time_ms=elapsed_ms,
                error_message=error_message,
                download_status=status,
            )

    def _maybe_cache_text(self, key: str, content: bytes, content_type: str | None) -> None:
        """Cache textual response bodies for recursive reference extraction."""
        if content_type:
            mime = content_type.split(";", 1)[0].strip().lower()
            if not any(mime.startswith(prefix) for prefix in _TEXT_PREFIXES):
                return
        try:
            self.downloaded_text[key] = content.decode("utf-8", errors="replace")
        except Exception:
            return


def _status_from_exception(exc: BaseException) -> int | None:
    """Extract an HTTP status code from a download exception when available."""
    if isinstance(exc, DownloaderError):
        from techspecter.asset_discovery.download_status import _status_from_message

        return _status_from_message(str(exc))
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None)


def _should_skip_asset_download(record: AssetRecord) -> bool:
    """Return True when an asset cannot contribute text technology evidence."""
    if record.category in _SKIP_DOWNLOAD_CATEGORIES:
        return True
    name = (record.filename or "").lower()
    url = (record.url or "").lower().split("?", 1)[0]
    return any(name.endswith(ext) or url.endswith(ext) for ext in _SKIP_DOWNLOAD_EXTENSIONS)
    if response is not None:
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int):
            return status_code
    return None
