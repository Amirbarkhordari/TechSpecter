"""JavaScript discovery pipeline orchestration."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from techspecter.config import Settings, get_settings
from techspecter.downloader.html_downloader import HtmlDownloader
from techspecter.downloader.http_client import AsyncHttpClient, HttpClientConfig
from techspecter.downloader.js_downloader import JsDownloadConfig, JsDownloader
from techspecter.models.discovery import DiscoveryResult
from techspecter.parser.html_parser import HtmlScriptParser
from techspecter.utils.dedup import deduplicate_scripts
from techspecter.utils.url import validate_url
from techspecter.utils.validation import build_target

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DiscoveryPipelineConfig:
    """Configuration for the JavaScript discovery pipeline.

    Attributes:
        settings: Application settings used to configure HTTP behavior.
    """

    settings: Settings | None = None


class DiscoveryPipeline:
    """End-to-end JavaScript discovery pipeline."""

    def __init__(
        self,
        config: DiscoveryPipelineConfig | None = None,
        *,
        http_client: AsyncHttpClient | None = None,
        html_parser: HtmlScriptParser | None = None,
    ) -> None:
        """Initialize the discovery pipeline.

        Args:
            config: Optional pipeline configuration.
            http_client: Optional preconfigured HTTP client for dependency injection.
            html_parser: Optional HTML parser for dependency injection.
        """
        self._config = config or DiscoveryPipelineConfig()
        self._settings = self._config.settings or get_settings()
        self._http_client = http_client
        self._html_parser = html_parser or HtmlScriptParser()
        self._owns_client = http_client is None

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

            parse_result = self._html_parser.parse(
                html_document.content,
                base_url=html_document.url,
            )

            external_scripts = deduplicate_scripts(parse_result.external_scripts)
            js_downloader = JsDownloader(
                client,
                JsDownloadConfig(max_concurrency=self._settings.max_concurrency),
            )
            downloads = await js_downloader.download_all(external_scripts)

            elapsed_ms = (time.perf_counter() - started_perf) * 1000
            completed_at = datetime.now(tz=UTC)

            result = DiscoveryResult(
                target=target,
                external_scripts=external_scripts,
                inline_scripts=parse_result.inline_scripts,
                downloads=downloads,
                elapsed_ms=elapsed_ms,
                started_at=started_at,
                completed_at=completed_at,
            )

            logger.info(
                "Discovery complete for %s: %d external, %d inline, %d downloaded, "
                "%d failed (%.0f ms)",
                normalized_url,
                len(result.external_scripts),
                len(result.inline_scripts),
                result.downloaded_count,
                result.failed_count,
                elapsed_ms,
            )
            return result
        finally:
            if self._owns_client:
                await client.close()
