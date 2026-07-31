"""External JavaScript resource downloader."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import httpx

from techspecter.downloader.http_client import AsyncHttpClient
from techspecter.exceptions import DownloaderError
from techspecter.models.discovery import DownloadResult, ScriptResource
from techspecter.parser.sourcemap import detect_source_map_url
from techspecter.utils.url import filename_from_url

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class JsDownloadConfig:
    """Configuration for JavaScript downloads.

    Attributes:
        max_concurrency: Maximum number of concurrent downloads.
    """

    max_concurrency: int = 10


class JsDownloader:
    """Download external JavaScript resources asynchronously."""

    def __init__(
        self,
        client: AsyncHttpClient,
        config: JsDownloadConfig | None = None,
    ) -> None:
        """Initialize the JavaScript downloader.

        Args:
            client: Shared asynchronous HTTP client.
            config: Optional download configuration.
        """
        self._client = client
        self._config = config or JsDownloadConfig()

    async def download_all(self, scripts: list[ScriptResource]) -> list[DownloadResult]:
        """Download all external JavaScript resources.

        Failures for individual resources do not stop remaining downloads.

        Args:
            scripts: External script resources to download.

        Returns:
            Download result metadata for each script.
        """
        if not scripts:
            return []

        semaphore = asyncio.Semaphore(self._config.max_concurrency)
        tasks = [self._download_one(script, semaphore) for script in scripts]
        return list(await asyncio.gather(*tasks))

    async def _download_one(
        self,
        script: ScriptResource,
        semaphore: asyncio.Semaphore,
    ) -> DownloadResult:
        """Download a single JavaScript resource.

        Args:
            script: Script resource to download.
            semaphore: Concurrency limiter.

        Returns:
            Download metadata for the resource.
        """
        url = str(script.url)
        filename = filename_from_url(url)
        started = time.perf_counter()

        async with semaphore:
            try:
                response = await self._client.get(url)
                duration_ms = (time.perf_counter() - started) * 1000
                return self._build_success_result(
                    response,
                    script=script,
                    filename=filename,
                    duration_ms=duration_ms,
                )
            except (DownloaderError, httpx.HTTPError) as exc:
                duration_ms = (time.perf_counter() - started) * 1000
                logger.debug("Failed to download JavaScript %s: %s", url, exc)
                return DownloadResult(
                    url=script.url,
                    filename=filename,
                    download_success=False,
                    download_duration_ms=duration_ms,
                    error_message=str(exc),
                )

    def _build_success_result(
        self,
        response: httpx.Response,
        *,
        script: ScriptResource,
        filename: str,
        duration_ms: float,
    ) -> DownloadResult:
        """Build a download result from an HTTP response.

        Args:
            response: HTTP response object.
            script: Original script resource metadata.
            filename: Derived filename.
            duration_ms: Download duration in milliseconds.

        Returns:
            ``DownloadResult`` instance with response metadata.
        """
        resource_url = str(response.url)
        encoding = response.encoding or "utf-8"
        content_type = response.headers.get("content-type")
        content_length = len(response.content)
        source_map_url: str | None = None
        body_text: str | None = None

        if response.status_code < 400 and response.content:
            body_text = _decode_response_body(response)
            source_map_url = detect_source_map_url(body_text, base_url=resource_url)

        success = response.status_code < 400
        error_message = None if success else f"HTTP {response.status_code}"

        logger.debug(
            "Downloaded JavaScript %s (%d bytes, %d ms)",
            resource_url,
            content_length,
            int(duration_ms),
        )

        return DownloadResult(
            url=script.url,
            filename=filename,
            status_code=response.status_code,
            content_type=content_type,
            encoding=encoding,
            content_length=content_length,
            download_success=success,
            download_duration_ms=duration_ms,
            error_message=error_message,
            source_map_url=source_map_url,
            content=body_text,
        )


def _decode_response_body(response: httpx.Response) -> str:
    """Decode an HTTP response body as text.

    Args:
        response: HTTP response object.

    Returns:
        Decoded response body text.
    """
    encoding = response.encoding or "utf-8"
    try:
        return response.content.decode(encoding, errors="replace")
    except LookupError:
        return response.content.decode("utf-8", errors="replace")
