"""HTML document downloader."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from techspecter.downloader.http_client import AsyncHttpClient
from techspecter.exceptions import DownloaderError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HtmlDocument:
    """Downloaded HTML document with metadata.

    Attributes:
        url: Final URL after redirects.
        content: Decoded HTML content.
        status_code: HTTP response status code.
        content_type: Response Content-Type header value.
        encoding: Character encoding used for decoding.
    """

    url: str
    content: str
    status_code: int
    content_type: str | None
    encoding: str | None


class HtmlDownloader:
    """Download and decode HTML documents from target URLs."""

    def __init__(self, client: AsyncHttpClient) -> None:
        """Initialize the HTML downloader.

        Args:
            client: Shared asynchronous HTTP client.
        """
        self._client = client

    async def download(self, url: str) -> HtmlDocument:
        """Download an HTML document.

        Args:
            url: Target page URL.

        Returns:
            Parsed ``HtmlDocument`` instance.

        Raises:
            DownloaderError: If the download fails or the response is not HTML.
        """
        try:
            response = await self._client.get(url)
        except DownloaderError:
            raise
        except httpx.HTTPError as exc:
            msg = f"Failed to download HTML from {url}: {exc}"
            raise DownloaderError(msg) from exc

        if response.status_code >= 400:
            msg = f"HTTP {response.status_code} while downloading HTML from {url}"
            raise DownloaderError(msg)

        content_type = response.headers.get("content-type")
        if content_type and "html" not in content_type.lower():
            logger.warning("Unexpected content type for %s: %s", url, content_type)

        encoding = response.encoding or "utf-8"
        try:
            content = response.text
        except UnicodeDecodeError as exc:
            content = response.content.decode("utf-8", errors="replace")
            encoding = "utf-8"
            logger.warning("Encoding fallback used for %s: %s", url, exc)

        final_url = str(response.url)
        logger.info("Downloaded HTML from %s (%d bytes)", final_url, len(response.content))

        return HtmlDocument(
            url=final_url,
            content=content,
            status_code=response.status_code,
            content_type=content_type,
            encoding=encoding,
        )
