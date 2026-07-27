"""HTML document downloader."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

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
        request_url: Original request URL before redirects.
        headers: Normalized response headers keyed by lowercase name.
        raw_headers: Raw response headers as received.
        set_cookies: Parsed Set-Cookie header values.
        redirects: Redirect chain as ``(url, status_code, location)`` tuples.
        body_size: Response body size in bytes.
        elapsed_ms: Request elapsed time in milliseconds when available.
    """

    url: str
    content: str
    status_code: int
    content_type: str | None
    encoding: str | None
    request_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    redirects: list[tuple[str, int, str | None]] = field(default_factory=list)
    body_size: int = 0
    elapsed_ms: float | None = None


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
        headers, raw_headers, set_cookies = _extract_headers(response)
        redirects = _extract_redirects(response)
        elapsed_ms = _response_elapsed_ms(response)
        body_size = len(response.content)

        logger.info("Downloaded HTML from %s (%d bytes)", final_url, body_size)

        return HtmlDocument(
            url=final_url,
            content=content,
            status_code=response.status_code,
            content_type=content_type,
            encoding=encoding,
            request_url=url,
            headers=headers,
            raw_headers=raw_headers,
            set_cookies=set_cookies,
            redirects=redirects,
            body_size=body_size,
            elapsed_ms=elapsed_ms,
        )


def _extract_headers(response: httpx.Response) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """Extract normalized headers, raw headers, and Set-Cookie values."""
    normalized: dict[str, str] = {}
    raw: dict[str, str] = {}
    set_cookies: list[str] = []

    for key, value in response.headers.multi_items():
        raw[key] = value
        lower_key = key.lower()
        if lower_key == "set-cookie":
            set_cookies.append(value)
        else:
            normalized[lower_key] = value

    return normalized, raw, set_cookies


def _extract_redirects(response: httpx.Response) -> list[tuple[str, int, str | None]]:
    """Extract redirect chain metadata from an httpx response."""
    redirects: list[tuple[str, int, str | None]] = []
    for prior in response.history:
        location = prior.headers.get("location")
        redirects.append((str(prior.url), prior.status_code, location))
    return redirects


def _response_elapsed_ms(response: httpx.Response) -> float | None:
    """Return response elapsed time in milliseconds when available."""
    elapsed = getattr(response, "elapsed", None)
    if elapsed is None:
        return None
    return float(elapsed.total_seconds() * 1000)
