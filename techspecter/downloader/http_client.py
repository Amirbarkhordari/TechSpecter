"""Reusable asynchronous HTTP client for TechSpecter."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

from techspecter.exceptions import DownloaderError

logger = logging.getLogger(__name__)

DEFAULT_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({408, 429, 500, 502, 503, 504})


@dataclass(slots=True)
class HttpClientConfig:
    """Configuration for the asynchronous HTTP client.

    Attributes:
        timeout: Request timeout in seconds.
        user_agent: Default User-Agent header value.
        max_retries: Maximum retry attempts for retryable failures.
        follow_redirects: Whether to follow HTTP redirects.
        headers: Additional default request headers.
    """

    timeout: float = 30.0
    user_agent: str = "TechSpecter/0.2.0"
    max_retries: int = 3
    follow_redirects: bool = True
    headers: dict[str, str] = field(default_factory=dict)


class AsyncHttpClient:
    """Reusable ``httpx.AsyncClient`` wrapper with retry support."""

    def __init__(self, config: HttpClientConfig | None = None) -> None:
        """Initialize the HTTP client.

        Args:
            config: Optional client configuration. Uses defaults when omitted.
        """
        self._config = config or HttpClientConfig()
        default_headers = {"User-Agent": self._config.user_agent}
        default_headers.update(self._config.headers)
        self._client = httpx.AsyncClient(
            timeout=self._config.timeout,
            follow_redirects=self._config.follow_redirects,
            headers=default_headers,
        )

    async def __aenter__(self) -> AsyncHttpClient:
        """Enter the async context manager."""
        return self

    async def __aexit__(self, *args: object) -> None:
        """Exit the async context manager and close the client."""
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform an HTTP GET request with retry logic.

        Args:
            url: Target URL.
            headers: Optional per-request headers merged with defaults.

        Returns:
            Successful ``httpx.Response`` instance.

        Raises:
            DownloaderError: If all retry attempts fail.
        """
        last_error: Exception | None = None

        for attempt in range(1, self._config.max_retries + 1):
            try:
                logger.debug("GET %s (attempt %d/%d)", url, attempt, self._config.max_retries)
                response = await self._client.get(url, headers=headers)
                if response.status_code in DEFAULT_RETRYABLE_STATUS_CODES:
                    msg = f"Retryable HTTP status {response.status_code} for {url}"
                    raise DownloaderError(msg)
                return response
            except (httpx.HTTPError, DownloaderError) as exc:
                last_error = exc
                logger.warning(
                    "Request failed for %s on attempt %d/%d: %s",
                    url,
                    attempt,
                    self._config.max_retries,
                    exc,
                )
                if attempt < self._config.max_retries:
                    await asyncio.sleep(min(2 ** (attempt - 1), 8))

        msg = f"Failed to download {url} after {self._config.max_retries} attempts."
        raise DownloaderError(msg) from last_error

    @property
    def config(self) -> HttpClientConfig:
        """Return the active client configuration."""
        return self._config

    @property
    def raw_client(self) -> httpx.AsyncClient:
        """Return the underlying ``httpx.AsyncClient`` instance."""
        return self._client
