"""Passive well-known resource collection."""

from __future__ import annotations

import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

from techspecter.downloader.http_client import AsyncHttpClient
from techspecter.exceptions import DownloaderError
from techspecter.models.metadata import WellKnownResourceObservation

logger = logging.getLogger(__name__)

# Fixed whitelist of intentionally public well-known paths (no directory enumeration).
WELL_KNOWN_PATHS: dict[str, str] = {
    "robots.txt": "/robots.txt",
    "sitemap.xml": "/sitemap.xml",
    "security.txt": "/.well-known/security.txt",
    "humans.txt": "/humans.txt",
    "ads.txt": "/ads.txt",
    "assetlinks.json": "/.well-known/assetlinks.json",
    "apple-app-site-association": "/.well-known/apple-app-site-association",
    "favicon.ico": "/favicon.ico",
    "site.webmanifest": "/site.webmanifest",
    "browserconfig.xml": "/browserconfig.xml",
    "manifest.json": "/manifest.json",
}

_SITEMAP_PATTERN = re.compile(r"(?im)^Sitemap:\s*(\S+)")


class WellKnownResourceCollector:
    """Collect publicly available well-known resources passively."""

    def __init__(self, client: AsyncHttpClient) -> None:
        """Initialize the collector."""
        self._client = client

    async def collect(
        self,
        base_url: str,
        *,
        linked_urls: dict[str, list[str]] | None = None,
    ) -> list[WellKnownResourceObservation]:
        """Collect well-known resources for a target origin."""
        origin = _origin_from_url(base_url)
        urls_to_fetch: dict[str, tuple[str, str]] = {}

        for resource_type, path in WELL_KNOWN_PATHS.items():
            urls_to_fetch[resource_type] = (urljoin(origin, path), "well-known-path")

        for resource_type, urls in (linked_urls or {}).items():
            for linked in urls:
                normalized_type = _normalize_linked_type(resource_type)
                if normalized_type not in urls_to_fetch:
                    urls_to_fetch[normalized_type] = (linked, "html-link")

        observations: list[WellKnownResourceObservation] = []
        for resource_type, (url, discovered_via) in urls_to_fetch.items():
            observation = await self._fetch_resource(
                resource_type=resource_type,
                url=url,
                discovered_via=discovered_via,
            )
            observations.append(observation)

            if resource_type == "robots.txt" and observation.available and observation.content:
                for sitemap_url in _extract_sitemap_urls(observation.content):
                    sitemap_observation = await self._fetch_resource(
                        resource_type="sitemap.xml",
                        url=sitemap_url,
                        discovered_via="robots.txt",
                    )
                    if not any(item.url == sitemap_observation.url for item in observations):
                        observations.append(sitemap_observation)

        logger.info(
            "Collected %d well-known resources for %s (%d available)",
            len(observations),
            origin,
            sum(1 for item in observations if item.available),
        )
        return observations

    async def _fetch_resource(
        self,
        *,
        resource_type: str,
        url: str,
        discovered_via: str,
    ) -> WellKnownResourceObservation:
        """Fetch a single well-known resource without raising on failure."""
        try:
            response = await self._client.get(url)
            available = 200 <= response.status_code < 400
            content: str | None = None
            if available:
                content = _safe_response_text(response)
            return WellKnownResourceObservation(
                resource_type=resource_type,
                url=url,
                status_code=response.status_code,
                content_type=response.headers.get("content-type"),
                content=content,
                available=available,
                discovered_via=discovered_via,
            )
        except (httpx.HTTPError, DownloaderError) as exc:
            logger.debug("Well-known resource unavailable %s: %s", url, exc)
            return WellKnownResourceObservation(
                resource_type=resource_type,
                url=url,
                available=False,
                discovered_via=discovered_via,
            )


def _origin_from_url(url: str) -> str:
    """Return the origin for a URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _normalize_linked_type(resource_type: str) -> str:
    """Normalize linked resource type names."""
    mapping = {
        "manifest": "site.webmanifest",
        "browserconfig": "browserconfig.xml",
        "favicon": "favicon.ico",
    }
    return mapping.get(resource_type, resource_type)


def _extract_sitemap_urls(content: str) -> list[str]:
    """Extract sitemap URLs declared in robots.txt."""
    return [match.group(1).strip() for match in _SITEMAP_PATTERN.finditer(content)]


def _safe_response_text(response: httpx.Response) -> str:
    """Return response text with encoding fallback."""
    try:
        return response.text
    except UnicodeDecodeError:
        return response.content.decode("utf-8", errors="replace")
