"""Passive source map downloader."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10.0


def fetch_source_map(url: str, *, timeout: float = _DEFAULT_TIMEOUT) -> str | None:
    """Download source map content passively when URL is fetchable."""
    if url.startswith("data:"):
        return _decode_data_url(url)
    if not url.startswith(("http://", "https://")):
        logger.debug("Skipping non-http source map URL: %s", url)
        return None

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.text
    except httpx.HTTPError as exc:
        logger.warning("Source map download failed for %s: %s", url, exc)
        return None


def _decode_data_url(url: str) -> str | None:
    """Decode inline data URL source maps."""
    if "," not in url:
        return None
    _, payload = url.split(",", 1)
    if url.startswith("data:application/json;base64,"):
        import base64

        try:
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        except Exception as exc:
            logger.debug("Failed to decode base64 source map: %s", exc)
            return None
    return payload
