"""Asset download status classification."""

from __future__ import annotations

import re

import httpx

from techspecter.asset_discovery.models import (
    AssetDownloadStatus,
    AssetDownloadSummary,
    AssetRecord,
)
from techspecter.exceptions import DownloaderError

_STATUS_PATTERN = re.compile(r"(?:HTTP status|HTTP)\s+(\d+)", re.I)


def classify_download_outcome(
    *,
    download_success: bool,
    http_status: int | None = None,
    error_message: str | None = None,
    exc: BaseException | None = None,
) -> AssetDownloadStatus:
    """Classify the outcome of an asset download attempt."""
    if download_success:
        return AssetDownloadStatus.DOWNLOADED

    message = " ".join(part for part in (error_message, str(exc) if exc else None) if part)
    lowered = message.lower()
    if "size limit" in lowered or "exceeds limit" in lowered:
        return AssetDownloadStatus.SKIPPED
    if isinstance(exc, httpx.TimeoutException) or "timeout" in lowered:
        return AssetDownloadStatus.TIMEOUT

    status = http_status or _status_from_message(message)
    if status == 403:
        return AssetDownloadStatus.FORBIDDEN
    if status == 429:
        return AssetDownloadStatus.RATE_LIMITED

    return AssetDownloadStatus.FAILED


def build_download_summary(assets: list[AssetRecord]) -> AssetDownloadSummary:
    """Aggregate download outcome counts for an inventory."""
    summary = AssetDownloadSummary()
    for asset in assets:
        status = asset.download_status
        if status is None:
            if asset.download_success:
                summary.downloaded += 1
            elif asset.error_message:
                summary.failed += 1
            continue
        if status == AssetDownloadStatus.DOWNLOADED:
            summary.downloaded += 1
        elif status == AssetDownloadStatus.SKIPPED:
            summary.skipped += 1
        elif status == AssetDownloadStatus.TIMEOUT:
            summary.timeout += 1
        elif status == AssetDownloadStatus.FORBIDDEN:
            summary.forbidden += 1
        elif status == AssetDownloadStatus.RATE_LIMITED:
            summary.rate_limited += 1
        elif status == AssetDownloadStatus.FAILED:
            summary.failed += 1
    summary.total_attempted = (
        summary.downloaded
        + summary.failed
        + summary.skipped
        + summary.timeout
        + summary.forbidden
        + summary.rate_limited
    )
    return summary


def _status_from_message(message: str) -> int | None:
    match = _STATUS_PATTERN.search(message)
    if match is None:
        return None
    return int(match.group(1))


def is_recoverable_download_error(exc: BaseException) -> bool:
    """Return True when a download error should not abort the scan."""
    return isinstance(exc, (httpx.HTTPError, httpx.TimeoutException, DownloaderError))
