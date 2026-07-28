"""Retire.js passive JavaScript library provider."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, cast

from techspecter.providers.base import BaseDetectionProvider
from techspecter.providers.models import ProviderDetectionResult, ProviderTarget
from techspecter.providers.normalizer import ProviderNormalizer
from techspecter.providers.retirejs import RetireJsExecutor

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RetireJsProvider(BaseDetectionProvider):
    """Run Retire.js for passive JavaScript library intelligence."""

    provider_id: str = field(default="retirejs", init=False)
    display_name: str = field(default="Retire.js", init=False)
    executor: RetireJsExecutor = field(default_factory=RetireJsExecutor)
    normalizer: ProviderNormalizer = field(default_factory=ProviderNormalizer)
    timeout_seconds: int = 120

    def is_available(self) -> bool:
        """Return whether Retire.js CLI is available."""
        return self.executor.is_available()

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Scan discovered JavaScript with Retire.js."""
        started = time.perf_counter()
        if not self.is_available():
            return self._failure_result(
                target,
                error="Retire.js CLI is not available",
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )

        try:
            urls, scripts = self._collect_scripts(target)
            payload: list[dict[str, object]] = []
            if urls:
                payload.extend(
                    self.executor.scan_urls(urls, timeout_seconds=self.timeout_seconds),
                )
            if scripts:
                payload.extend(
                    self.executor.scan_discovery_scripts(
                        scripts,
                        timeout_seconds=self.timeout_seconds,
                    ),
                )
            elapsed_ms = (time.perf_counter() - started) * 1000
            result = self.normalizer.from_retirejs(
                cast(list[dict[str, Any]], payload),
                target_url=target.url,
                elapsed_ms=elapsed_ms,
            )
            logger.info(
                "Retire.js provider detected %d libraries for %s",
                len(result.matches),
                target.url,
            )
            return result
        except Exception as exc:
            logger.warning("Retire.js provider failed for %s: %s", target.url, exc)
            return self._failure_result(
                target,
                error=str(exc),
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )

    def _collect_scripts(
        self,
        target: ProviderTarget,
    ) -> tuple[list[str], list[tuple[str, str]]]:
        """Collect script URLs and inline content from discovery."""
        urls: list[str] = []
        scripts: list[tuple[str, str]] = []
        if target.discovery is None:
            return urls, scripts

        from techspecter.models.discovery import DiscoveryResult

        if not isinstance(target.discovery, DiscoveryResult):
            return urls, scripts

        for download in target.discovery.downloads:
            if download.download_success and download.content:
                url = str(download.url)
                urls.append(url)
                scripts.append((download.filename or url, download.content))

        for inline in target.discovery.inline_scripts:
            scripts.append((f"inline-script-{inline.index}.js", inline.content))

        return urls, scripts
