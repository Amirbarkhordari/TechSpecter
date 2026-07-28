"""Retire.js passive JavaScript library provider."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from techspecter.providers.backends.retirejs import CliRetireJsBackend, RetireJsBackend
from techspecter.providers.base import BaseDetectionProvider
from techspecter.providers.external import ExternalProviderPolicy, ExternalProviderRunner
from techspecter.providers.models import ProviderDetectionResult, ProviderTarget
from techspecter.providers.normalizer import ProviderNormalizer

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RetireJsProvider(BaseDetectionProvider):
    """Run an optional Retire.js backend for passive JavaScript intelligence."""

    provider_id: str = field(default="retirejs", init=False)
    display_name: str = field(default="Retire.js", init=False)
    backend: RetireJsBackend = field(default_factory=CliRetireJsBackend)
    normalizer: ProviderNormalizer = field(default_factory=ProviderNormalizer)
    policy: ExternalProviderPolicy = field(default_factory=ExternalProviderPolicy)

    def is_available(self) -> bool:
        """Return whether the configured Retire.js backend is available."""
        try:
            return self.backend.is_available()
        except Exception as exc:
            logger.warning(
                "Retire.js availability check failed",
                extra={"provider_id": self.provider_id, "error": str(exc)},
            )
            return False

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Scan discovered JavaScript with the Retire.js backend."""
        started = time.perf_counter()
        if not self.is_available():
            logger.info(
                "Retire.js backend unavailable; skipping passive enrichment",
                extra={"provider_id": self.provider_id, "target_url": target.url},
            )
            return self._failure_result(
                target,
                error="Retire.js backend is not available (optional dependency)",
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )

        runner = ExternalProviderRunner(provider_id=self.provider_id, policy=self.policy)
        try:
            urls, scripts = self._collect_scripts(target)

            def _scan() -> list[dict[str, Any]]:
                payload: list[dict[str, Any]] = []
                if urls:
                    payload.extend(
                        self.backend.scan_urls(
                            urls,
                            timeout_seconds=self.policy.timeout_seconds,
                        ),
                    )
                if scripts:
                    payload.extend(
                        self.backend.scan_scripts(
                            scripts,
                            timeout_seconds=self.policy.timeout_seconds,
                        ),
                    )
                return payload

            payload = runner.run(
                _scan,
                target_url=target.url,
                operation_name="retirejs_scan",
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            result = self.normalizer.from_retirejs(
                payload,
                target_url=target.url,
                elapsed_ms=elapsed_ms,
            )
            logger.info(
                "Retire.js provider detected %d libraries",
                len(result.matches),
                extra={
                    "provider_id": self.provider_id,
                    "target_url": target.url,
                    "match_count": len(result.matches),
                },
            )
            return result
        except Exception as exc:
            logger.warning(
                "Retire.js provider failed; continuing with remaining providers",
                extra={
                    "provider_id": self.provider_id,
                    "target_url": target.url,
                    "error": str(exc),
                },
            )
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
