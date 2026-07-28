"""Wappalyzer passive detection provider."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.benchmark.wappalyzer import WappalyzerExecutor
from techspecter.providers.base import BaseDetectionProvider
from techspecter.providers.models import ProviderDetectionResult, ProviderTarget
from techspecter.providers.normalizer import ProviderNormalizer

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WappalyzerProvider(BaseDetectionProvider):
    """Run Wappalyzer as an additional passive detection provider."""

    provider_id: str = field(default="wappalyzer", init=False)
    display_name: str = field(default="Wappalyzer", init=False)
    executor: WappalyzerExecutor = field(default_factory=WappalyzerExecutor)
    normalizer: ProviderNormalizer = field(default_factory=ProviderNormalizer)
    timeout_seconds: int = 120

    def is_available(self) -> bool:
        """Return whether Wappalyzer CLI is available."""
        return self.executor.is_available()

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Execute Wappalyzer and normalize results."""
        started = time.perf_counter()
        if not self.is_available():
            return self._failure_result(
                target,
                error="Wappalyzer CLI is not available",
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )
        try:
            payload = self.executor.run(target.url, timeout_seconds=self.timeout_seconds)
            elapsed_ms = (time.perf_counter() - started) * 1000
            result = self.normalizer.from_wappalyzer(
                payload,
                target_url=target.url,
                elapsed_ms=elapsed_ms,
            )
            logger.info(
                "Wappalyzer provider detected %d technologies for %s",
                len(result.matches),
                target.url,
            )
            return result
        except Exception as exc:
            logger.warning("Wappalyzer provider failed for %s: %s", target.url, exc)
            return self._failure_result(
                target,
                error=str(exc),
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )
