"""Wappalyzer passive detection provider."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.providers.backends.wappalyzer import CliWappalyzerBackend, WappalyzerBackend
from techspecter.providers.base import BaseDetectionProvider
from techspecter.providers.external import ExternalProviderPolicy, ExternalProviderRunner
from techspecter.providers.models import ProviderDetectionResult, ProviderTarget
from techspecter.providers.normalizer import ProviderNormalizer

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WappalyzerProvider(BaseDetectionProvider):
    """Run an optional Wappalyzer backend as a passive detection provider."""

    provider_id: str = field(default="wappalyzer", init=False)
    display_name: str = field(default="Wappalyzer", init=False)
    backend: WappalyzerBackend = field(default_factory=CliWappalyzerBackend)
    normalizer: ProviderNormalizer = field(default_factory=ProviderNormalizer)
    policy: ExternalProviderPolicy = field(default_factory=ExternalProviderPolicy)

    def is_available(self) -> bool:
        """Return whether the configured Wappalyzer backend is available."""
        try:
            return self.backend.is_available()
        except Exception as exc:
            logger.warning(
                "Wappalyzer availability check failed",
                extra={"provider_id": self.provider_id, "error": str(exc)},
            )
            return False

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Execute the Wappalyzer backend and normalize results."""
        started = time.perf_counter()
        if not self.is_available():
            logger.info(
                "Wappalyzer backend unavailable; skipping passive enrichment",
                extra={"provider_id": self.provider_id, "target_url": target.url},
            )
            return self._failure_result(
                target,
                error="Wappalyzer backend is not available (optional dependency)",
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )

        runner = ExternalProviderRunner(provider_id=self.provider_id, policy=self.policy)
        try:
            payload = runner.run(
                lambda: self.backend.detect(
                    target.url,
                    timeout_seconds=self.policy.timeout_seconds,
                ),
                target_url=target.url,
                operation_name="wappalyzer_detect",
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            result = self.normalizer.from_wappalyzer(
                payload,
                target_url=target.url,
                elapsed_ms=elapsed_ms,
            )
            logger.info(
                "Wappalyzer provider detected %d technologies",
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
                "Wappalyzer provider failed; continuing with remaining providers",
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
