"""TechSpecter primary detection provider."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.providers.base import BaseDetectionProvider
from techspecter.providers.models import ProviderDetectionResult, ProviderTarget
from techspecter.providers.normalizer import ProviderNormalizer

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TechSpecterProvider(BaseDetectionProvider):
    """Wrap the existing TechSpecter fingerprint engine."""

    provider_id: str = field(default="techspecter", init=False)
    display_name: str = field(default="TechSpecter", init=False)
    pipeline: FingerprintPipeline | None = None
    normalizer: ProviderNormalizer = field(default_factory=ProviderNormalizer)

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Run TechSpecter fingerprint detection."""
        started = time.perf_counter()
        if target.discovery is None:
            return self._failure_result(target, error="Discovery result required for TechSpecter")

        from techspecter.models.discovery import DiscoveryResult

        if not isinstance(target.discovery, DiscoveryResult):
            return self._failure_result(target, error="Invalid discovery result type")

        try:
            pipeline = self.pipeline or FingerprintPipeline()
            detection = pipeline.run(target.discovery)
            result = self.normalizer.from_techspecter(detection)
            result.elapsed_ms = (time.perf_counter() - started) * 1000
            logger.info(
                "TechSpecter provider detected %d technologies for %s",
                len(result.matches),
                target.url,
            )
            return result
        except Exception as exc:
            logger.exception("TechSpecter provider failed for %s", target.url)
            return self._failure_result(
                target,
                error=str(exc),
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )
