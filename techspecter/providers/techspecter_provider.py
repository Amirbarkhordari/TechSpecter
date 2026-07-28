"""TechSpecter primary detection provider."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.providers.base import BaseDetectionProvider
from techspecter.providers.models import (
    ProviderDetectionResult,
    ProviderHealthState,
    ProviderHealthStatus,
    ProviderTarget,
)
from techspecter.providers.normalizer import ProviderNormalizer
from techspecter.providers.validation import ProviderOutputValidator

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TechSpecterProvider(BaseDetectionProvider):
    """Wrap the existing TechSpecter fingerprint engine."""

    provider_id: str = field(default="techspecter", init=False)
    display_name: str = field(default="TechSpecter", init=False)
    pipeline: FingerprintPipeline | None = None
    normalizer: ProviderNormalizer = field(default_factory=ProviderNormalizer)
    validator: ProviderOutputValidator = field(default_factory=ProviderOutputValidator)

    def check_health(self) -> ProviderHealthStatus:
        """TechSpecter engine is always available when discovery is present."""
        return ProviderHealthStatus(
            provider_id=self.provider_id,
            display_name=self.display_name,
            state=ProviderHealthState.AVAILABLE,
            backend_id="fingerprint-engine",
        )

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Run TechSpecter fingerprint detection."""
        started = time.perf_counter()
        health = self.check_health()
        if target.discovery is None:
            return self._failure_result(
                target,
                error="Discovery result required for TechSpecter",
                health=health,
            )

        from techspecter.models.discovery import DiscoveryResult

        if not isinstance(target.discovery, DiscoveryResult):
            return self._failure_result(
                target,
                error="Invalid discovery result type",
                health=health,
            )

        try:
            pipeline = self.pipeline or FingerprintPipeline()
            detection = pipeline.run(target.discovery)
            result = self.normalizer.from_techspecter(detection)
            validated = self.validator.validate_matches(result.matches, provider=self.provider_id)
            result = validated.apply_to_result(result)
            result.elapsed_ms = (time.perf_counter() - started) * 1000
            result.health = health
            result.backend_id = "fingerprint-engine"
            logger.info(
                "TechSpecter provider detected technologies",
                extra={
                    "provider_id": self.provider_id,
                    "target_url": target.url,
                    "match_count": len(result.matches),
                    "elapsed_ms": result.elapsed_ms,
                },
            )
            return result
        except Exception as exc:
            logger.exception("TechSpecter provider failed for %s", target.url)
            failed_health = health.model_copy(
                update={"state": ProviderHealthState.FAILED, "reason": str(exc)},
            )
            return self._failure_result(
                target,
                error=str(exc),
                elapsed_ms=(time.perf_counter() - started) * 1000,
                health=failed_health,
            )
