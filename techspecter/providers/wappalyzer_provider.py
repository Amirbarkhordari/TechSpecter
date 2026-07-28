"""Wappalyzer passive detection provider."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from techspecter.providers.backends.wappalyzer import CliWappalyzerBackend, WappalyzerBackend
from techspecter.providers.base import BaseDetectionProvider
from techspecter.providers.external import ExternalProviderPolicy
from techspecter.providers.lifecycle import ExternalProviderLifecycle
from techspecter.providers.models import (
    ProviderDetectionResult,
    ProviderHealthStatus,
    ProviderTarget,
)
from techspecter.providers.normalizer import ProviderNormalizer
from techspecter.providers.validation import ProviderOutputValidator

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WappalyzerProvider(BaseDetectionProvider):
    """Run an optional Wappalyzer backend as a passive detection provider."""

    provider_id: str = field(default="wappalyzer", init=False)
    display_name: str = field(default="Wappalyzer", init=False)
    backend: WappalyzerBackend = field(default_factory=CliWappalyzerBackend)
    normalizer: ProviderNormalizer = field(default_factory=ProviderNormalizer)
    policy: ExternalProviderPolicy = field(default_factory=ExternalProviderPolicy)
    validator: ProviderOutputValidator = field(default_factory=ProviderOutputValidator)

    def __post_init__(self) -> None:
        self._lifecycle = ExternalProviderLifecycle(
            provider_id=self.provider_id,
            display_name=self.display_name,
            policy=self.policy,
            validator=self.validator,
        )

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

    def check_health(self) -> ProviderHealthStatus:
        """Return Wappalyzer health with selected backend details."""
        return self._lifecycle.check_health(
            is_available=self.backend.is_available,
            backend_id=self.backend.backend_id(),
            backend_version=self.backend.backend_version,
            unavailable_reason=self.backend.unavailable_reason(),
        )

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Execute the Wappalyzer backend lifecycle."""
        health = self.check_health()

        def _normalize(payload: Any, elapsed_ms: float) -> ProviderDetectionResult:
            return self.normalizer.from_wappalyzer(
                payload,
                target_url=target.url,
                elapsed_ms=elapsed_ms,
            )

        return self._lifecycle.execute(
            target,
            health=health,
            operation=lambda: self.backend.detect(
                target.url,
                timeout_seconds=self.policy.timeout_seconds,
            ),
            normalize=_normalize,
            validate_raw=self.validator.validate_wappalyzer_payload,
            operation_name="wappalyzer_detect",
        )
