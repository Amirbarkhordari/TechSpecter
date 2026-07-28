"""Detection provider manager."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from techspecter.configuration.models import ProvidersConfig
from techspecter.providers.base import DetectionProvider
from techspecter.providers.models import ProviderDetectionResult, ProviderTarget
from techspecter.providers.retirejs_provider import RetireJsProvider
from techspecter.providers.techspecter_provider import TechSpecterProvider
from techspecter.providers.wappalyzer_provider import WappalyzerProvider

logger = logging.getLogger(__name__)

_ALL_PROVIDER_IDS: frozenset[str] = frozenset({"techspecter", "wappalyzer", "retirejs"})


@dataclass(slots=True)
class ProviderManager:
    """Execute all enabled passive detection providers."""

    config: ProvidersConfig = field(default_factory=ProvidersConfig)
    providers: dict[str, DetectionProvider] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Register default providers when none supplied."""
        if not self.providers:
            self.providers = {
                "techspecter": TechSpecterProvider(),
                "wappalyzer": WappalyzerProvider(),
                "retirejs": RetireJsProvider(),
            }

    def enabled_provider_ids(
        self,
        *,
        selected: list[str] | None = None,
        disabled: list[str] | None = None,
    ) -> list[str]:
        """Resolve which providers should run."""
        disabled_set = {item.lower() for item in (disabled or [])}
        if selected:
            normalized = []
            for item in selected:
                lowered = item.lower()
                if lowered == "all":
                    normalized.extend(sorted(_ALL_PROVIDER_IDS))
                    continue
                if lowered in _ALL_PROVIDER_IDS:
                    normalized.append(lowered)
            chosen = []
            seen: set[str] = set()
            for provider_id in normalized:
                if provider_id in seen:
                    continue
                seen.add(provider_id)
                if provider_id in disabled_set:
                    continue
                if self.config.is_provider_enabled(provider_id):
                    chosen.append(provider_id)
            return chosen

        return [
            provider_id
            for provider_id in ("techspecter", "wappalyzer", "retirejs")
            if provider_id not in disabled_set and self.config.is_provider_enabled(provider_id)
        ]

    def run_all(
        self,
        target: ProviderTarget,
        *,
        selected: list[str] | None = None,
        disabled: list[str] | None = None,
    ) -> list[ProviderDetectionResult]:
        """Execute enabled providers independently."""
        results: list[ProviderDetectionResult] = []
        for provider_id in self.enabled_provider_ids(selected=selected, disabled=disabled):
            provider = self.providers.get(provider_id)
            if provider is None:
                logger.warning("Unknown provider requested: %s", provider_id)
                continue
            if provider_id != "techspecter" and not provider.is_available():
                logger.info("Skipping unavailable provider: %s", provider_id)
                results.append(
                    ProviderDetectionResult(
                        provider=provider_id,
                        target_url=target.url,
                        success=False,
                        error=f"{provider.display_name} is not available",
                    ),
                )
                continue
            logger.info("Running provider: %s", provider_id)
            results.append(provider.detect(target))
        return results
