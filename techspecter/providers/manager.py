"""Detection provider manager."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from techspecter.configuration.models import ProvidersConfig
from techspecter.providers.base import DetectionProvider
from techspecter.providers.external import ExternalProviderPolicy
from techspecter.providers.health import format_health_report, log_health_report
from techspecter.providers.models import (
    ProviderDetectionResult,
    ProviderHealthStatus,
    ProviderTarget,
)
from techspecter.providers.retirejs_provider import RetireJsProvider
from techspecter.providers.techspecter_provider import TechSpecterProvider
from techspecter.providers.wappalyzer_provider import WappalyzerProvider

logger = logging.getLogger(__name__)

_ALL_PROVIDER_IDS: frozenset[str] = frozenset({"techspecter", "wappalyzer", "retirejs"})


def _build_default_providers(config: ProvidersConfig) -> dict[str, DetectionProvider]:
    """Register built-in providers with configured external policies."""
    return {
        "techspecter": TechSpecterProvider(),
        "wappalyzer": WappalyzerProvider(
            policy=ExternalProviderPolicy.from_config(config.wappalyzer),
        ),
        "retirejs": RetireJsProvider(
            policy=ExternalProviderPolicy.from_config(config.retirejs),
        ),
    }


@dataclass(slots=True)
class ProviderManager:
    """Execute all enabled passive detection providers."""

    config: ProvidersConfig = field(default_factory=ProvidersConfig)
    providers: dict[str, DetectionProvider] = field(default_factory=dict)
    _last_health_report: list[ProviderHealthStatus] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        """Register default providers when none supplied."""
        if not self.providers:
            self.providers = _build_default_providers(self.config)

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

    def check_health_all(
        self,
        *,
        selected: list[str] | None = None,
        disabled: list[str] | None = None,
    ) -> list[ProviderHealthStatus]:
        """Run health checks for enabled providers."""
        statuses: list[ProviderHealthStatus] = []
        for provider_id in self.enabled_provider_ids(selected=selected, disabled=disabled):
            provider = self.providers.get(provider_id)
            if provider is None:
                continue
            statuses.append(provider.check_health())
        self._last_health_report = statuses
        log_health_report(statuses)
        logger.debug("Provider health report:\n%s", format_health_report(statuses))
        return statuses

    @property
    def last_health_report(self) -> list[ProviderHealthStatus]:
        """Return health statuses from the most recent check."""
        return list(self._last_health_report)

    def run_all(
        self,
        target: ProviderTarget,
        *,
        selected: list[str] | None = None,
        disabled: list[str] | None = None,
    ) -> list[ProviderDetectionResult]:
        """Execute enabled providers independently; never stop on provider failure."""
        self.check_health_all(selected=selected, disabled=disabled)
        results: list[ProviderDetectionResult] = []
        for provider_id in self.enabled_provider_ids(selected=selected, disabled=disabled):
            provider = self.providers.get(provider_id)
            if provider is None:
                logger.warning(
                    "Unknown provider requested",
                    extra={"provider_id": provider_id, "target_url": target.url},
                )
                continue
            logger.info(
                "Running provider",
                extra={"provider_id": provider_id, "target_url": target.url},
            )
            try:
                result = provider.detect(target)
            except Exception as exc:
                logger.exception(
                    "Provider raised unexpected error; continuing with remaining providers",
                    extra={
                        "provider_id": provider_id,
                        "target_url": target.url,
                        "error": str(exc),
                    },
                )
                result = ProviderDetectionResult(
                    provider=provider_id,
                    target_url=target.url,
                    success=False,
                    error=str(exc),
                )
            results.append(result)
        return results
