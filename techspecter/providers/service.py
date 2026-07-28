"""Unified multi-provider detection service."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.configuration.models import ProvidersConfig
from techspecter.crawler.discovery import DiscoveryPipeline
from techspecter.fingerprinting.models import FingerprintAnalysisResult
from techspecter.providers.manager import ProviderManager
from techspecter.providers.merger import ProviderMerger
from techspecter.providers.models import ProviderTarget, UnifiedDetectionResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class UnifiedDetectionService:
    """Orchestrate TechSpecter and additional passive detection providers."""

    discovery_pipeline: DiscoveryPipeline | None = None
    provider_manager: ProviderManager | None = None
    merger: ProviderMerger = field(default_factory=ProviderMerger)
    providers_config: ProvidersConfig = field(default_factory=ProvidersConfig)

    async def analyze_url(
        self,
        target_url: str,
        *,
        selected_providers: list[str] | None = None,
        disabled_providers: list[str] | None = None,
    ) -> FingerprintAnalysisResult:
        """Discover, run all enabled providers, and return merged detection."""
        started = time.perf_counter()
        discovery_started = time.perf_counter()
        discovery = await self._discovery().run(target_url)
        discovery_elapsed_ms = (time.perf_counter() - discovery_started) * 1000

        target = ProviderTarget(url=str(discovery.target.url), discovery=discovery)
        manager = self._manager()
        provider_results = manager.run_all(
            target,
            selected=selected_providers,
            disabled=disabled_providers,
        )

        successful = [item for item in provider_results if item.success]
        failed = [item.provider for item in provider_results if not item.success]
        merged = self.merger.merge(
            successful,
            target_url=target.url,
            scripts_analyzed=len(discovery.downloads) + len(discovery.inline_scripts),
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )

        if failed:
            logger.info("Providers skipped or failed: %s", ", ".join(failed))

        return FingerprintAnalysisResult(
            target_url=target.url,
            discovery_elapsed_ms=discovery_elapsed_ms,
            detection=merged,
            elapsed_ms=merged.elapsed_ms,
        )

    def build_unified_result(
        self,
        provider_results: list[object],
        *,
        target_url: str,
        scripts_analyzed: int = 0,
    ) -> UnifiedDetectionResult:
        """Build unified metadata wrapper (for testing/extension)."""
        from techspecter.providers.models import ProviderDetectionResult

        typed = [item for item in provider_results if isinstance(item, ProviderDetectionResult)]
        failed = [item.provider for item in typed if not item.success]
        elapsed = sum(item.elapsed_ms for item in typed)
        return UnifiedDetectionResult(
            target_url=target_url,
            provider_results=typed,
            failed_providers=failed,
            elapsed_ms=elapsed,
        )

    def _discovery(self) -> DiscoveryPipeline:
        """Return discovery pipeline."""
        if self.discovery_pipeline is None:
            self.discovery_pipeline = DiscoveryPipeline()
        return self.discovery_pipeline

    def _manager(self) -> ProviderManager:
        """Return provider manager."""
        if self.provider_manager is None:
            self.provider_manager = ProviderManager(config=self.providers_config)
        return self.provider_manager
