"""Unified multi-provider detection service."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from techspecter.configuration.models import ProvidersConfig
from techspecter.crawler.discovery import DiscoveryPipeline
from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer
from techspecter.fingerprinting.models import FingerprintAnalysisResult
from techspecter.fingerprinting.rebuild import rebuild_fingerprint_analysis_models  # noqa: F401
from techspecter.providers.manager import ProviderManager
from techspecter.providers.merger import ProviderMerger
from techspecter.providers.models import (
    MergeSummary,
    ProviderDetectionResult,
    ProviderHealthStatus,
    ProviderTarget,
    UnifiedDetectionResult,
)
from techspecter.technology_intelligence.engine import TechnologyIntelligenceEngine

if TYPE_CHECKING:
    from techspecter.fingerprinting.evidence.models import EvidenceCollection

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class UnifiedDetectionService:
    """Orchestrate TechSpecter and additional passive detection providers."""

    discovery_pipeline: DiscoveryPipeline | None = None
    provider_manager: ProviderManager | None = None
    merger: ProviderMerger = field(default_factory=ProviderMerger)
    providers_config: ProvidersConfig = field(default_factory=ProvidersConfig)
    intelligence_engine: TechnologyIntelligenceEngine | None = None
    compatibility_layer: FingerprintCompatibilityLayer | None = None
    collect_evidence: bool = True

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
        provider_health = manager.last_health_report

        failed = [item.provider for item in provider_results if not item.success]
        merged = self.merger.merge(
            provider_results,
            target_url=target.url,
            scripts_analyzed=len(discovery.downloads) + len(discovery.inline_scripts),
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
        merge_summary = self.merger.last_merge_summary

        if failed:
            logger.info(
                "Providers skipped or failed",
                extra={"failed_providers": failed, "target_url": target.url},
            )

        unified = self.build_unified_result(
            provider_results,
            target_url=target.url,
            provider_health=provider_health,
            merge_summary=merge_summary,
        )

        evidence_collection: EvidenceCollection | None = None
        if self.collect_evidence:
            evidence_collection = self._compatibility().collect_evidence(discovery)

        intelligence = self._intelligence().build(
            discovery,
            merged,
            evidence_collection=evidence_collection,
        )

        return FingerprintAnalysisResult(
            target_url=target.url,
            discovery_elapsed_ms=discovery_elapsed_ms,
            detection=merged,
            elapsed_ms=merged.elapsed_ms,
            provider_diagnostics={
                "provider_health": [item.model_dump() for item in unified.provider_health],
                "failed_providers": unified.failed_providers,
                "merge_summary": merge_summary.model_dump() if merge_summary else {},
            },
            technology_intelligence=intelligence,
            asset_inventory=discovery.asset_inventory,
            sensitive_intelligence=discovery.sensitive_intelligence,
        )

    def build_unified_result(
        self,
        provider_results: list[ProviderDetectionResult],
        *,
        target_url: str,
        scripts_analyzed: int = 0,
        provider_health: list[ProviderHealthStatus] | None = None,
        merge_summary: MergeSummary | None = None,
    ) -> UnifiedDetectionResult:
        """Build unified metadata wrapper (for testing/extension)."""
        failed = [item.provider for item in provider_results if not item.success]
        elapsed = sum(item.elapsed_ms for item in provider_results)
        _ = scripts_analyzed
        return UnifiedDetectionResult(
            target_url=target_url,
            provider_results=provider_results,
            failed_providers=failed,
            provider_health=list(provider_health or []),
            merge_summary=merge_summary,
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

    def _intelligence(self) -> TechnologyIntelligenceEngine:
        """Return technology intelligence engine."""
        if self.intelligence_engine is None:
            self.intelligence_engine = TechnologyIntelligenceEngine()
        return self.intelligence_engine

    def _compatibility(self) -> FingerprintCompatibilityLayer:
        """Return fingerprint compatibility layer for evidence collection."""
        if self.compatibility_layer is None:
            self.compatibility_layer = FingerprintCompatibilityLayer()
        return self.compatibility_layer
