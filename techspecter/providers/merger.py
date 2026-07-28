"""Merge provider detection outputs."""

from __future__ import annotations

import logging
from collections import defaultdict

from techspecter.fingerprinting.models import (
    DetectionResult,
    SecurityFinding,
    Technology,
    TechnologyMatch,
)
from techspecter.providers.confidence import ProviderConfidenceEngine
from techspecter.providers.evidence import ProviderEvidenceAggregator
from techspecter.providers.models import MergeSummary, ProviderDetectionResult, ProviderMatch
from techspecter.providers.version_resolver import ProviderVersionResolver

logger = logging.getLogger(__name__)


class ProviderMerger:
    """Merge normalized provider results into a unified DetectionResult."""

    def __init__(
        self,
        *,
        version_resolver: ProviderVersionResolver | None = None,
        confidence_engine: ProviderConfidenceEngine | None = None,
        evidence_aggregator: ProviderEvidenceAggregator | None = None,
    ) -> None:
        """Initialize merger with injectable engines."""
        self._version_resolver = version_resolver or ProviderVersionResolver()
        self._confidence_engine = confidence_engine or ProviderConfidenceEngine()
        self._evidence_aggregator = evidence_aggregator or ProviderEvidenceAggregator()

    def merge(
        self,
        results: list[ProviderDetectionResult],
        *,
        target_url: str,
        scripts_analyzed: int = 0,
        elapsed_ms: float = 0.0,
    ) -> DetectionResult:
        """Merge provider outputs into one DetectionResult."""
        grouped: dict[str, list[ProviderMatch]] = defaultdict(list)
        succeeded = [item.provider for item in results if item.success]
        failed = [item.provider for item in results if not item.success]
        version_conflicts = 0

        for result in results:
            if not result.success:
                continue
            for match in result.matches:
                grouped[match.technology_id].append(match)

        merged_matches: list[TechnologyMatch] = []
        for tech_id, provider_matches in grouped.items():
            merged = self._merge_technology(tech_id, provider_matches)
            if merged.provider_metadata.get("version_conflict"):
                version_conflicts += 1
            merged_matches.append(merged)

        merged_matches.sort(key=lambda item: (-item.confidence, item.technology.name.lower()))

        evidence_total = sum(item.evidence_count for item in merged_matches)
        summary = MergeSummary(
            technologies_merged=len(merged_matches),
            providers_succeeded=succeeded,
            providers_failed=failed,
            evidence_items_total=evidence_total,
            version_conflicts=version_conflicts,
        )
        logger.info(
            "Provider merge summary",
            extra={
                "target_url": target_url,
                "technologies_merged": summary.technologies_merged,
                "providers_succeeded": summary.providers_succeeded,
                "providers_failed": summary.providers_failed,
                "evidence_items_total": summary.evidence_items_total,
                "version_conflicts": summary.version_conflicts,
            },
        )
        self._last_merge_summary = summary

        return DetectionResult(
            target_url=target_url,
            matches=merged_matches,
            scripts_analyzed=scripts_analyzed,
            elapsed_ms=elapsed_ms,
        )

    @property
    def last_merge_summary(self) -> MergeSummary | None:
        """Return summary from the most recent merge operation."""
        return getattr(self, "_last_merge_summary", None)

    def _merge_technology(
        self,
        tech_id: str,
        matches: list[ProviderMatch],
    ) -> TechnologyMatch:
        """Merge all provider matches for one technology."""
        primary = self._select_primary_match(matches)
        providers = sorted({match.provider for match in matches})
        detection_methods = sorted({match.detection_method for match in matches})
        evidence_strings, structured_evidence = self._evidence_aggregator.aggregate(matches)
        categories = sorted({match.category for match in matches if match.category})
        category = (
            primary.category
            if primary.category != "unknown"
            else (categories[0] if categories else "unknown")
        )

        version_outcome = self._version_resolver.resolve(matches)
        confidence_breakdown = self._confidence_engine.calculate_with_breakdown(
            matches,
            provider_count=len(providers),
        )
        confidence = confidence_breakdown.final

        security_findings = self._merge_security_findings(matches)
        provider_details: dict[str, object] = {}
        version_metadata_by_provider: dict[str, object] = {}
        for match in matches:
            if match.metadata:
                provider_details[match.provider] = match.metadata
            if match.version_metadata is not None:
                version_metadata_by_provider[match.provider] = match.version_metadata.model_dump()

        provider_metadata: dict[str, object] = {
            "providers": providers,
            "version_source_provider": version_outcome.source_provider,
            "version_reason": version_outcome.reason,
            "version_conflict": version_outcome.conflict,
            "provider_details": provider_details,
            "version_metadata_by_provider": version_metadata_by_provider,
        }
        if version_outcome.rejected_versions:
            provider_metadata["rejected_versions"] = list(version_outcome.rejected_versions)

        return TechnologyMatch(
            technology=Technology(
                id=tech_id,
                name=primary.name,
                category=category,
            ),
            version=version_outcome.version,
            confidence=confidence,
            matched_patterns=evidence_strings[:20],
            detection_reason="; ".join(evidence_strings[:5]) if evidence_strings else None,
            version_source=version_outcome.source_provider,
            version_reason=version_outcome.reason,
            version_confidence=version_outcome.confidence,
            evidence_count=len(evidence_strings),
            evidence_sources=detection_methods,
            evidence=structured_evidence[:20],
            confidence_breakdown={
                "provider_agreement": confidence_breakdown.provider_agreement,
                "base_confidence": confidence_breakdown.base_confidence,
                "evidence_bonus": confidence_breakdown.evidence_bonus,
                "quality_bonus": confidence_breakdown.quality_bonus,
                "final": confidence_breakdown.final,
            },
            providers=providers,
            detection_methods=detection_methods,
            provider_metadata=provider_metadata,
            security_findings=security_findings,
            rejected_version_candidates=list(version_outcome.rejected_versions),
        )

    def _select_primary_match(self, matches: list[ProviderMatch]) -> ProviderMatch:
        """Select the primary match for naming (TechSpecter preferred)."""
        priority = {"techspecter": 0, "wappalyzer": 1, "retirejs": 2}
        return min(matches, key=lambda item: (priority.get(item.provider, 99), -item.confidence))

    def _merge_security_findings(
        self,
        matches: list[ProviderMatch],
    ) -> list[SecurityFinding]:
        """Merge Retire.js security findings."""
        seen: set[tuple[str, str, str]] = set()
        findings: list[SecurityFinding] = []
        for match in matches:
            for finding in match.security_findings:
                key = (finding.library, finding.installed_version, finding.severity or "")
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
        return findings
