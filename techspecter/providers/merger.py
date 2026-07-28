"""Merge provider detection outputs."""

from __future__ import annotations

from collections import defaultdict

from techspecter.fingerprinting.models import (
    DetectionResult,
    SecurityFinding,
    Technology,
    TechnologyMatch,
)
from techspecter.providers.confidence import ProviderConfidenceEngine
from techspecter.providers.models import ProviderDetectionResult, ProviderMatch
from techspecter.providers.version_resolver import ProviderVersionResolver


class ProviderMerger:
    """Merge normalized provider results into a unified DetectionResult."""

    def __init__(
        self,
        *,
        version_resolver: ProviderVersionResolver | None = None,
        confidence_engine: ProviderConfidenceEngine | None = None,
    ) -> None:
        """Initialize merger with injectable engines."""
        self._version_resolver = version_resolver or ProviderVersionResolver()
        self._confidence_engine = confidence_engine or ProviderConfidenceEngine()

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
        for result in results:
            if not result.success:
                continue
            for match in result.matches:
                grouped[match.technology_id].append(match)

        merged_matches: list[TechnologyMatch] = []
        for tech_id, provider_matches in grouped.items():
            merged_matches.append(self._merge_technology(tech_id, provider_matches))

        merged_matches.sort(key=lambda item: (-item.confidence, item.technology.name.lower()))
        return DetectionResult(
            target_url=target_url,
            matches=merged_matches,
            scripts_analyzed=scripts_analyzed,
            elapsed_ms=elapsed_ms,
        )

    def _merge_technology(
        self,
        tech_id: str,
        matches: list[ProviderMatch],
    ) -> TechnologyMatch:
        """Merge all provider matches for one technology."""
        primary = self._select_primary_match(matches)
        providers = sorted({match.provider for match in matches})
        detection_methods = sorted({match.detection_method for match in matches})
        evidence = self._merge_evidence(matches)
        categories = sorted({match.category for match in matches if match.category})
        category = (
            primary.category
            if primary.category != "unknown"
            else (categories[0] if categories else "unknown")
        )

        version_outcome = self._version_resolver.resolve(matches)
        confidence = self._confidence_engine.calculate(matches, provider_count=len(providers))

        security_findings = self._merge_security_findings(matches)
        provider_details: dict[str, object] = {}
        for match in matches:
            if match.metadata:
                provider_details[match.provider] = match.metadata
        provider_metadata: dict[str, object] = {
            "providers": providers,
            "version_source_provider": version_outcome.source_provider,
            "version_reason": version_outcome.reason,
            "version_conflict": version_outcome.conflict,
            "provider_details": provider_details,
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
            matched_patterns=evidence[:20],
            detection_reason="; ".join(evidence[:5]) if evidence else None,
            version_source=version_outcome.source_provider,
            version_reason=version_outcome.reason,
            version_confidence=version_outcome.confidence,
            evidence_count=len(evidence),
            evidence_sources=detection_methods,
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

    def _merge_evidence(self, matches: list[ProviderMatch]) -> list[str]:
        """Merge unique evidence strings from all providers."""
        seen: set[str] = set()
        merged: list[str] = []
        for match in matches:
            for item in match.evidence:
                if item in seen:
                    continue
                seen.add(item)
                merged.append(item)
        return merged

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
