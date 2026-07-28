"""Comparison engine for TechSpecter vs Wappalyzer results."""

from __future__ import annotations

from techspecter.benchmark.models import (
    UNKNOWN_VERSION,
    NormalizedScanResult,
    NormalizedTechnology,
    TechnologyComparison,
    VersionComparison,
)
from techspecter.benchmark.utils import categories_match


class ComparisonEngine:
    """Compare normalized scan results from TechSpecter and Wappalyzer."""

    def compare(
        self,
        techspecter: NormalizedScanResult,
        wappalyzer: NormalizedScanResult,
    ) -> tuple[list[TechnologyComparison], list[TechnologyComparison], list[TechnologyComparison]]:
        """Compare two normalized scan results.

        Returns:
            Tuple of (matched, techspecter_only, wappalyzer_only) comparisons.
        """
        ts_map = {tech.id: tech for tech in techspecter.technologies}
        wap_map = {tech.id: tech for tech in wappalyzer.technologies}
        all_ids = sorted(set(ts_map) | set(wap_map))

        matched: list[TechnologyComparison] = []
        ts_only: list[TechnologyComparison] = []
        wap_only: list[TechnologyComparison] = []

        for tech_id in all_ids:
            ts_tech = ts_map.get(tech_id)
            wap_tech = wap_map.get(tech_id)
            if ts_tech is not None and wap_tech is not None:
                matched.append(self._build_comparison(tech_id, ts_tech, wap_tech, "both"))
            elif ts_tech is not None:
                ts_only.append(
                    self._build_comparison(tech_id, ts_tech, None, "techspecter_only"),
                )
            else:
                wap_only.append(
                    self._build_comparison(tech_id, None, wap_tech, "wappalyzer_only"),
                )

        return matched, ts_only, wap_only

    def compare_versions(
        self,
        matched: list[TechnologyComparison],
    ) -> list[VersionComparison]:
        """Build version comparisons for technologies detected by both engines."""
        comparisons: list[VersionComparison] = []
        for item in matched:
            if item.techspecter is None or item.wappalyzer is None:
                continue
            version_cmp = self._compare_versions(
                technology_id=item.technology_id,
                technology_name=item.technology_name,
                techspecter=item.techspecter,
                wappalyzer=item.wappalyzer,
            )
            item.version_comparison = version_cmp
            comparisons.append(version_cmp)
        return comparisons

    def _build_comparison(
        self,
        technology_id: str,
        techspecter: NormalizedTechnology | None,
        wappalyzer: NormalizedTechnology | None,
        detected_by: str,
    ) -> TechnologyComparison:
        """Build a technology comparison record."""
        ref = techspecter if techspecter is not None else wappalyzer
        name = ref.name if ref is not None else technology_id
        category = (
            techspecter.category
            if techspecter is not None
            else (wappalyzer.category if wappalyzer is not None else "unknown")
        )
        confidence_delta = None
        category_match = None
        if techspecter is not None and wappalyzer is not None:
            if techspecter.confidence is not None and wappalyzer.confidence is not None:
                confidence_delta = round(techspecter.confidence - wappalyzer.confidence, 1)
            category_match = categories_match(techspecter.category, wappalyzer.category)

        return TechnologyComparison(
            technology_id=technology_id,
            technology_name=name,
            category=category,
            detected_by=detected_by,  # type: ignore[arg-type]
            techspecter=techspecter,
            wappalyzer=wappalyzer,
            confidence_delta=confidence_delta,
            category_match=category_match,
        )

    def _compare_versions(
        self,
        *,
        technology_id: str,
        technology_name: str,
        techspecter: NormalizedTechnology,
        wappalyzer: NormalizedTechnology,
    ) -> VersionComparison:
        """Compare versions for a matched technology."""
        ts_version = techspecter.version or UNKNOWN_VERSION
        wap_version = wappalyzer.version or UNKNOWN_VERSION
        ts_unknown = ts_version == UNKNOWN_VERSION
        wap_unknown = wap_version == UNKNOWN_VERSION

        if ts_unknown and wap_unknown:
            return VersionComparison(
                technology_id=technology_id,
                technology_name=technology_name,
                techspecter_version=ts_version,
                wappalyzer_version=wap_version,
                status="both_unknown",
                reason="Neither engine resolved a version",
                suggested_improvement=f"Add version extractors for {technology_name}",
            )

        if ts_unknown and not wap_unknown:
            reason = self._unknown_version_reason(techspecter)
            return VersionComparison(
                technology_id=technology_id,
                technology_name=technology_name,
                techspecter_version=ts_version,
                wappalyzer_version=wap_version,
                status="unknown_techspecter",
                reason=reason,
                suggested_improvement=f"Improve {technology_name} version extractor",
            )

        if wap_unknown and not ts_unknown:
            return VersionComparison(
                technology_id=technology_id,
                technology_name=technology_name,
                techspecter_version=ts_version,
                wappalyzer_version=wap_version,
                status="unknown_wappalyzer",
                reason="Wappalyzer did not resolve a version",
            )

        if ts_version == wap_version:
            return VersionComparison(
                technology_id=technology_id,
                technology_name=technology_name,
                techspecter_version=ts_version,
                wappalyzer_version=wap_version,
                status="match",
                reason="Versions agree",
            )

        return VersionComparison(
            technology_id=technology_id,
            technology_name=technology_name,
            techspecter_version=ts_version,
            wappalyzer_version=wap_version,
            status="different",
            reason=(f"Version mismatch: TechSpecter={ts_version}, Wappalyzer={wap_version}"),
            suggested_improvement=(
                f"Review {technology_name} version resolution and validate against "
                f"Wappalyzer reference {wap_version}"
            ),
        )

    def _unknown_version_reason(self, techspecter: NormalizedTechnology) -> str:
        """Infer why TechSpecter did not resolve a version."""
        metadata = techspecter.raw_metadata
        evidence_count = metadata.get("evidence_count", 0)
        version_source = metadata.get("version_source")
        if not evidence_count:
            return "No version candidate generated"
        if version_source in (None, "none", ""):
            return "Version candidates exist but none matched technology extractors"
        return "Version evidence present but resolution returned Unknown"
