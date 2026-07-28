"""Gap analysis and actionable recommendations."""

from __future__ import annotations

from techspecter.benchmark.models import (
    GapRecommendation,
    TechnologyComparison,
    VersionComparison,
)


class GapAnalyzer:
    """Generate actionable recommendations from benchmark comparisons."""

    _CATEGORY_HINTS: dict[str, str] = {
        "javascript-frameworks": "Add runtime detector patterns for framework globals",
        "web-frameworks": "Add manifest and HTTP header detection rules",
        "cms": "Add HTTP header and HTML marker detection",
        "cdn": "Add script reference and HTTP header detection",
        "analytics": "Add script URL and inline configuration patterns",
        "security": "Add HTTP header detection rules",
        "build-tools": "Add bundle runtime and manifest parsing",
    }

    def analyze(
        self,
        *,
        wappalyzer_only: list[TechnologyComparison],
        techspecter_only: list[TechnologyComparison],
        version_comparisons: list[VersionComparison],
    ) -> list[GapRecommendation]:
        """Produce gap analysis recommendations."""
        recommendations: list[GapRecommendation] = []

        for item in wappalyzer_only:
            recommendations.extend(self._missing_detection_gaps(item))

        for item in techspecter_only:
            recommendations.append(
                GapRecommendation(
                    technology_id=item.technology_id,
                    technology_name=item.technology_name,
                    gap_type="extra_detection",
                    severity="medium",
                    reason=(f"TechSpecter detected {item.technology_name} but Wappalyzer did not"),
                    suggested_improvement=(
                        "Review detection rules for false positive risk and add negative "
                        "evidence if needed"
                    ),
                ),
            )

        for version in version_comparisons:
            if version.status == "unknown_techspecter":
                recommendations.append(
                    GapRecommendation(
                        technology_id=version.technology_id,
                        technology_name=version.technology_name,
                        gap_type="missing_version",
                        severity="high",
                        reason=version.reason or "TechSpecter version is Unknown",
                        suggested_improvement=(
                            version.suggested_improvement
                            or f"Improve {version.technology_name} version extractor"
                        ),
                    ),
                )
            elif version.status == "different":
                recommendations.append(
                    GapRecommendation(
                        technology_id=version.technology_id,
                        technology_name=version.technology_name,
                        gap_type="version_mismatch",
                        severity="high",
                        reason=version.reason or "Version mismatch",
                        suggested_improvement=(
                            version.suggested_improvement
                            or f"Validate {version.technology_name} version resolution"
                        ),
                    ),
                )

        return self._dedupe_recommendations(recommendations)

    def _missing_detection_gaps(
        self,
        item: TechnologyComparison,
    ) -> list[GapRecommendation]:
        """Recommend improvements for technologies Wappalyzer found but TechSpecter missed."""
        tech_name = item.technology_name
        category = item.category
        category_hint = self._CATEGORY_HINTS.get(category, "Add detection rules for this category")

        return [
            GapRecommendation(
                technology_id=item.technology_id,
                technology_name=tech_name,
                gap_type="missing_detection",
                severity="high",
                reason=f"Wappalyzer detected {tech_name}; TechSpecter did not",
                suggested_improvement=category_hint,
            ),
            GapRecommendation(
                technology_id=item.technology_id,
                technology_name=tech_name,
                gap_type="missing_evidence",
                severity="medium",
                reason="No correlated evidence collected for this technology",
                suggested_improvement=(
                    "Review runtime, package metadata, manifest parsing, source map analysis, "
                    "and banner extraction"
                ),
            ),
            GapRecommendation(
                technology_id=item.technology_id,
                technology_name=tech_name,
                gap_type="weak_correlation",
                severity="medium",
                reason="Missing cross-resource evidence correlation",
                suggested_improvement=(
                    "Correlate weak signals across HTML, JavaScript, headers, and manifests"
                ),
            ),
        ]

    def _dedupe_recommendations(
        self,
        recommendations: list[GapRecommendation],
    ) -> list[GapRecommendation]:
        """Remove duplicate recommendations."""
        seen: set[tuple[str, str]] = set()
        unique: list[GapRecommendation] = []
        for item in recommendations:
            key = (item.technology_id, item.gap_type)
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique
