"""Benchmark statistics calculation."""

from __future__ import annotations

from techspecter.benchmark.models import (
    BenchmarkStatistics,
    TechnologyComparison,
    VersionComparison,
)


class StatisticsCalculator:
    """Calculate precision, recall, and version metrics."""

    def calculate(
        self,
        *,
        matched: list[TechnologyComparison],
        techspecter_only: list[TechnologyComparison],
        wappalyzer_only: list[TechnologyComparison],
        version_comparisons: list[VersionComparison],
    ) -> BenchmarkStatistics:
        """Calculate benchmark statistics from comparison groups."""
        matched_count = len(matched)
        extra = len(techspecter_only)
        missing = len(wappalyzer_only)
        ts_total = matched_count + extra
        wap_total = matched_count + missing

        true_positives = matched_count
        false_positives = extra
        false_negatives = missing

        precision = true_positives / ts_total if ts_total else 0.0
        recall = true_positives / wap_total if wap_total else 0.0
        coverage = (matched_count / wap_total * 100.0) if wap_total else 0.0

        version_matches = sum(1 for item in version_comparisons if item.status == "match")
        version_total = len(version_comparisons)
        version_match_rate = version_matches / version_total if version_total else 0.0

        resolved = [
            item
            for item in version_comparisons
            if item.status in {"match", "different", "unknown_wappalyzer"}
        ]
        accurate = sum(
            1 for item in resolved if item.status == "match" or item.status == "unknown_wappalyzer"
        )
        version_accuracy = accurate / len(resolved) if resolved else 0.0

        return BenchmarkStatistics(
            technology_precision=round(precision, 4),
            technology_recall=round(recall, 4),
            version_match_rate=round(version_match_rate, 4),
            version_accuracy=round(version_accuracy, 4),
            coverage_percent=round(coverage, 2),
            extra_detections=extra,
            missing_detections=missing,
            false_positives=false_positives,
            false_negatives=false_negatives,
            matched_technologies=matched_count,
            techspecter_total=ts_total,
            wappalyzer_total=wap_total,
            version_comparisons=version_total,
            version_matches=version_matches,
        )
