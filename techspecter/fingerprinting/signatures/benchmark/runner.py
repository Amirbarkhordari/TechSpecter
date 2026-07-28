"""Benchmark runner for signature intelligence platform."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from techspecter.fingerprinting.detection.pipeline import EvidenceDetectionPipeline
from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceCollection,
    EvidenceSource,
    EvidenceType,
)
from techspecter.fingerprinting.signatures.benchmark.models import (
    BenchmarkMetrics,
    BenchmarkReport,
    BenchmarkSampleResult,
    CompetitorComparison,
)
from techspecter.fingerprinting.signatures.loader import TechnologySignatureLoader

logger = logging.getLogger(__name__)

REGRESSION_DATASET = Path(__file__).resolve().parent.parent / "regression" / "dataset.json"

# Static competitor baseline estimates for comparative reporting (technology detection only).
COMPETITOR_BASELINES: tuple[CompetitorComparison, ...] = (
    CompetitorComparison(
        name="Wappalyzer",
        precision=0.82,
        recall=0.78,
        coverage=3000,
        notes="Estimated baseline for technology identification coverage",
    ),
    CompetitorComparison(
        name="BuiltWith",
        precision=0.80,
        recall=0.75,
        coverage=2500,
        notes="Estimated baseline for hosted technology profiling",
    ),
    CompetitorComparison(
        name="WhatRuns",
        precision=0.78,
        recall=0.72,
        coverage=1800,
        notes="Estimated baseline for browser-extension detection",
    ),
    CompetitorComparison(
        name="FingerprintJS Pro",
        precision=0.85,
        recall=0.70,
        coverage=1200,
        notes="Technology detection subset only; excludes browser fingerprinting signals",
    ),
)


@dataclass(slots=True)
class BenchmarkRunner:
    """Run detection benchmarks against regression dataset."""

    pipeline: EvidenceDetectionPipeline = field(default_factory=EvidenceDetectionPipeline)
    loader: TechnologySignatureLoader = field(default_factory=TechnologySignatureLoader)
    dataset_path: Path = REGRESSION_DATASET

    def run(self) -> BenchmarkReport:
        """Execute benchmark and return report."""
        samples = self._load_dataset()
        results: list[BenchmarkSampleResult] = []
        tp = fp = fn = 0
        version_hits = 0
        version_total = 0
        explainability = 0.0

        for sample in samples:
            collection = self._build_collection(sample)
            detection = self.pipeline.detect(collection).detection
            detected_ids = {match.technology.id for match in detection.matches}
            expected_raw = sample.get("expected", [])
            expected = set(expected_raw) if isinstance(expected_raw, list) else set()
            sample_fp = detected_ids - expected
            sample_fn = expected - detected_ids
            tp += len(detected_ids & expected)
            fp += len(sample_fp)
            fn += len(sample_fn)

            version_map_raw = sample.get("versions", {})
            version_map = version_map_raw if isinstance(version_map_raw, dict) else {}
            version_results: dict[str, bool] = {}
            for match in detection.matches:
                if match.technology.id not in version_map:
                    continue
                version_total += 1
                expected_version = str(version_map[match.technology.id])
                hit = match.version == expected_version
                version_results[match.technology.id] = hit
                if hit:
                    version_hits += 1

            for match in detection.matches:
                if match.detection_reason and match.supporting_evidence_ids:
                    explainability += 1.0

            results.append(
                BenchmarkSampleResult(
                    sample_id=str(sample["id"]),
                    expected=tuple(sorted(expected)),
                    detected=tuple(sorted(detected_ids)),
                    false_positives=tuple(sorted(sample_fp)),
                    false_negatives=tuple(sorted(sample_fn)),
                    version_matches=version_results,
                ),
            )

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        version_accuracy = version_hits / max(version_total, 1)
        explainability_score = explainability / max(len(results), 1)

        metrics = BenchmarkMetrics(
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            version_accuracy=round(version_accuracy, 4),
            false_positives=fp,
            false_negatives=fn,
            true_positives=tp,
            coverage=len(self.loader.load_all()),
            explainability_score=round(explainability_score, 4),
        )
        return BenchmarkReport(
            metrics=metrics,
            samples=tuple(results),
            comparisons=COMPETITOR_BASELINES,
            signature_count=len(self.loader.load_all()),
            category_coverage=self.loader.categories(),
        )

    def _load_dataset(self) -> list[dict[str, object]]:
        """Load regression dataset JSON."""
        if not self.dataset_path.is_file():
            logger.warning("Regression dataset missing: %s", self.dataset_path)
            return []
        payload = json.loads(self.dataset_path.read_text(encoding="utf-8"))
        samples_raw = payload.get("samples", [])
        if not isinstance(samples_raw, list):
            return []
        return [item for item in samples_raw if isinstance(item, dict)]

    def _build_collection(self, sample: dict[str, object]) -> EvidenceCollection:
        """Build synthetic evidence collection from regression sample."""
        items: list[Evidence] = []
        timestamp = datetime.now(UTC)
        evidence_raw = sample.get("evidence", [])
        if not isinstance(evidence_raw, list):
            evidence_raw = []
        for raw in evidence_raw:
            if not isinstance(raw, dict):
                continue
            items.append(
                Evidence(
                    source=EvidenceSource(str(raw.get("source", "javascript"))),
                    evidence_type=EvidenceType(str(raw["type"])),
                    collector="regression",
                    matched_value=str(raw.get("value", "")),
                    file=str(raw.get("file", "app.js")),
                    url=str(raw.get("url", "https://example.com/app.js")),
                    metadata=dict(raw.get("metadata", {})),
                    timestamp=timestamp,
                ),
            )
        return EvidenceCollection(
            target_url=str(sample.get("url", "https://example.com/")),
            items=tuple(items),
        )
