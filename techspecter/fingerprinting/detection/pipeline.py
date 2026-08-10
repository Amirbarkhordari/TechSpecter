"""Evidence-based detection pipeline.

Evaluates technology signatures from the knowledge catalog against collected
evidence. Signatures provide detection rules; a technology appears in output
only when evidence satisfies those rules — never from catalog membership alone.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.conflict import ConflictResolver
from techspecter.fingerprinting.detection.explain import build_detection_result
from techspecter.fingerprinting.detection.filters import FalsePositiveReducer
from techspecter.fingerprinting.detection.merger import TechnologyMerger
from techspecter.fingerprinting.detection.models import (
    ExplainableDetectionResult,
    ScoringBreakdown,
    TechnologyEvaluation,
    VersionResolution,
)
from techspecter.fingerprinting.detection.normalizer import normalize_evidence
from techspecter.fingerprinting.detection.rules import RuleEvaluator
from techspecter.fingerprinting.detection.scoring import ConfidenceEngine, ScoringEngine
from techspecter.fingerprinting.detection.version_resolver import (
    VersionResolutionEngine,
    resolve_cross_file_versions,
)
from techspecter.fingerprinting.detection.weights import ScoringWeights
from techspecter.fingerprinting.evidence.models import EvidenceCollection
from techspecter.fingerprinting.signatures.registry import SignatureRegistry, signature_registry

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EvidenceDetectionPipeline:
    """Multi-stage explainable detection pipeline."""

    registry: SignatureRegistry = field(default_factory=lambda: signature_registry)
    weights: ScoringWeights = field(default_factory=ScoringWeights)
    rule_evaluator: RuleEvaluator = field(default_factory=RuleEvaluator)
    false_positive_reducer: FalsePositiveReducer | None = None
    scoring_engine: ScoringEngine | None = None
    confidence_engine: ConfidenceEngine | None = None
    version_engine: VersionResolutionEngine | None = None
    conflict_resolver: ConflictResolver = field(default_factory=ConflictResolver)
    merger: TechnologyMerger = field(default_factory=TechnologyMerger)

    def __post_init__(self) -> None:
        """Initialize dependent engines."""
        if self.false_positive_reducer is None:
            self.false_positive_reducer = FalsePositiveReducer(weights=self.weights)
        if self.scoring_engine is None:
            self.scoring_engine = ScoringEngine(weights=self.weights)
        if self.confidence_engine is None:
            self.confidence_engine = ConfidenceEngine(
                weights=self.weights, scorer=self.scoring_engine
            )
        if self.version_engine is None:
            self.version_engine = VersionResolutionEngine(weights=self.weights)

    def detect(self, collection: EvidenceCollection) -> ExplainableDetectionResult:
        """Run the full detection pipeline against collected evidence."""
        started = time.perf_counter()
        normalized = normalize_evidence(collection, weights=self.weights)
        signatures = self.registry.resolve()

        evaluations: list[TechnologyEvaluation] = []
        for signature in signatures:
            evaluation = self.rule_evaluator.evaluate(signature, normalized)
            evaluations.append(evaluation)

        reducer = self.false_positive_reducer or FalsePositiveReducer(weights=self.weights)
        accepted = reducer.filter_evaluations(evaluations)

        version_engine = self.version_engine or VersionResolutionEngine(weights=self.weights)
        version_map: dict[str, VersionResolution] = {}
        for evaluation in accepted:
            tech_id = evaluation.signature.id
            version_map[tech_id] = version_engine.resolve(
                evaluation.signature,
                evidence_items=collection.items,
                matched_rules=evaluation.matched_rules,
            )
        version_map = resolve_cross_file_versions(version_map)

        confidence_engine = self.confidence_engine or ConfidenceEngine(weights=self.weights)
        scoring_map: dict[str, ScoringBreakdown] = {}
        for evaluation in accepted:
            tech_id = evaluation.signature.id
            version = version_map.get(tech_id)
            if version is None:
                continue
            breakdown = confidence_engine.calculate(evaluation, version=version)
            scoring_map[tech_id] = breakdown

        merged_evaluations = self.merger.merge_evaluations(accepted)
        matches = self.merger.build_merged_matches(merged_evaluations, scoring_map, version_map)
        signature_lookup = {signature.id: signature for signature in signatures}
        final_matches = self.conflict_resolver.resolve(matches, signature_lookup)
        final_matches = self.merger.merge_matches(final_matches)

        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Evidence detection for %s produced %d technologies (%.2f ms)",
            collection.target_url,
            len(final_matches),
            elapsed_ms,
        )
        return build_detection_result(
            target_url=collection.target_url,
            matches=final_matches,
            elapsed_ms=elapsed_ms,
            evaluations={item.signature.id: item for item in evaluations if not item.rejected},
            scoring=scoring_map,
            version_resolutions=version_map,
        )


ExplainableDetectionPipeline = EvidenceDetectionPipeline
