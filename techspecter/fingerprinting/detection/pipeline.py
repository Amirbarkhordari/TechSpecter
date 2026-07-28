"""Evidence-based detection pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.conflict import ConflictResolver
from techspecter.fingerprinting.detection.explain import build_detection_result, build_matches
from techspecter.fingerprinting.detection.filters import FalsePositiveReducer
from techspecter.fingerprinting.detection.models import (
    ExplainableDetectionResult,
    TechnologyEvaluation,
)
from techspecter.fingerprinting.detection.normalizer import normalize_evidence
from techspecter.fingerprinting.detection.rules import RuleEvaluator
from techspecter.fingerprinting.detection.scoring import ConfidenceEngine, ScoringEngine
from techspecter.fingerprinting.detection.version_resolver import VersionResolutionEngine
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

        confidence_engine = self.confidence_engine or ConfidenceEngine(weights=self.weights)
        scoring_map = {}
        for evaluation in accepted:
            breakdown = confidence_engine.calculate(evaluation)
            scoring_map[evaluation.signature.id] = breakdown

        version_engine = self.version_engine or VersionResolutionEngine(weights=self.weights)
        version_map = {}
        for evaluation in accepted:
            tech_id = evaluation.signature.id
            if scoring_map.get(tech_id) is None or scoring_map[tech_id].final_confidence <= 0:
                continue
            version_map[tech_id] = version_engine.resolve(
                evaluation.signature,
                evidence_items=collection.items,
                matched_rules=evaluation.matched_rules,
            )

        matches = build_matches(accepted, scoring_map, version_map)
        signature_lookup = {signature.id: signature for signature in signatures}
        final_matches = self.conflict_resolver.resolve(matches, signature_lookup)

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
