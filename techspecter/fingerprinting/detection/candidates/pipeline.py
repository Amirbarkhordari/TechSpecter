"""Evidence-driven candidate detection pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.candidates.generator import CandidateGenerator
from techspecter.fingerprinting.detection.candidates.indexer import EvidenceIndexer
from techspecter.fingerprinting.detection.candidates.models import TechnologyCandidate
from techspecter.fingerprinting.detection.candidates.validator import CandidateValidator
from techspecter.fingerprinting.detection.merger import TechnologyMerger
from techspecter.fingerprinting.evidence.models import EvidenceCollection
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch

logger = logging.getLogger(__name__)


@dataclass
class CandidateDetectionPipeline:
    """Index evidence, generate candidates, and confirm strong matches."""

    indexer: EvidenceIndexer = field(default_factory=EvidenceIndexer)
    generator: CandidateGenerator = field(default_factory=CandidateGenerator)
    validator: CandidateValidator = field(default_factory=CandidateValidator)
    merger: TechnologyMerger = field(default_factory=TechnologyMerger)

    def detect(self, collection: EvidenceCollection) -> DetectionResult:
        """Run candidate discovery and return confirmed technology matches only."""
        started = time.perf_counter()
        index = self.indexer.index(collection)
        candidates = self.generator.generate(index)
        confirmed, rejected = self.validator.validate(candidates)
        merged = self.merger.merge_matches(confirmed)
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Candidate detection for %s: %d candidates -> %d confirmed "
            "(%d rejected) in %.2f ms",
            collection.target_url,
            len(candidates),
            len(merged),
            len(rejected),
            elapsed_ms,
        )
        return DetectionResult(
            target_url=collection.target_url,
            matches=merged,
            ignored_matches=[],
            scripts_analyzed=0,
            elapsed_ms=elapsed_ms,
        )

    def generate_candidates(
        self,
        collection: EvidenceCollection,
    ) -> list[TechnologyCandidate]:
        """Expose candidate generation for testing and diagnostics."""
        return self.generator.generate(self.indexer.index(collection))

    def validate_candidates(
        self,
        candidates: list[TechnologyCandidate],
    ) -> tuple[list[TechnologyMatch], list[TechnologyCandidate]]:
        """Expose validation for testing and diagnostics."""
        return self.validator.validate(candidates)
