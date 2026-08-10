"""Backward compatibility between evidence and detection pipelines."""

from __future__ import annotations

import logging

from techspecter.fingerprinting.detection.candidates import CandidateDetectionPipeline
from techspecter.fingerprinting.detection.models import ExplainableDetectionResult
from techspecter.fingerprinting.detection.pipeline import EvidenceDetectionPipeline
from techspecter.fingerprinting.evidence.models import EvidenceCollection
from techspecter.fingerprinting.models import DetectionResult
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.fingerprinting.pipeline.evidence_pipeline import EvidencePipeline
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


class FingerprintCompatibilityLayer:
    """Bridge legacy detection with evidence collection and explainable detection."""

    def __init__(
        self,
        *,
        detection_pipeline: FingerprintPipeline | None = None,
        evidence_pipeline: EvidencePipeline | None = None,
        evidence_detection_pipeline: EvidenceDetectionPipeline | None = None,
        candidate_pipeline: CandidateDetectionPipeline | None = None,
    ) -> None:
        """Initialize compatibility layer with injectable pipelines."""
        self._detection_pipeline = detection_pipeline or FingerprintPipeline()
        self._evidence_pipeline = evidence_pipeline or EvidencePipeline()
        self._evidence_detection_pipeline = (
            evidence_detection_pipeline or EvidenceDetectionPipeline()
        )
        self._candidate_pipeline = candidate_pipeline or CandidateDetectionPipeline()

    def detect(self, discovery: DiscoveryResult) -> DetectionResult:
        """Run legacy technology detection unchanged."""
        return self._detection_pipeline.run(discovery)

    def collect_evidence(self, discovery: DiscoveryResult) -> EvidenceCollection:
        """Run the evidence-only pipeline."""
        return self._evidence_pipeline.collect(discovery)

    def detect_from_evidence(self, collection: EvidenceCollection) -> ExplainableDetectionResult:
        """Run explainable evidence-based detection."""
        return self._evidence_detection_pipeline.detect(collection)

    def detect_candidates(self, collection: EvidenceCollection) -> DetectionResult:
        """Run evidence-driven candidate generation and validation."""
        return self._candidate_pipeline.detect(collection)

    def analyze(
        self,
        discovery: DiscoveryResult,
        *,
        use_evidence_detection: bool = True,
    ) -> tuple[DetectionResult, EvidenceCollection]:
        """Run detection and evidence collection."""
        evidence = self.collect_evidence(discovery)
        if use_evidence_detection:
            explainable = self.detect_from_evidence(evidence)
            detection = explainable.detection
        else:
            detection = self.detect(discovery)
        logger.debug(
            "Compatibility layer produced %d detections and %d evidence items for %s",
            len(detection.matches),
            evidence.summary.total_items,
            detection.target_url,
        )
        return detection, evidence

    def analyze_explainable(self, discovery: DiscoveryResult) -> ExplainableDetectionResult:
        """Collect evidence and run explainable detection."""
        evidence = self.collect_evidence(discovery)
        return self.detect_from_evidence(evidence)
