"""Backward compatibility between evidence and detection pipelines."""

from __future__ import annotations

import logging

from techspecter.fingerprinting.evidence.models import EvidenceCollection
from techspecter.fingerprinting.models import DetectionResult
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.fingerprinting.pipeline.evidence_pipeline import EvidencePipeline
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


class FingerprintCompatibilityLayer:
    """Bridge legacy detection with the new evidence collection pipeline."""

    def __init__(
        self,
        *,
        detection_pipeline: FingerprintPipeline | None = None,
        evidence_pipeline: EvidencePipeline | None = None,
    ) -> None:
        """Initialize compatibility layer with injectable pipelines."""
        self._detection_pipeline = detection_pipeline or FingerprintPipeline()
        self._evidence_pipeline = evidence_pipeline or EvidencePipeline()

    def detect(self, discovery: DiscoveryResult) -> DetectionResult:
        """Run legacy technology detection unchanged."""
        return self._detection_pipeline.run(discovery)

    def collect_evidence(self, discovery: DiscoveryResult) -> EvidenceCollection:
        """Run the evidence-only pipeline."""
        return self._evidence_pipeline.collect(discovery)

    def analyze(self, discovery: DiscoveryResult) -> tuple[DetectionResult, EvidenceCollection]:
        """Run detection and evidence collection without breaking legacy behavior."""
        detection = self.detect(discovery)
        evidence = self.collect_evidence(discovery)
        logger.debug(
            "Compatibility layer produced %d detections and %d evidence items for %s",
            len(detection.matches),
            evidence.summary.total_items,
            detection.target_url,
        )
        return detection, evidence
