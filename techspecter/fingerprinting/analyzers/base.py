"""Abstract interfaces for evidence-only fingerprint analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from techspecter.fingerprinting.evidence.models import EvidenceCollection, EvidenceResult
from techspecter.models.discovery import DiscoveryResult


class BaseAnalyzer(ABC):
    """Base class for isolated fingerprint evidence analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the analyzer identifier."""

    @property
    def priority(self) -> int:
        """Return execution priority (lower runs first)."""
        return 100

    @abstractmethod
    def supports(self, discovery: DiscoveryResult) -> bool:
        """Return whether this analyzer can process the discovery result."""

    @abstractmethod
    def collect(self, discovery: DiscoveryResult) -> EvidenceResult:
        """Collect evidence from discovery data without detecting technologies."""


class EvidenceCollector(BaseAnalyzer):
    """Specialized analyzer that only emits raw evidence observations."""

    @abstractmethod
    def collect(self, discovery: DiscoveryResult) -> EvidenceResult:
        """Collect evidence items from the discovery result."""


class FingerprintAnalyzer(EvidenceCollector):
    """Fingerprint-stage analyzer interface for future detection phases.

    Phase 1 implementations collect evidence only and never assign technologies.
    """

    def analyze(self, discovery: DiscoveryResult) -> EvidenceCollection:
        """Collect and wrap evidence in a collection."""
        result = self.collect(discovery)
        return EvidenceCollection(
            target_url=str(discovery.target.url),
            items=result.items,
            elapsed_ms=result.elapsed_ms,
        )
