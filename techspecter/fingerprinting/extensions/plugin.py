"""Plugin extension points for the evidence-based fingerprinting engine."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from techspecter.fingerprinting.analyzers.base import EvidenceCollector
from techspecter.fingerprinting.detection.plugins import (
    DetectionConfidencePlugin,
    DetectionRulePlugin,
    DetectionValidatorPlugin,
    DetectionVersionPlugin,
)
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceCollection


class EvidenceProvider(Protocol):
    """Protocol for components that can emit standalone evidence items."""

    def provide(self, *, target_url: str) -> list[Evidence]:
        """Return evidence items for a target URL."""


class FingerprintPluginExtension(ABC):
    """Extension point for fingerprint plugin integration."""

    @abstractmethod
    def register_collectors(self, registry: object) -> None:
        """Register custom evidence collectors."""

    @abstractmethod
    def register_analyzers(self, registry: object) -> None:
        """Register custom fingerprint analyzers."""


class DetectionPluginExtension(ABC):
    """Optional extension point for detection plugins."""

    @abstractmethod
    def register_detection_plugins(self, registry: object) -> None:
        """Register custom detection plugins (rules, confidence, version resolvers)."""


__all__ = [
    "CollectorPlugin",
    "DetectionConfidencePlugin",
    "DetectionPluginExtension",
    "DetectionRulePlugin",
    "DetectionValidatorPlugin",
    "DetectionVersionPlugin",
    "EvidenceProvider",
    "EvidenceProviderPlugin",
    "FingerprintPluginExtension",
    "merge_collections",
]


class CollectorPlugin(ABC):
    """Plugin hook for registering a custom evidence collector."""

    @abstractmethod
    def collector(self) -> EvidenceCollector:
        """Return the collector instance provided by the plugin."""


class EvidenceProviderPlugin(ABC):
    """Plugin hook for registering a custom evidence provider."""

    @abstractmethod
    def provider(self) -> EvidenceProvider:
        """Return the evidence provider instance."""


def merge_collections(
    target_url: str,
    *collections: EvidenceCollection,
) -> EvidenceCollection:
    """Merge multiple evidence collections into one immutable result."""
    items: list[Evidence] = []
    elapsed_ms = 0.0
    for collection in collections:
        items.extend(collection.items)
        elapsed_ms += collection.elapsed_ms
    from techspecter.fingerprinting.evidence.models import summarize_evidence

    return EvidenceCollection(
        target_url=target_url,
        items=tuple(items),
        summary=summarize_evidence(items),
        elapsed_ms=elapsed_ms,
    )
