"""Detection plugin extension points."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from techspecter.fingerprinting.detection.models import TechnologyEvaluation, VersionResolution
from techspecter.fingerprinting.detection.weights import ScoringWeights
from techspecter.fingerprinting.evidence.models import Evidence
from techspecter.fingerprinting.signatures.models import SignatureRule, TechnologySignature
from techspecter.fingerprinting.signatures.registry import SignatureRegistry


class CustomRuleProvider(Protocol):
    """Protocol for plugins that contribute detection rules."""

    def rules_for(self, technology_id: str) -> list[SignatureRule]:
        """Return additional rules for a technology."""


class ConfidenceProvider(Protocol):
    """Protocol for plugins that adjust confidence scoring."""

    def adjust_confidence(
        self,
        evaluation: TechnologyEvaluation,
        confidence: float,
    ) -> float:
        """Return adjusted confidence score."""


class VersionResolverProvider(Protocol):
    """Protocol for plugins that resolve technology versions."""

    def resolve_version(
        self,
        signature: TechnologySignature,
        evidence_items: tuple[Evidence, ...],
    ) -> VersionResolution | None:
        """Return a custom version resolution when applicable."""


class EvidenceValidator(Protocol):
    """Protocol for plugins that validate evidence before detection."""

    def validate(self, evidence: Evidence) -> bool:
        """Return whether evidence should participate in detection."""


class DetectionRulePlugin(ABC):
    """Plugin hook for registering custom detection rules."""

    @abstractmethod
    def register_rules(self, registry: SignatureRegistry) -> None:
        """Register custom technology signatures or rules."""


class DetectionConfidencePlugin(ABC):
    """Plugin hook for custom confidence providers."""

    @abstractmethod
    def provider(self) -> ConfidenceProvider:
        """Return confidence provider instance."""


class DetectionVersionPlugin(ABC):
    """Plugin hook for custom version resolvers."""

    @abstractmethod
    def provider(self) -> VersionResolverProvider:
        """Return version resolver provider instance."""


class DetectionValidatorPlugin(ABC):
    """Plugin hook for custom evidence validators."""

    @abstractmethod
    def validator(self) -> EvidenceValidator:
        """Return evidence validator instance."""


class DetectionExtensionRegistry:
    """Registry for detection plugin extensions."""

    def __init__(self) -> None:
        """Initialize extension registry."""
        self._rule_plugins: list[DetectionRulePlugin] = []
        self._confidence_plugins: list[DetectionConfidencePlugin] = []
        self._version_plugins: list[DetectionVersionPlugin] = []
        self._validator_plugins: list[DetectionValidatorPlugin] = []
        self.weights = ScoringWeights()

    def register_rule_plugin(self, plugin: DetectionRulePlugin) -> None:
        """Register a custom rule plugin."""
        self._rule_plugins.append(plugin)

    def register_confidence_plugin(self, plugin: DetectionConfidencePlugin) -> None:
        """Register a confidence plugin."""
        self._confidence_plugins.append(plugin)

    def register_version_plugin(self, plugin: DetectionVersionPlugin) -> None:
        """Register a version resolver plugin."""
        self._version_plugins.append(plugin)

    def register_validator_plugin(self, plugin: DetectionValidatorPlugin) -> None:
        """Register an evidence validator plugin."""
        self._validator_plugins.append(plugin)

    def apply_rule_plugins(self, registry: SignatureRegistry) -> None:
        """Apply all registered rule plugins."""
        for plugin in self._rule_plugins:
            plugin.register_rules(registry)


detection_extension_registry = DetectionExtensionRegistry()
