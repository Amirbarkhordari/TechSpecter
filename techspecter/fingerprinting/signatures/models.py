"""Signature Intelligence Platform models."""

from __future__ import annotations

from pydantic import Field, model_validator

from techspecter.models.base import TechSpecterModel


class SignatureRule(TechSpecterModel):
    """Single positive, negative, required, or optional signature rule."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    matcher: str
    pattern: str
    weight: float = Field(default=1.0, ge=0.0)
    target: str = "content"
    description: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class SignatureIndicator(TechSpecterModel):
    """Typed evidence indicator for a technology signature."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    pattern: str
    matcher: str = "contains"
    weight: float = Field(default=70.0, ge=0.0)
    description: str | None = None


class SignatureIndicators(TechSpecterModel):
    """Grouped indicators mapped to evidence targets."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    runtime: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    bundle: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    html: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    http: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    header: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    manifest: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    sourcemap: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    package: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    metadata: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)
    content: tuple[SignatureIndicator, ...] = Field(default_factory=tuple)


class VersionExtractorSpec(TechSpecterModel):
    """Version extraction configuration for evidence-based resolution."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    pattern: str
    source: str = "content"
    weight: float = Field(default=1.0, ge=0.0)
    enabled: bool = True
    description: str | None = None


class ConfidenceModifier(TechSpecterModel):
    """Explainable confidence adjustment for a signature."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    value: float
    reason: str


class TechnologySignature(TechSpecterModel):
    """Evidence-based technology signature for explainable detection."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    name: str
    category: str
    subcategory: str | None = None
    vendor: str | None = None
    priority: int = Field(default=0, ge=0)
    description: str | None = None
    website: str | None = None
    notes: str | None = None
    deprecated: bool = False
    minimum_score: float = Field(default=40.0, ge=0.0, le=100.0)
    confidence_modifier: float = Field(default=0.0, ge=-50.0, le=50.0)
    aliases: tuple[str, ...] = Field(default_factory=tuple)
    dependencies: tuple[str, ...] = Field(default_factory=tuple)
    conflicts_with: tuple[str, ...] = Field(default_factory=tuple)
    supported_versions: tuple[str, ...] = Field(default_factory=tuple)
    references: tuple[str, ...] = Field(default_factory=tuple)
    confidence_modifiers: tuple[ConfidenceModifier, ...] = Field(default_factory=tuple)
    required_evidence: SignatureIndicators = Field(default_factory=SignatureIndicators)
    optional_evidence: SignatureIndicators = Field(default_factory=SignatureIndicators)
    negative_evidence: SignatureIndicators = Field(default_factory=SignatureIndicators)
    positive_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    negative_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    required_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    optional_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    version_extractors: tuple[VersionExtractorSpec, ...] = Field(default_factory=tuple)

    @model_validator(mode="after")
    def _validate_has_detection_logic(self) -> TechnologySignature:
        """Ensure signature defines at least one detection path."""
        has_rules = any(
            (
                self.positive_rules,
                self.required_rules,
                self.optional_rules,
                self.required_evidence.runtime,
                self.required_evidence.package,
                self.required_evidence.content,
                self.optional_evidence.runtime,
                self.optional_evidence.package,
            ),
        )
        if not has_rules:
            msg = f"Signature '{self.id}' must define rules or evidence indicators"
            raise ValueError(msg)
        return self
