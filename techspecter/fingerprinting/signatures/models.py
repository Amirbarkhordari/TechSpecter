"""Next-generation signature schema models."""

from __future__ import annotations

from pydantic import Field

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


class VersionExtractorSpec(TechSpecterModel):
    """Version extraction configuration for evidence-based resolution."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    pattern: str
    source: str = "content"
    weight: float = Field(default=1.0, ge=0.0)
    enabled: bool = True


class TechnologySignature(TechSpecterModel):
    """Evidence-based technology signature for explainable detection."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    name: str
    category: str
    priority: int = Field(default=0, ge=0)
    description: str | None = None
    minimum_score: float = Field(default=40.0, ge=0.0, le=100.0)
    aliases: tuple[str, ...] = Field(default_factory=tuple)
    dependencies: tuple[str, ...] = Field(default_factory=tuple)
    conflicts_with: tuple[str, ...] = Field(default_factory=tuple)
    positive_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    negative_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    required_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    optional_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    references: tuple[str, ...] = Field(default_factory=tuple)
    version_extractors: tuple[VersionExtractorSpec, ...] = Field(default_factory=tuple)
