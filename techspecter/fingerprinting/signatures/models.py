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
    """Placeholder for future version extraction configuration."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    pattern: str
    source: str = "content"
    enabled: bool = False


class TechnologySignature(TechSpecterModel):
    """Evidence-based technology signature schema (Phase 1 infrastructure only)."""

    model_config = TechSpecterModel.model_config | {"frozen": True}

    id: str
    name: str
    category: str
    priority: int = Field(default=0, ge=0)
    description: str | None = None
    positive_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    negative_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    required_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    optional_rules: tuple[SignatureRule, ...] = Field(default_factory=tuple)
    references: tuple[str, ...] = Field(default_factory=tuple)
    version_extractors: tuple[VersionExtractorSpec, ...] = Field(default_factory=tuple)
