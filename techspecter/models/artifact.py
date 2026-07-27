"""Artifact observation models for passive cloud, identity, and API analysis."""

from __future__ import annotations

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class ArtifactReference(TechSpecterModel):
    """Passive artifact indicator extracted from collected data."""

    artifact_type: str
    category: str
    value: str
    source: str
    location: str | None = None
    snippet: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class ArtifactDiscoveryObservation(TechSpecterModel):
    """Complete passive artifact discovery observation."""

    references: list[ArtifactReference] = Field(default_factory=list)
    sources_scanned: list[str] = Field(default_factory=list)

    def references_for_types(self, *artifact_types: str) -> list[ArtifactReference]:
        """Return references matching any of the given artifact types."""
        allowed = set(artifact_types)
        return [item for item in self.references if item.artifact_type in allowed]

    def references_for_category(self, category: str) -> list[ArtifactReference]:
        """Return references belonging to a category."""
        return [item for item in self.references if item.category == category]
