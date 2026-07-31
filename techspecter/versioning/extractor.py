"""Technology version extractor protocol."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from techspecter.versioning.models import ExtractedVersion


class TechnologyVersionExtractor(ABC):
    """Extract versions for a single technology from JavaScript content."""

    technology_id: ClassVar[str]
    aliases: ClassVar[frozenset[str]] = frozenset()

    @abstractmethod
    def extract(
        self,
        content: str,
        *,
        url: str,
        filename: str,
    ) -> list[ExtractedVersion]:
        """Extract all version observations from content."""

    def matches_technology(self, technology_id: str) -> bool:
        """Return whether this extractor handles a technology id."""
        normalized = technology_id.lower().strip()
        if normalized == self.technology_id:
            return True
        return normalized in self.aliases
