"""Version extractor registry."""

from __future__ import annotations

from techspecter.versioning.extractor import TechnologyVersionExtractor
from techspecter.versioning.extractors import (
    AngularVersionExtractor,
    BootstrapVersionExtractor,
    JQueryVersionExtractor,
    LeafletVersionExtractor,
    MaterialUiVersionExtractor,
    NextJsVersionExtractor,
    ReactVersionExtractor,
    TailwindVersionExtractor,
    TurbopackVersionExtractor,
    ViteVersionExtractor,
    VueVersionExtractor,
    WebpackVersionExtractor,
)


def build_default_registry() -> tuple[dict[str, TechnologyVersionExtractor], frozenset[str]]:
    """Register all built-in technology version extractors."""
    instances: list[TechnologyVersionExtractor] = [
        ReactVersionExtractor(),
        NextJsVersionExtractor(),
        AngularVersionExtractor(),
        VueVersionExtractor(),
        JQueryVersionExtractor(),
        BootstrapVersionExtractor(),
        TailwindVersionExtractor(),
        MaterialUiVersionExtractor(),
        LeafletVersionExtractor(),
        WebpackVersionExtractor(),
        ViteVersionExtractor(),
        TurbopackVersionExtractor(),
    ]
    registry: dict[str, TechnologyVersionExtractor] = {}
    primary_ids: set[str] = set()
    for extractor in instances:
        registry[extractor.technology_id] = extractor
        primary_ids.add(extractor.technology_id)
        for alias in extractor.aliases:
            registry[alias.lower()] = extractor
    return registry, frozenset(primary_ids)


class VersionExtractorRegistry:
    """Lookup table for technology-specific version extractors."""

    def __init__(self, extractors: dict[str, TechnologyVersionExtractor] | None = None) -> None:
        """Initialize registry."""
        if extractors is None:
            registry, primary_ids = build_default_registry()
            self._extractors = registry
            self._primary_ids = primary_ids
        else:
            self._extractors = extractors
            self._primary_ids = frozenset(
                {ext.technology_id for ext in extractors.values()},
            )

    def get(self, technology_id: str) -> TechnologyVersionExtractor | None:
        """Return extractor for a technology id or alias."""
        return self._extractors.get(technology_id.lower().strip())

    def register(self, extractor: TechnologyVersionExtractor) -> None:
        """Register an extractor."""
        self._extractors[extractor.technology_id] = extractor
        self._primary_ids = frozenset(set(self._primary_ids) | {extractor.technology_id})
        for alias in extractor.aliases:
            self._extractors[alias.lower()] = extractor

    @property
    def supported_technology_ids(self) -> frozenset[str]:
        """Return primary technology ids with dedicated extractors."""
        return self._primary_ids
