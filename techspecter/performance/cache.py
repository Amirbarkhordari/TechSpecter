"""Production-grade analysis caches."""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock
from typing import TypeVar

from techspecter.models.artifact import ArtifactDiscoveryObservation

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(slots=True)
class CacheStats:
    """Cache hit/miss statistics."""

    hits: int = 0
    misses: int = 0

    @property
    def total(self) -> int:
        """Return total cache lookups."""
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        """Return cache hit rate as a percentage."""
        if self.total == 0:
            return 0.0
        return round((self.hits / self.total) * 100.0, 2)


class _LruCache:
    """Thread-safe LRU cache for analysis artifacts."""

    def __init__(self, *, maxsize: int = 128) -> None:
        self._maxsize = max(1, maxsize)
        self._items: OrderedDict[str, object] = OrderedDict()
        self._lock = Lock()
        self.stats = CacheStats()

    def get(self, key: str) -> object | None:
        """Return a cached value when present."""
        with self._lock:
            value = self._items.get(key)
            if value is None:
                self.stats.misses += 1
                return None
            self._items.move_to_end(key)
            self.stats.hits += 1
            return value

    def set(self, key: str, value: object) -> None:
        """Store a value in the cache."""
        with self._lock:
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self._maxsize:
                self._items.popitem(last=False)

    def clear(self) -> None:
        """Clear cached entries."""
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


@dataclass
class AnalysisCache:
    """Caches expensive passive analysis derivations."""

    max_entries: int = 128
    enabled: bool = True
    _artifact_cache: _LruCache = field(init=False, repr=False)
    _text_source_cache: _LruCache = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._artifact_cache = _LruCache(maxsize=self.max_entries)
        self._text_source_cache = _LruCache(maxsize=self.max_entries)

    @staticmethod
    def discovery_key(discovery_id: str, suffix: str) -> str:
        """Build a stable cache key for discovery-derived data."""
        digest = hashlib.sha256(discovery_id.encode("utf-8")).hexdigest()[:16]
        return f"{suffix}:{digest}"

    @staticmethod
    def discovery_fingerprint(
        *,
        target_url: str,
        inline_count: int,
        download_count: int,
        metadata_present: bool,
    ) -> str:
        """Build a lightweight discovery fingerprint for caching."""
        payload = f"{target_url}|{inline_count}|{download_count}|{metadata_present}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get_artifact_observation(self, key: str) -> ArtifactDiscoveryObservation | None:
        """Return cached artifact observation."""
        if not self.enabled:
            return None
        cached = self._artifact_cache.get(key)
        if isinstance(cached, ArtifactDiscoveryObservation):
            return cached
        return None

    def set_artifact_observation(self, key: str, observation: ArtifactDiscoveryObservation) -> None:
        """Cache artifact observation."""
        if self.enabled:
            self._artifact_cache.set(key, observation)

    def get_text_sources(self, key: str) -> list[object] | None:
        """Return cached text source list."""
        if not self.enabled:
            return None
        cached = self._text_source_cache.get(key)
        if isinstance(cached, list):
            return cached
        return None

    def set_text_sources(self, key: str, sources: list[object]) -> None:
        """Cache collected text sources."""
        if self.enabled:
            self._text_source_cache.set(key, sources)

    def stats_summary(self) -> dict[str, object]:
        """Return cache statistics for reporting."""
        return {
            "enabled": self.enabled,
            "artifact_entries": len(self._artifact_cache),
            "text_source_entries": len(self._text_source_cache),
            "artifact_hits": self._artifact_cache.stats.hits,
            "artifact_misses": self._artifact_cache.stats.misses,
            "artifact_hit_rate": self._artifact_cache.stats.hit_rate,
            "text_source_hits": self._text_source_cache.stats.hits,
            "text_source_misses": self._text_source_cache.stats.misses,
            "text_source_hit_rate": self._text_source_cache.stats.hit_rate,
        }

    def clear(self) -> None:
        """Clear all analysis caches."""
        self._artifact_cache.clear()
        self._text_source_cache.clear()
        logger.debug("Analysis cache cleared")


_global_cache: AnalysisCache | None = None


def get_analysis_cache(*, enabled: bool = True, max_entries: int = 128) -> AnalysisCache:
    """Return the process-wide analysis cache."""
    global _global_cache
    if _global_cache is None:
        _global_cache = AnalysisCache(enabled=enabled, max_entries=max_entries)
    else:
        _global_cache.enabled = enabled
        _global_cache.max_entries = max_entries
    return _global_cache


def reset_analysis_cache() -> None:
    """Reset the process-wide analysis cache (primarily for tests)."""
    global _global_cache
    if _global_cache is not None:
        _global_cache.clear()
    _global_cache = None
