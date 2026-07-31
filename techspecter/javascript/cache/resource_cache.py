"""Intelligent caching for JavaScript pipeline stages."""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock
from typing import Generic, TypeVar

from techspecter.javascript.ast.models import PreparedAst
from techspecter.javascript.models import JavaScriptResourceMetadata
from techspecter.javascript.normalization.pipeline import NormalizationResult

logger = logging.getLogger(__name__)

T = TypeVar("T")


class LruCache(Generic[T]):
    """Thread-safe LRU cache."""

    def __init__(self, *, maxsize: int = 128) -> None:
        """Initialize cache."""
        self._maxsize = max(1, maxsize)
        self._items: OrderedDict[str, T] = OrderedDict()
        self._lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> T | None:
        """Return cached value."""
        with self._lock:
            value = self._items.get(key)
            if value is None:
                self.misses += 1
                return None
            self._items.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: T) -> None:
        """Store value."""
        with self._lock:
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self._maxsize:
                self._items.popitem(last=False)

    def clear(self) -> None:
        """Clear cache."""
        with self._lock:
            self._items.clear()


@dataclass(slots=True)
class JavaScriptResourceCache:
    """Unified cache for downloads, normalization, metadata, and AST snapshots."""

    download_cache: LruCache[str] = field(default_factory=lambda: LruCache[str](maxsize=256))
    normalized_cache: LruCache[NormalizationResult] = field(
        default_factory=lambda: LruCache[NormalizationResult](maxsize=256),
    )
    metadata_cache: LruCache[JavaScriptResourceMetadata] = field(
        default_factory=lambda: LruCache[JavaScriptResourceMetadata](maxsize=256),
    )
    ast_cache: LruCache[PreparedAst] = field(
        default_factory=lambda: LruCache[PreparedAst](maxsize=128),
    )
    hash_cache: LruCache[str] = field(default_factory=lambda: LruCache[str](maxsize=512))

    @staticmethod
    def content_hash(content: str) -> str:
        """Compute SHA-256 hash of JavaScript content."""
        return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def url_key(url: str) -> str:
        """Build deterministic cache key for a URL."""
        return url

    @staticmethod
    def content_key(*, url: str, content: str) -> str:
        """Build cache key combining URL and content hash."""
        digest = JavaScriptResourceCache.content_hash(content)[:16]
        return f"{url}:{digest}"

    @property
    def total_hits(self) -> int:
        """Return aggregate cache hits."""
        return (
            self.download_cache.hits
            + self.normalized_cache.hits
            + self.metadata_cache.hits
            + self.ast_cache.hits
            + self.hash_cache.hits
        )

    def clear_all(self) -> None:
        """Clear all caches."""
        self.download_cache.clear()
        self.normalized_cache.clear()
        self.metadata_cache.clear()
        self.ast_cache.clear()
        self.hash_cache.clear()
        logger.debug("JavaScript resource caches cleared")


_global_cache: JavaScriptResourceCache | None = None


def get_javascript_cache() -> JavaScriptResourceCache:
    """Return process-wide JavaScript resource cache."""
    global _global_cache
    if _global_cache is None:
        _global_cache = JavaScriptResourceCache()
    return _global_cache
