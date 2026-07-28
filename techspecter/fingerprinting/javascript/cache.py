"""Parse cache for JavaScript intelligence."""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict
from threading import Lock

from techspecter.fingerprinting.javascript.models import ParsedScript

logger = logging.getLogger(__name__)


class ParseCache:
    """Thread-safe LRU cache for parsed JavaScript resources."""

    def __init__(self, *, maxsize: int = 64) -> None:
        """Initialize parse cache."""
        self._maxsize = max(1, maxsize)
        self._items: OrderedDict[str, ParsedScript] = OrderedDict()
        self._lock = Lock()

    @staticmethod
    def cache_key(*, url: str, content: str) -> str:
        """Build a stable cache key for a JavaScript resource."""
        digest = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
        return f"{url}:{digest[:16]}"

    def get(self, key: str) -> ParsedScript | None:
        """Return cached parse result."""
        with self._lock:
            value = self._items.get(key)
            if value is None:
                return None
            self._items.move_to_end(key)
            return value

    def set(self, key: str, parsed: ParsedScript) -> None:
        """Store parse result."""
        with self._lock:
            self._items[key] = parsed
            self._items.move_to_end(key)
            while len(self._items) > self._maxsize:
                self._items.popitem(last=False)

    def clear(self) -> None:
        """Clear cached parse results."""
        with self._lock:
            self._items.clear()
        logger.debug("JavaScript parse cache cleared")


_global_cache: ParseCache | None = None


def get_parse_cache(*, maxsize: int = 64) -> ParseCache:
    """Return process-wide parse cache."""
    global _global_cache
    if _global_cache is None:
        _global_cache = ParseCache(maxsize=maxsize)
    return _global_cache
