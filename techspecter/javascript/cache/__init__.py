"""JavaScript resource cache."""

from techspecter.javascript.cache.resource_cache import (
    JavaScriptResourceCache,
    LruCache,
    get_javascript_cache,
)

__all__ = ["JavaScriptResourceCache", "LruCache", "get_javascript_cache"]
