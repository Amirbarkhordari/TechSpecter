"""Backward-compatible re-exports."""

from techspecter.fingerprinting.matchers.base import (
    MatcherRegistry,
    PatternMatcher,
    build_default_registry,
)

__all__ = ["MatcherRegistry", "PatternMatcher", "build_default_registry"]
