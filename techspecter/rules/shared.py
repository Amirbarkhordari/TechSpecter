"""Shared rule engine resources configured from performance settings."""

from __future__ import annotations

from pathlib import Path

from techspecter.configuration.manager import get_configuration_manager
from techspecter.rules.cache import RegexCache, RuleCache
from techspecter.rules.loader import RuleLoader

_shared_regex_cache: RegexCache | None = None
_shared_rule_cache: RuleCache | None = None


def get_shared_regex_cache(*, maxsize: int | None = None) -> RegexCache:
    """Return a process-wide regex compilation cache."""
    global _shared_regex_cache
    if maxsize is None:
        maxsize = get_configuration_manager().config.performance.max_regex_cache_size
    if _shared_regex_cache is None:
        _shared_regex_cache = RegexCache(maxsize=maxsize)
    return _shared_regex_cache


def get_shared_rule_cache() -> RuleCache:
    """Return a process-wide rule load cache."""
    global _shared_rule_cache
    if _shared_rule_cache is None:
        _shared_rule_cache = RuleCache()
    return _shared_rule_cache


def create_rule_loader(
    *,
    rule_directories: list[str | Path] | None = None,
) -> RuleLoader:
    """Create a rule loader honoring performance configuration."""
    performance = get_configuration_manager().config.performance
    return RuleLoader(
        rule_directories=rule_directories,
        cache=get_shared_rule_cache(),
        use_cache=performance.cache_rules,
    )


def reset_shared_rule_resources() -> None:
    """Reset shared rule caches (primarily for tests)."""
    global _shared_regex_cache, _shared_rule_cache
    if _shared_regex_cache is not None:
        _shared_regex_cache.clear()
    _shared_regex_cache = None
    if _shared_rule_cache is not None:
        _shared_rule_cache.clear()
    _shared_rule_cache = None
