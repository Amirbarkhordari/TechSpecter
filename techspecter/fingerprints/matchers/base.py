"""Pattern matcher interface and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.models import Pattern


class PatternMatcher(ABC):
    """Base class for fingerprint pattern matchers."""

    matcher_type: ClassVar[str]

    @abstractmethod
    def matches(self, pattern: Pattern, context: MatchContext) -> bool:
        """Return whether the pattern matches the given context.

        Args:
            pattern: Fingerprint pattern definition.
            context: JavaScript resource context.

        Returns:
            ``True`` when the pattern matches.
        """


class MatcherRegistry:
    """Registry mapping matcher type names to matcher implementations."""

    def __init__(self) -> None:
        """Initialize an empty matcher registry."""
        self._matchers: dict[str, PatternMatcher] = {}

    def register(self, matcher: PatternMatcher) -> None:
        """Register a matcher implementation.

        Args:
            matcher: Matcher instance to register.
        """
        self._matchers[matcher.matcher_type] = matcher

    def get(self, matcher_type: str) -> PatternMatcher | None:
        """Return a matcher for the given type name.

        Args:
            matcher_type: Matcher identifier.

        Returns:
            Matcher instance, or ``None`` when unsupported.
        """
        return self._matchers.get(matcher_type)


def build_default_registry() -> MatcherRegistry:
    """Create a registry with all built-in matcher implementations.

    Returns:
        Configured ``MatcherRegistry`` instance.
    """
    from techspecter.fingerprints.matchers.filename import FilenameMatcher
    from techspecter.fingerprints.matchers.global_var import GlobalVariableMatcher
    from techspecter.fingerprints.matchers.regex import RegexMatcher
    from techspecter.fingerprints.matchers.sourcemap import SourceMapMatcher
    from techspecter.fingerprints.matchers.string import StringMatcher

    registry = MatcherRegistry()
    for matcher in (
        StringMatcher(),
        RegexMatcher(),
        FilenameMatcher(),
        SourceMapMatcher(),
        GlobalVariableMatcher(),
    ):
        registry.register(matcher)
    return registry
