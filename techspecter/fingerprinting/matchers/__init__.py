"""Pattern matcher implementations."""

from techspecter.fingerprinting.matchers.base import (
    MatcherRegistry,
    PatternMatcher,
    build_default_registry,
)
from techspecter.fingerprinting.matchers.filename_matcher import FilenameMatcher
from techspecter.fingerprinting.matchers.global_variable_matcher import GlobalVariableMatcher
from techspecter.fingerprinting.matchers.regex_matcher import RegexMatcher
from techspecter.fingerprinting.matchers.sourcemap_matcher import SourceMapMatcher
from techspecter.fingerprinting.matchers.string_matcher import StringMatcher

__all__ = [
    "FilenameMatcher",
    "GlobalVariableMatcher",
    "MatcherRegistry",
    "PatternMatcher",
    "RegexMatcher",
    "SourceMapMatcher",
    "StringMatcher",
    "build_default_registry",
]
