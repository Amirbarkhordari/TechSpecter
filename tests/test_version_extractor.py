"""Tests for improved version extraction."""

from __future__ import annotations

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.loader import SignatureLoader
from techspecter.fingerprints.models import UNKNOWN_VERSION
from techspecter.fingerprints.version import VersionExtractor


def test_version_extractor_picks_highest_confidence_candidate() -> None:
    """Verify the extractor prefers higher-weight version patterns."""
    react = next(item for item in SignatureLoader().load_all() if item.id == "react")
    extractor = VersionExtractor()
    context = MatchContext(
        content='React.version="18.2.0"; react@17.0.0;',
        filename="react.js",
        url="https://example.com/react.js",
    )
    version, pattern = extractor.extract_with_pattern(react, context)
    assert version == "18.2.0"
    assert pattern is not None


def test_version_extractor_supports_bundle_source() -> None:
    """Verify bundle metadata can be used for version extraction."""
    angular = next(item for item in SignatureLoader().load_all() if item.id == "angular")
    extractor = VersionExtractor()
    context = MatchContext(
        content="console.log('app');",
        filename="@angular/core@17.3.0/index.js",
        url="https://example.com/@angular/core@17.3.0/index.js",
    )
    version = extractor.extract(angular, context)
    assert version == "17.3.0"


def test_version_extractor_returns_unknown_for_missing_version() -> None:
    """Verify unknown version is returned when no pattern matches."""
    react = next(item for item in SignatureLoader().load_all() if item.id == "react")
    extractor = VersionExtractor()
    assert extractor.extract(react, "console.log('no version');") == UNKNOWN_VERSION
