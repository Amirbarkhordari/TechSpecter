"""Tests for version extraction."""

from __future__ import annotations

from techspecter.fingerprints.loader import SignatureLoader
from techspecter.fingerprints.models import UNKNOWN_VERSION
from techspecter.fingerprints.version import VersionExtractor


def test_version_extractor_finds_react_version() -> None:
    """Verify React version strings are extracted."""
    react = next(item for item in SignatureLoader().load_all() if item.id == "react")
    extractor = VersionExtractor()
    content = 'React.version="18.2.0";'
    assert extractor.extract(react, content) == "18.2.0"


def test_version_extractor_returns_unknown_when_missing() -> None:
    """Verify unknown version is returned when no pattern matches."""
    react = next(item for item in SignatureLoader().load_all() if item.id == "react")
    extractor = VersionExtractor()
    assert extractor.extract(react, "console.log('no version');") == UNKNOWN_VERSION


def test_version_extractor_finds_jquery_version() -> None:
    """Verify jQuery version strings are extracted."""
    jquery = next(item for item in SignatureLoader().load_all() if item.id == "jquery")
    extractor = VersionExtractor()
    content = 'jQuery.fn.jquery = "3.7.1";'
    assert extractor.extract(jquery, content) == "3.7.1"
