"""Tests for package import and public API surface."""

from __future__ import annotations

import importlib

from techspecter import __version__, version_display


def test_package_imports_successfully() -> None:
    """Verify the top-level package and subpackages import without errors."""
    package = importlib.import_module("techspecter")
    assert package.__version__ == __version__

    subpackages = [
        "techspecter.core",
        "techspecter.crawler",
        "techspecter.analysis",
        "techspecter.configuration",
        "techspecter.rules",
        "techspecter.downloader",
        "techspecter.parser",
        "techspecter.detector",
        "techspecter.fingerprints",
        "techspecter.report",
        "techspecter.models",
        "techspecter.utils",
        "techspecter.plugins",
        "techspecter.performance",
    ]
    for name in subpackages:
        module = importlib.import_module(name)
        assert module is not None


def test_public_exports() -> None:
    """Verify key symbols are exported from the public API."""
    from techspecter import Settings, get_settings

    assert __version__ == "1.0.0rc1"
    assert version_display() == "1.0.0-rc1"
    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.app_name == "TechSpecter"
