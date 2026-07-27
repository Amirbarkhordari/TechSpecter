"""Tests for package import and public API surface."""

from __future__ import annotations

import importlib


def test_package_imports_successfully() -> None:
    """Verify the top-level package and subpackages import without errors."""
    package = importlib.import_module("techspecter")
    assert package.__version__ == "0.4.0"

    subpackages = [
        "techspecter.core",
        "techspecter.crawler",
        "techspecter.downloader",
        "techspecter.parser",
        "techspecter.detector",
        "techspecter.fingerprints",
        "techspecter.report",
        "techspecter.models",
        "techspecter.utils",
        "techspecter.plugins",
    ]
    for name in subpackages:
        module = importlib.import_module(name)
        assert module is not None


def test_public_exports() -> None:
    """Verify key symbols are exported from the public API."""
    from techspecter import Settings, __version__, get_settings

    assert __version__ == "0.4.0"
    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.app_name == "TechSpecter"
