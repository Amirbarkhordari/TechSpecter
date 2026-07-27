"""Tests for plugin metadata."""

from __future__ import annotations

import sys

import pytest

from techspecter import __version__
from techspecter.plugins.metadata import PluginMetadata
from techspecter.plugins.sdk import (
    current_python_version,
    is_python_version_compatible,
    normalize_platforms,
    parse_version,
)
from tests.plugin_fixtures import sample_metadata


def test_metadata_required_fields() -> None:
    """Verify metadata stores all required fields."""
    metadata = sample_metadata(
        author="Author",
        homepage="https://example.com",
        license="MIT",
        tags=["test"],
    )
    assert metadata.id == "sample-plugin"
    assert metadata.name == "Sample Plugin"
    assert metadata.version == "1.0.0"
    assert metadata.author == "Author"
    assert metadata.homepage == "https://example.com"
    assert metadata.license == "MIT"
    assert metadata.tags == ["test"]


def test_metadata_rejects_empty_id() -> None:
    """Verify blank metadata fields are rejected."""
    with pytest.raises(ValueError):
        sample_metadata(id="")


def test_to_core_metadata() -> None:
    """Verify rich metadata converts to legacy core metadata."""
    metadata = sample_metadata(author="Author")
    core = metadata.to_core_metadata()
    assert core.name == "sample-plugin"
    assert core.version == "1.0.0"
    assert core.description == "Sample plugin for tests"
    assert core.author == "Author"


def test_platform_support_any() -> None:
    """Verify 'any' platform matches all environments."""
    metadata = PluginMetadata(
        id="p",
        name="P",
        version="1.0.0",
        description="d",
        supported_platforms=["any"],
    )
    assert metadata.is_platform_supported()


def test_platform_support_current(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify platform checks honor the active platform."""
    metadata = PluginMetadata(
        id="p",
        name="P",
        version="1.0.0",
        description="d",
        supported_platforms=["linux"],
    )
    monkeypatch.setattr(sys, "platform", "linux")
    assert metadata.is_platform_supported()

    monkeypatch.setattr(sys, "platform", "win32")
    assert not metadata.is_platform_supported()


def test_core_version_compatibility() -> None:
    """Verify minimum core version checks."""
    metadata = sample_metadata(minimum_core_version="0.5.0")
    assert metadata.is_core_compatible("0.5.0")
    assert metadata.is_core_compatible(__version__)
    assert not metadata.is_core_compatible("0.1.0")


def test_parse_version() -> None:
    """Verify version parsing for comparisons."""
    assert parse_version("1.2.3") == (1, 2, 3)
    assert parse_version("0.5.0") >= parse_version("0.4.0")


def test_python_version_compatibility() -> None:
    """Verify minimum Python version checks."""
    metadata = sample_metadata(minimum_python_version="3.11")
    assert metadata.is_python_compatible("3.11")
    assert metadata.is_python_compatible("3.12")
    assert not metadata.is_python_compatible("3.10")
    assert is_python_version_compatible("3.11", current_python_version())


def test_plugin_type_defaults_to_lifecycle() -> None:
    """Verify plugin metadata defaults to lifecycle type."""
    metadata = sample_metadata()
    assert metadata.plugin_type.value == "lifecycle"


def test_normalize_platforms() -> None:
    """Verify platform normalization."""
    assert normalize_platforms(["Windows", "LINUX"]) == ["windows", "linux"]
    assert normalize_platforms([]) == ["any"]
