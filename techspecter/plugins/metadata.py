"""Plugin metadata models."""

from __future__ import annotations

import sys
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator

from techspecter import __version__
from techspecter.core.interfaces import PluginMetadata as CorePluginMetadata
from techspecter.models.base import TechSpecterModel
from techspecter.plugins.sdk import (
    current_python_version,
    is_python_version_compatible,
    parse_version,
)

PlatformName = Literal["windows", "linux", "macos", "any"]


class PluginType(StrEnum):
    """Supported plugin categories."""

    ANALYZER = "analyzer"
    REPORTER = "reporter"
    EXPORTER = "exporter"
    RULE_PACK = "rule_pack"
    LIFECYCLE = "lifecycle"


def _default_supported_platforms() -> list[PlatformName]:
    """Return the default supported platform list."""
    return ["any"]


class PluginMetadata(TechSpecterModel):
    """Rich metadata describing a TechSpecter plugin."""

    id: str
    name: str
    version: str
    description: str
    author: str | None = None
    homepage: str | None = None
    license: str | None = None
    plugin_type: PluginType = PluginType.LIFECYCLE
    minimum_core_version: str = "0.1.0"
    minimum_python_version: str = "3.11"
    supported_platforms: list[PlatformName] = Field(default_factory=_default_supported_platforms)
    tags: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)

    @field_validator("id", "name", "version", "description")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        """Ensure required string fields are not blank."""
        if not value.strip():
            msg = "Metadata fields must not be empty."
            raise ValueError(msg)
        return value.strip()

    def frozen_copy(self) -> PluginMetadata:
        """Return an immutable copy of this metadata."""
        return self.model_copy(deep=True)

    def to_core_metadata(self) -> CorePluginMetadata:
        """Convert to the legacy core metadata model."""
        return CorePluginMetadata(
            name=self.id,
            version=self.version,
            description=self.description,
            author=self.author,
        )

    def is_platform_supported(self) -> bool:
        """Return whether the plugin supports the current platform."""
        if "any" in self.supported_platforms:
            return True
        current = sys.platform
        if current.startswith("win") and "windows" in self.supported_platforms:
            return True
        if current == "darwin" and "macos" in self.supported_platforms:
            return True
        return bool(current.startswith("linux") and "linux" in self.supported_platforms)

    def is_core_compatible(self, core_version: str | None = None) -> bool:
        """Return whether the plugin supports the active core version."""
        minimum = parse_version(self.minimum_core_version)
        current = parse_version(core_version or __version__)
        return current >= minimum

    def is_python_compatible(self, python_version: str | None = None) -> bool:
        """Return whether the plugin supports the active Python version."""
        return is_python_version_compatible(
            self.minimum_python_version,
            python_version or current_python_version(),
        )
