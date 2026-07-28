"""TechSpecter — Passive Web Application Analysis Framework."""

from techspecter._version import __version__, version_display
from techspecter.config import Settings, get_settings

__all__ = ["Settings", "__version__", "get_settings", "version_display"]
