"""Data models and schemas for TechSpecter."""

from techspecter.models.base import TechSpecterModel
from techspecter.models.discovery import (
    DiscoveryResult,
    DownloadResult,
    InlineScript,
    ScriptResource,
    Target,
)

__all__ = [
    "DiscoveryResult",
    "DownloadResult",
    "InlineScript",
    "ScriptResource",
    "Target",
    "TechSpecterModel",
]
