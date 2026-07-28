"""Unified passive detection provider framework."""

from techspecter.fingerprinting.models import SecurityFinding
from techspecter.providers.models import (
    ProviderDetectionResult,
    ProviderMatch,
    ProviderTarget,
    UnifiedDetectionResult,
)

__all__ = [
    "ProviderDetectionResult",
    "ProviderMatch",
    "ProviderTarget",
    "SecurityFinding",
    "UnifiedDetectionResult",
]


def __getattr__(name: str) -> object:
    """Lazy-load heavy provider modules."""
    if name == "ProviderManager":
        from techspecter.providers.manager import ProviderManager

        return ProviderManager
    if name == "UnifiedDetectionService":
        from techspecter.providers.service import UnifiedDetectionService

        return UnifiedDetectionService
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
