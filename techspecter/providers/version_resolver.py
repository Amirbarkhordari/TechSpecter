"""Unified version resolution across providers."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.providers.models import ProviderMatch

_PROVIDER_PRIORITY: tuple[str, ...] = ("techspecter", "wappalyzer", "retirejs")
_VERSION_RE = __import__("re").compile(r"^\d{1,4}(?:\.\d{1,4}){0,3}(?:[-+][\w.-]+)?$")


@dataclass(frozen=True, slots=True)
class VersionResolutionOutcome:
    """Resolved version with conflict metadata."""

    version: str
    source_provider: str
    confidence: float
    reason: str
    rejected_versions: tuple[str, ...] = field(default_factory=tuple)
    conflict: bool = False


class ProviderVersionResolver:
    """Resolve best version from multiple provider matches."""

    def resolve(self, matches: list[ProviderMatch]) -> VersionResolutionOutcome:
        """Select the best version using provider priority and confidence."""
        if not matches:
            return VersionResolutionOutcome(
                version=UNKNOWN_VERSION,
                source_provider="none",
                confidence=0.0,
                reason="No provider matches available",
            )

        candidates: list[tuple[str, str, float]] = []
        for provider in _PROVIDER_PRIORITY:
            for match in matches:
                if match.provider != provider:
                    continue
                version = self._normalize_version(match.version)
                if version is None:
                    continue
                candidates.append((version, provider, match.confidence))

        if not candidates:
            return VersionResolutionOutcome(
                version=UNKNOWN_VERSION,
                source_provider="none",
                confidence=0.0,
                reason="No valid version candidates from any provider",
            )

        unique_versions = {item[0] for item in candidates}
        ranked = sorted(candidates, key=lambda item: (-_provider_weight(item[1]), -item[2]))
        best_version, best_provider, best_confidence = ranked[0]
        rejected = tuple(sorted(unique_versions - {best_version}))
        conflict = len(unique_versions) > 1

        reason = (
            f"Selected version from {best_provider} "
            f"(priority {_provider_weight(best_provider):.0f})"
        )
        if conflict:
            reason += f"; rejected conflicting version(s): {', '.join(rejected)}"

        return VersionResolutionOutcome(
            version=best_version,
            source_provider=best_provider,
            confidence=min(100.0, best_confidence + (5.0 if not conflict else 0.0)),
            reason=reason,
            rejected_versions=rejected,
            conflict=conflict,
        )

    def _normalize_version(self, raw: str) -> str | None:
        """Validate and normalize a version string."""
        value = raw.strip().lstrip("vV")
        if not value or value == UNKNOWN_VERSION:
            return None
        if not _VERSION_RE.match(value):
            return None
        return value


def _provider_weight(provider: str) -> float:
    """Return priority weight for a provider."""
    try:
        index = _PROVIDER_PRIORITY.index(provider)
    except ValueError:
        return 10.0
    return float(len(_PROVIDER_PRIORITY) - index) * 30.0
