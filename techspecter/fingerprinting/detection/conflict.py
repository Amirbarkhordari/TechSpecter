"""Conflict resolution for technology detections."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.fingerprinting.detection.models import VersionResolution
from techspecter.fingerprinting.models import TechnologyMatch
from techspecter.fingerprinting.signatures.models import TechnologySignature


@dataclass(slots=True)
class ConflictResolver:
    """Resolve overlapping and conflicting technology detections."""

    def resolve(
        self,
        matches: list[TechnologyMatch],
        signatures: dict[str, TechnologySignature],
    ) -> list[TechnologyMatch]:
        """Apply dependency and conflict rules to final matches."""
        by_id = {match.technology.id: match for match in matches}
        resolved: list[TechnologyMatch] = []

        for match in sorted(matches, key=lambda item: (-item.confidence, item.technology.name)):
            signature = signatures.get(match.technology.id)
            if signature is None:
                resolved.append(match)
                continue
            if self._conflicts_with_detected(signature, by_id, resolved):
                continue
            resolved.append(match)
            self._ensure_dependencies(signature, by_id, resolved)

        return self._dedupe_versions(resolved)

    def _conflicts_with_detected(
        self,
        signature: TechnologySignature,
        all_matches: dict[str, TechnologyMatch],
        accepted: list[TechnologyMatch],
    ) -> bool:
        """Return True when a higher-priority conflicting technology is present."""
        for conflict_id in signature.conflicts_with:
            other = all_matches.get(conflict_id)
            if other is None:
                continue
            if other.confidence >= signature.minimum_score and conflict_id in {
                m.technology.id for m in accepted
            }:
                return True
        return False

    def _ensure_dependencies(
        self,
        signature: TechnologySignature,
        all_matches: dict[str, TechnologyMatch],
        accepted: list[TechnologyMatch],
    ) -> None:
        """Ensure dependency technologies remain detected when parent is accepted."""
        accepted_ids = {match.technology.id for match in accepted}
        for dependency_id in signature.dependencies:
            if dependency_id in accepted_ids:
                continue
            dependency = all_matches.get(dependency_id)
            if dependency is not None and dependency not in accepted:
                accepted.append(dependency)

    def _dedupe_versions(self, matches: list[TechnologyMatch]) -> list[TechnologyMatch]:
        """Keep highest-confidence version when duplicate technology IDs exist."""
        best: dict[str, TechnologyMatch] = {}
        for match in matches:
            existing = best.get(match.technology.id)
            if existing is None or match.confidence > existing.confidence:
                best[match.technology.id] = match
        return sorted(best.values(), key=lambda item: (-item.confidence, item.technology.name))


def resolve_version_conflicts(
    versions: dict[str, VersionResolution],
) -> dict[str, VersionResolution]:
    """Pick best version when multiple resolutions exist for one technology."""
    return versions
