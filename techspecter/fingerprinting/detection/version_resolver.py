"""Version resolution engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.weights import ScoringWeights
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceType
from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.fingerprinting.signatures.models import TechnologySignature

from .models import RuleMatch, VersionResolution

_VERSION_RE = re.compile(r"^\d{1,4}(?:\.\d{1,4}){0,3}(?:[-+][\w.-]+)?$")
_SOURCE_WEIGHTS = {
    "package": 100.0,
    "banner": 90.0,
    "manifest": 85.0,
    "metadata": 80.0,
    "runtime": 75.0,
    "content": 60.0,
    "bundle": 55.0,
    "regex": 40.0,
}


@dataclass(slots=True)
class VersionResolutionEngine:
    """Resolve version candidates collected during evidence analysis."""

    weights: ScoringWeights = field(default_factory=ScoringWeights)

    def resolve(
        self,
        signature: TechnologySignature,
        *,
        evidence_items: tuple[Evidence, ...],
        matched_rules: tuple[RuleMatch, ...],
    ) -> VersionResolution:
        """Select the best supported version for a technology."""
        candidates = self._collect_candidates(signature, evidence_items, matched_rules)
        if not candidates:
            return VersionResolution(
                version=UNKNOWN_VERSION,
                confidence=0.0,
                source="none",
                reason="No version candidates matched technology extractors",
            )

        ranked = sorted(candidates, key=lambda item: (-item[1], item[0]))
        best_version, best_score, best_source = ranked[0]
        rejected = tuple(sorted({item[0] for item in ranked[1:]}))
        return VersionResolution(
            version=best_version,
            confidence=min(100.0, best_score),
            source=best_source,
            reason=f"Selected highest-ranked version candidate from {best_source}",
            rejected_candidates=rejected,
        )

    def _collect_candidates(
        self,
        signature: TechnologySignature,
        evidence_items: tuple[Evidence, ...],
        matched_rules: tuple[RuleMatch, ...],
    ) -> list[tuple[str, float, str]]:
        """Collect and rank version candidates."""
        candidates: list[tuple[str, float, str]] = []
        seen: set[str] = set()

        for item in evidence_items:
            if item.evidence_type != EvidenceType.VERSION_CANDIDATE:
                continue
            value = (item.matched_value or "").strip()
            if not value or not _VERSION_RE.match(value):
                continue
            if value in seen:
                continue
            if not self._candidate_supported(signature, value, item, matched_rules):
                continue
            seen.add(value)
            source = str(item.metadata.get("origin", item.category or "content"))
            weight = _SOURCE_WEIGHTS.get(source, 50.0)
            candidates.append((value, weight, source))

        for spec in signature.version_extractors:
            if not spec.enabled:
                continue
            for item in evidence_items:
                haystack = (item.matched_value or "") + " " + str(item.metadata)
                match = re.search(spec.pattern, haystack, re.IGNORECASE)
                if match is None:
                    continue
                version = match.group(1) if match.lastindex else match.group(0)
                if not _VERSION_RE.match(version) or version in seen:
                    continue
                seen.add(version)
                weight = spec.weight * _SOURCE_WEIGHTS.get(spec.source, 50.0) / 100.0
                candidates.append((version, weight, spec.source))

        return candidates

    def _candidate_supported(
        self,
        signature: TechnologySignature,
        version: str,
        item: Evidence,
        matched_rules: tuple[RuleMatch, ...],
    ) -> bool:
        """Return whether a version candidate is plausibly linked to the technology."""
        if signature.version_extractors:
            return any(
                re.search(
                    spec.pattern,
                    (item.matched_value or "") + " " + str(item.metadata),
                    re.IGNORECASE,
                )
                for spec in signature.version_extractors
                if spec.enabled
            )
        context = " ".join(
            [
                *(match.matched_text.lower() for match in matched_rules),
                signature.id.lower(),
                signature.name.lower(),
            ],
        )
        return (
            signature.id.lower() in context
            or signature.name.lower() in context
            or bool(matched_rules)
        )
