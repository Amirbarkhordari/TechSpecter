"""Generate technology candidates from indexed structured evidence."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass

from techspecter.fingerprinting.detection.candidates.indexer import EvidenceIndex
from techspecter.fingerprinting.detection.candidates.mappings import (
    GENERIC_MARKER_BLOCKLIST,
    lookup_bundle_marker,
    lookup_http_header,
    lookup_package,
    lookup_runtime_family,
    normalize_package_key,
)
from techspecter.fingerprinting.detection.candidates.models import (
    CandidateStatus,
    DiscoveryBasis,
    TechnologyCandidate,
)
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceType

logger = logging.getLogger(__name__)

_STRONG_TYPES = frozenset(
    {
        EvidenceType.PACKAGE_REFERENCE,
        EvidenceType.RUNTIME_PATTERN,
        EvidenceType.BUNDLE_MARKER,
        EvidenceType.BUNDLE_RUNTIME,
        EvidenceType.HTTP_HEADER,
        EvidenceType.IMPORT_EXPORT,
    },
)


@dataclass
class CandidateGenerator:
    """Produce technology candidates from strong structured evidence only."""

    min_confidence_hint: float = 40.0

    def generate(self, index: EvidenceIndex) -> list[TechnologyCandidate]:
        """Generate candidates keyed by technology identity."""
        buckets: dict[str, list[tuple[Evidence, DiscoveryBasis, str]]] = defaultdict(list)
        names: dict[str, tuple[str, str]] = {}

        for evidence_list in index.by_package.values():
            for item in evidence_list:
                mapping = self._from_package(item)
                if mapping is None:
                    continue
                tech_id, name, category, basis, reason = mapping
                buckets[tech_id].append((item, basis, reason))
                names[tech_id] = (name, category)

        for family, evidence_list in index.by_runtime_family.items():
            mapping = lookup_runtime_family(family)
            if mapping is None:
                continue
            tech_id, name, category = mapping
            for item in evidence_list:
                buckets[tech_id].append(
                    (item, DiscoveryBasis.RUNTIME, f"runtime family '{family}'"),
                )
            names[tech_id] = (name, category)

        for marker, evidence_list in index.by_bundle_marker.items():
            if marker.lower() in GENERIC_MARKER_BLOCKLIST:
                continue
            mapping = lookup_bundle_marker(marker)
            if mapping is None:
                continue
            tech_id, name, category = mapping
            for item in evidence_list:
                buckets[tech_id].append(
                    (item, DiscoveryBasis.BUNDLE, f"bundle marker '{marker}'"),
                )
            names[tech_id] = (name, category)

        for module, evidence_list in index.by_import.items():
            mapping = lookup_package(module)
            if mapping is None:
                continue
            tech_id, name, category = mapping
            for item in evidence_list:
                if item.evidence_type not in {
                    EvidenceType.IMPORT_EXPORT,
                    EvidenceType.AST_EXTRACTION,
                }:
                    continue
                # Only treat import-kind AST/import evidence as discovery
                kind = item.metadata.get("kind")
                if kind not in {None, "import"}:
                    continue
                buckets[tech_id].append(
                    (item, DiscoveryBasis.IMPORT, f"import module '{module}'"),
                )
            names[tech_id] = (name, category)

        for header, evidence_list in index.by_http_header.items():
            for item in evidence_list:
                value = item.matched_value or ""
                mapping = lookup_http_header(header, value)
                if mapping is None:
                    continue
                tech_id, name, category = mapping
                buckets[tech_id].append(
                    (item, DiscoveryBasis.HTTP, f"HTTP header '{header}'"),
                )
                names[tech_id] = (name, category)

        candidates: list[TechnologyCandidate] = []
        for tech_id, entries in buckets.items():
            evidence_items = self._dedupe_evidence([item for item, _, _ in entries])
            if not evidence_items:
                continue
            if not any(item.evidence_type in _STRONG_TYPES for item in evidence_items):
                continue
            bases = {basis for _, basis, _ in entries}
            primary_basis = (
                DiscoveryBasis.MULTI_SIGNAL if len(bases) >= 2 else next(iter(bases))
            )
            reasons = sorted({reason for _, _, reason in entries})
            name, category = names[tech_id]
            confidence = self._score(evidence_items, multi_signal=len(bases) >= 2)
            source_file = next((item.file for item in evidence_items if item.file), None)
            source_url = next((item.url for item in evidence_items if item.url), None)
            candidates.append(
                TechnologyCandidate(
                    technology_id=tech_id,
                    name=name,
                    category=category,
                    status=CandidateStatus.CANDIDATE,
                    evidence=tuple(evidence_items),
                    source_url=source_url,
                    source_file=source_file,
                    confidence=confidence,
                    discovery_basis=primary_basis,
                    discovery_reason="; ".join(reasons[:5]),
                    supporting_evidence_ids=tuple(item.id for item in evidence_items),
                ),
            )
            logger.debug(
                "Generated technology candidate '%s' (%s, confidence %.1f)",
                tech_id,
                primary_basis.value,
                confidence,
            )
        return sorted(candidates, key=lambda item: (-item.confidence, item.technology_id))

    def _from_package(
        self,
        item: Evidence,
    ) -> tuple[str, str, str, DiscoveryBasis, str] | None:
        value = item.matched_value or ""
        if not value:
            return None
        key = normalize_package_key(value)
        if key in GENERIC_MARKER_BLOCKLIST:
            # Bare generic tokens are not package discovery unless PACKAGE_REFERENCE
            if item.evidence_type != EvidenceType.PACKAGE_REFERENCE:
                return None
            # Still block ultra-generic bare names that aren't real package paths
            if "/" not in value and key in {"react", "vue", "angular", "bootstrap", "webpack"}:
                # PACKAGE_REFERENCE with exact package name is structured — allow via lookup
                pass
        mapping = lookup_package(value)
        if mapping is None:
            mapping = lookup_bundle_marker(value)
            if mapping is None:
                return None
            tech_id, name, category = mapping
            return (
                tech_id,
                name,
                category,
                DiscoveryBasis.BUNDLE,
                f"structured marker '{value}'",
            )
        tech_id, name, category = mapping
        if item.evidence_type == EvidenceType.PACKAGE_MARKER:
            # Markers like "import ... from" alone are not technology-specific
            if lookup_bundle_marker(value) is None and "/" not in value:
                # webpack-specific package markers still map via lookup_package
                if tech_id not in {"webpack"} and value.lower() in GENERIC_MARKER_BLOCKLIST:
                    return None
        return tech_id, name, category, DiscoveryBasis.PACKAGE, f"package '{key}'"

    def _score(self, items: list[Evidence], *, multi_signal: bool) -> float:
        weights = {
            EvidenceType.PACKAGE_REFERENCE: 85.0,
            EvidenceType.RUNTIME_PATTERN: 80.0,
            EvidenceType.IMPORT_EXPORT: 70.0,
            EvidenceType.BUNDLE_MARKER: 75.0,
            EvidenceType.BUNDLE_RUNTIME: 75.0,
            EvidenceType.HTTP_HEADER: 70.0,
            EvidenceType.PACKAGE_MARKER: 55.0,
            EvidenceType.AST_EXTRACTION: 50.0,
        }
        best = max(
            (weights.get(item.evidence_type, 40.0) for item in items),
            default=40.0,
        )
        type_bonus = min(15.0, (len({item.evidence_type for item in items}) - 1) * 5.0)
        multi_bonus = 10.0 if multi_signal else 0.0
        hint_bonus = min(
            5.0,
            max((item.confidence_hint for item in items), default=0.0) / 20.0,
        )
        return min(100.0, round(best + type_bonus + multi_bonus + hint_bonus, 1))

    def _dedupe_evidence(self, items: list[Evidence]) -> list[Evidence]:
        seen: set[str] = set()
        deduped: list[Evidence] = []
        for item in items:
            if item.id in seen:
                continue
            seen.add(item.id)
            deduped.append(item)
        return deduped
