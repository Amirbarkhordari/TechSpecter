"""Generate technology candidates from indexed structured evidence."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass

from techspecter.fingerprinting.detection.candidates.indexer import EvidenceIndex
from techspecter.fingerprinting.detection.candidates.mappings import (
    GENERIC_MARKER_BLOCKLIST,
    is_relative_module,
    is_structured_package_evidence,
    is_url_like_module,
    lookup_bundle_marker,
    lookup_http_header,
    lookup_runtime_family,
    normalize_package_key,
    resolve_package_identity,
)
from techspecter.fingerprinting.detection.candidates.models import (
    CandidateStatus,
    DiscoveryBasis,
    IdentityKind,
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
        EvidenceType.SOURCE_MAP_METADATA,
    },
)


@dataclass
class _BucketMeta:
    name: str
    category: str
    identity_kind: IdentityKind
    identity_source: str
    knowledge_matched: bool
    version_hint: str | None = None


@dataclass
class CandidateGenerator:
    """Produce technology candidates from strong structured evidence only."""

    min_confidence_hint: float = 40.0

    def generate(self, index: EvidenceIndex) -> list[TechnologyCandidate]:
        """Generate candidates keyed by technology identity."""
        buckets: dict[str, list[tuple[Evidence, DiscoveryBasis, str]]] = defaultdict(list)
        metas: dict[str, _BucketMeta] = {}

        for evidence_list in index.by_package.values():
            for item in evidence_list:
                if item.evidence_type == EvidenceType.VERSION_CANDIDATE:
                    # Attached in a later pass once package identities exist.
                    continue
                resolved = self._from_package_evidence(item)
                if resolved is None:
                    continue
                tech_id, meta, basis, reason = resolved
                buckets[tech_id].append((item, basis, reason))
                self._merge_meta(metas, tech_id, meta)

        for family, evidence_list in index.by_runtime_family.items():
            mapping = lookup_runtime_family(family)
            if mapping is None:
                continue
            tech_id, name, category = mapping
            for item in evidence_list:
                buckets[tech_id].append(
                    (item, DiscoveryBasis.RUNTIME, f"runtime family '{family}'"),
                )
            self._merge_meta(
                metas,
                tech_id,
                _BucketMeta(
                    name=name,
                    category=category,
                    identity_kind=IdentityKind.RUNTIME,
                    identity_source="RUNTIME_PATTERN",
                    knowledge_matched=True,
                ),
            )

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
            self._merge_meta(
                metas,
                tech_id,
                _BucketMeta(
                    name=name,
                    category=category,
                    identity_kind=IdentityKind.BUNDLE,
                    identity_source="BUNDLE_MARKER",
                    knowledge_matched=True,
                ),
            )

        for module, evidence_list in index.by_import.items():
            for item in evidence_list:
                if item.evidence_type not in {
                    EvidenceType.IMPORT_EXPORT,
                    EvidenceType.AST_EXTRACTION,
                }:
                    continue
                if item.metadata.get("kind") not in {None, "import"}:
                    continue
                resolved = self._from_package_value(
                    module,
                    item=item,
                    basis=DiscoveryBasis.IMPORT,
                    identity_source="IMPORT_EXPORT",
                )
                if resolved is None:
                    continue
                tech_id, meta, basis, reason = resolved
                buckets[tech_id].append((item, basis, reason))
                self._merge_meta(metas, tech_id, meta)

        for _header, evidence_list in index.by_http_header.items():
            for item in evidence_list:
                header = str(
                    item.metadata.get("header") or item.matched_pattern or "",
                ).strip()
                value = item.matched_value or ""
                mapping = lookup_http_header(header, value)
                if mapping is None:
                    continue
                tech_id, name, category = mapping
                buckets[tech_id].append(
                    (item, DiscoveryBasis.HTTP, f"HTTP header '{header}'"),
                )
                self._merge_meta(
                    metas,
                    tech_id,
                    _BucketMeta(
                        name=name,
                        category=category,
                        identity_kind=IdentityKind.HTTP,
                        identity_source="HTTP_HEADER",
                        knowledge_matched=True,
                    ),
                )

        for item in index.by_type.get(EvidenceType.SOURCE_MAP_METADATA.value, []):
            value = item.matched_value or ""
            if "node_modules/" not in value.replace("\\", "/").lower():
                continue
            resolved = self._from_package_value(
                value,
                item=item,
                basis=DiscoveryBasis.SOURCE_MAP,
                identity_source="SOURCE_MAP_METADATA",
            )
            if resolved is None:
                continue
            tech_id, meta, basis, reason = resolved
            buckets[tech_id].append((item, basis, reason))
            self._merge_meta(metas, tech_id, meta)

        # Attach owned version evidence after package identities are established.
        for item in index.by_type.get(EvidenceType.VERSION_CANDIDATE.value, []):
            self._attach_version_evidence(buckets, metas, item)

        candidates: list[TechnologyCandidate] = []
        for tech_id, entries in buckets.items():
            meta = metas.get(tech_id)
            if meta is None:
                continue
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
            confidence = self._score(
                evidence_items,
                multi_signal=len(bases) >= 2,
                knowledge_matched=meta.knowledge_matched,
            )
            version_hint = meta.version_hint or self._version_hint(evidence_items, tech_id)
            source_file = next((item.file for item in evidence_items if item.file), None)
            source_url = next((item.url for item in evidence_items if item.url), None)
            candidates.append(
                TechnologyCandidate(
                    technology_id=tech_id,
                    name=meta.name,
                    category=meta.category,
                    status=CandidateStatus.CANDIDATE,
                    evidence=tuple(evidence_items),
                    source_url=source_url,
                    source_file=source_file,
                    confidence=confidence,
                    discovery_basis=primary_basis,
                    discovery_reason="; ".join(reasons[:5]),
                    supporting_evidence_ids=tuple(item.id for item in evidence_items),
                    version_hint=version_hint,
                    identity_kind=meta.identity_kind,
                    identity_source=meta.identity_source,
                    knowledge_matched=meta.knowledge_matched,
                ),
            )
            logger.debug(
                "Generated technology candidate '%s' (%s, knowledge=%s, confidence %.1f)",
                tech_id,
                primary_basis.value,
                meta.knowledge_matched,
                confidence,
            )
        return sorted(candidates, key=lambda item: (-item.confidence, item.technology_id))

    def _attach_version_evidence(
        self,
        buckets: dict[str, list[tuple[Evidence, DiscoveryBasis, str]]],
        metas: dict[str, _BucketMeta],
        item: Evidence,
    ) -> None:
        """Attach package-owned version evidence to an existing package identity."""
        meta_package = str(item.metadata.get("package", "")).strip()
        meta_tech = str(item.metadata.get("technology", "")).strip().lower()
        tech_id: str | None = None
        if meta_tech and meta_tech in buckets:
            tech_id = meta_tech
        elif meta_package:
            resolved = resolve_package_identity(meta_package)
            if resolved is not None:
                candidate_id = resolved[0]
                if candidate_id in buckets:
                    tech_id = candidate_id
        if tech_id is None:
            return
        buckets[tech_id].append(
            (item, DiscoveryBasis.PACKAGE, "owned package version evidence"),
        )
        version = item.matched_value
        if version:
            existing = metas.get(tech_id)
            if existing is not None and existing.version_hint is None:
                self._merge_meta(
                    metas,
                    tech_id,
                    _BucketMeta(
                        name=existing.name,
                        category=existing.category,
                        identity_kind=existing.identity_kind,
                        identity_source=existing.identity_source,
                        knowledge_matched=existing.knowledge_matched,
                        version_hint=version,
                    ),
                )

    def _from_package_evidence(
        self,
        item: Evidence,
    ) -> tuple[str, _BucketMeta, DiscoveryBasis, str] | None:
        if item.evidence_type == EvidenceType.PACKAGE_MARKER:
            value = item.matched_value or ""
            mapping = lookup_bundle_marker(value)
            if mapping is not None:
                tech_id, name, category = mapping
                return (
                    tech_id,
                    _BucketMeta(
                        name=name,
                        category=category,
                        identity_kind=IdentityKind.BUNDLE,
                        identity_source="PACKAGE_MARKER",
                        knowledge_matched=True,
                    ),
                    DiscoveryBasis.BUNDLE,
                    f"structured marker '{value}'",
                )
            # Non-specific package markers (e.g. "import ... from") are not identities
            if not is_structured_package_evidence(item):
                return None
        if not is_structured_package_evidence(item) and item.evidence_type != EvidenceType.PACKAGE_REFERENCE:
            return None
        value = item.matched_value or ""
        return self._from_package_value(
            value,
            item=item,
            basis=DiscoveryBasis.PACKAGE,
            identity_source=item.evidence_type.value.upper(),
        )

    def _from_package_value(
        self,
        value: str,
        *,
        item: Evidence,
        basis: DiscoveryBasis,
        identity_source: str,
    ) -> tuple[str, _BucketMeta, DiscoveryBasis, str] | None:
        if is_relative_module(value) or is_url_like_module(value):
            return None
        key = normalize_package_key(value)
        if not key:
            return None
        if key in GENERIC_MARKER_BLOCKLIST and item.evidence_type != EvidenceType.PACKAGE_REFERENCE:
            return None
        resolved = resolve_package_identity(value)
        if resolved is None:
            return None
        tech_id, name, category, knowledge_matched = resolved
        version_hint = None
        meta_version = item.metadata.get("version")
        meta_package = str(item.metadata.get("package", "")).strip().lower()
        if isinstance(meta_version, str) and meta_version:
            package_key = key
            if not meta_package or normalize_package_key(meta_package) == package_key:
                version_hint = meta_version
        return (
            tech_id,
            _BucketMeta(
                name=name,
                category=category,
                identity_kind=(
                    IdentityKind.CATALOG if knowledge_matched else IdentityKind.PACKAGE
                ),
                identity_source=identity_source,
                knowledge_matched=knowledge_matched,
                version_hint=version_hint,
            ),
            basis,
            f"package '{key}'",
        )

    def _merge_meta(
        self,
        metas: dict[str, _BucketMeta],
        tech_id: str,
        meta: _BucketMeta,
    ) -> None:
        existing = metas.get(tech_id)
        if existing is None:
            metas[tech_id] = meta
            return
        # Prefer catalog enrichment over evidence-native identity.
        if meta.knowledge_matched and not existing.knowledge_matched:
            metas[tech_id] = meta
            return
        if existing.version_hint is None and meta.version_hint is not None:
            metas[tech_id] = _BucketMeta(
                name=existing.name,
                category=existing.category,
                identity_kind=existing.identity_kind,
                identity_source=existing.identity_source,
                knowledge_matched=existing.knowledge_matched,
                version_hint=meta.version_hint,
            )

    def _version_hint(self, items: list[Evidence], tech_id: str) -> str | None:
        package_key = tech_id.removeprefix("package:")
        for item in items:
            if item.evidence_type != EvidenceType.VERSION_CANDIDATE:
                continue
            version = item.matched_value
            if not version:
                continue
            meta_package = str(item.metadata.get("package", "")).strip().lower()
            meta_tech = str(item.metadata.get("technology", "")).strip().lower()
            if meta_tech and meta_tech == tech_id:
                return version
            if meta_package and normalize_package_key(meta_package) == package_key:
                return version
        return None

    def _score(
        self,
        items: list[Evidence],
        *,
        multi_signal: bool,
        knowledge_matched: bool,
    ) -> float:
        weights = {
            EvidenceType.PACKAGE_REFERENCE: 85.0,
            EvidenceType.RUNTIME_PATTERN: 80.0,
            EvidenceType.IMPORT_EXPORT: 70.0,
            EvidenceType.BUNDLE_MARKER: 75.0,
            EvidenceType.BUNDLE_RUNTIME: 75.0,
            EvidenceType.HTTP_HEADER: 70.0,
            EvidenceType.PACKAGE_MARKER: 55.0,
            EvidenceType.AST_EXTRACTION: 50.0,
            EvidenceType.SOURCE_MAP_METADATA: 65.0,
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
        # Evidence-native packages need slightly more support to confirm.
        open_penalty = 0.0 if knowledge_matched else 5.0
        return min(100.0, round(best + type_bonus + multi_bonus + hint_bonus - open_penalty, 1))

    def _dedupe_evidence(self, items: list[Evidence]) -> list[Evidence]:
        seen: set[str] = set()
        deduped: list[Evidence] = []
        for item in items:
            if item.id in seen:
                continue
            seen.add(item.id)
            deduped.append(item)
        return deduped
