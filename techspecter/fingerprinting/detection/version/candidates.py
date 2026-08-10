"""Version candidate collection without premature discarding."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.version.priorities import (
    priority_for_source,
    source_from_evidence_type,
)
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceType
from techspecter.fingerprinting.signatures.models import TechnologySignature
from techspecter.versioning.ownership import version_evidence_relevant
from techspecter.versioning.validator import validate_and_normalize

_VERSION_RE = re.compile(r"^\d{1,4}(?:\.\d{1,4}){0,3}(?:[-+][\w.-]+)?$")
_PACKAGE_VERSION_PATH = re.compile(
    r"node_modules/(?:@?[\w.-]+/[\w.-]+|@?[\w.-]+)@(\d{1,4}(?:\.\d{1,4}){0,3}(?:[-+][\w.-]+)?)"
)


@dataclass(frozen=True, slots=True)
class VersionCandidate:
    """A single version observation linked to provenance."""

    version: str
    source: str
    priority: float
    technology_id: str | None = None
    evidence_id: str | None = None
    resource: str | None = None
    extractor_id: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class VersionCandidateCollector:
    """Collect version candidates from all evidence for one technology."""

    def collect(
        self,
        signature: TechnologySignature,
        *,
        evidence_items: tuple[Evidence, ...],
        matched_evidence_ids: frozenset[str] | None = None,
        matched_resources: frozenset[str] | None = None,
    ) -> tuple[VersionCandidate, ...]:
        """Gather all version candidates without filtering by selection."""
        candidates: list[VersionCandidate] = []
        seen: set[tuple[str, str, str | None]] = set()
        _ = matched_resources
        owned_evidence_ids = matched_evidence_ids or frozenset()

        for item in evidence_items:
            self._collect_from_evidence(
                signature,
                item,
                candidates,
                seen,
                matched_evidence_ids=owned_evidence_ids,
            )

        for spec in signature.version_extractors:
            if not spec.enabled:
                continue
            for item in evidence_items:
                if not version_evidence_relevant(
                    signature.id,
                    item,
                    matched_evidence_ids=owned_evidence_ids,
                ):
                    continue
                self._collect_from_extractor(
                    signature,
                    spec,
                    item,
                    candidates,
                    seen,
                )

        return tuple(candidates)

    def _collect_from_evidence(
        self,
        signature: TechnologySignature,
        item: Evidence,
        candidates: list[VersionCandidate],
        seen: set[tuple[str, str, str | None]],
        *,
        matched_evidence_ids: frozenset[str],
    ) -> None:
        """Extract version candidates from a single evidence item."""
        if not version_evidence_relevant(
            signature.id,
            item,
            matched_evidence_ids=matched_evidence_ids,
        ):
            return

        source = str(item.metadata.get("origin", item.category or ""))
        if not source or source == item.category:
            source = source_from_evidence_type(item.evidence_type.value)

        metadata_version = item.metadata.get("version")
        if isinstance(metadata_version, str):
            self._add_candidate(
                candidates,
                seen,
                technology_id=signature.id,
                version=metadata_version,
                source=source,
                evidence_id=item.id,
                resource=item.url or item.file,
                metadata={"origin": "metadata.version"},
            )

        value = (item.matched_value or "").strip()
        if not value:
            return

        if item.evidence_type == EvidenceType.VERSION_CANDIDATE:
            self._add_candidate(
                candidates,
                seen,
                technology_id=signature.id,
                version=value,
                source=source,
                evidence_id=item.id,
                resource=item.url or item.file,
                metadata={"origin": "version_candidate"},
            )
            return

        for match in _PACKAGE_VERSION_PATH.finditer(value):
            self._add_candidate(
                candidates,
                seen,
                technology_id=signature.id,
                version=match.group(1),
                source="package",
                evidence_id=item.id,
                resource=item.url or item.file,
                metadata={"origin": "package_path"},
            )

        if item.evidence_type in {
            EvidenceType.BANNER,
            EvidenceType.MANIFEST,
            EvidenceType.RUNTIME_PATTERN,
            EvidenceType.PACKAGE_REFERENCE,
            EvidenceType.HTTP_HEADER,
            EvidenceType.SOURCE_MAP_METADATA,
        }:
            self._extract_embedded_versions(
                signature,
                value,
                source=source,
                evidence_id=item.id,
                resource=item.url or item.file,
                candidates=candidates,
                seen=seen,
            )

    def _collect_from_extractor(
        self,
        signature: TechnologySignature,
        spec: object,
        item: Evidence,
        candidates: list[VersionCandidate],
        seen: set[tuple[str, str, str | None]],
    ) -> None:
        """Apply signature version extractors to evidence haystacks."""
        from techspecter.fingerprinting.signatures.models import VersionExtractorSpec

        if not isinstance(spec, VersionExtractorSpec):
            return
        haystack = (item.matched_value or "") + " " + str(item.metadata)
        for match in re.finditer(spec.pattern, haystack, re.IGNORECASE):
            version = match.group(1) if match.lastindex else match.group(0)
            priority = priority_for_source(spec.source) * (spec.weight / 100.0)
            self._add_candidate(
                candidates,
                seen,
                technology_id=signature.id,
                version=version,
                source=spec.source,
                priority_override=priority,
                evidence_id=item.id,
                resource=item.url or item.file,
                extractor_id=spec.id,
                metadata={"pattern": spec.pattern},
            )

    def _extract_embedded_versions(
        self,
        signature: TechnologySignature,
        value: str,
        *,
        source: str,
        evidence_id: str,
        resource: str | None,
        candidates: list[VersionCandidate],
        seen: set[tuple[str, str, str | None]],
    ) -> None:
        """Extract semver-like tokens embedded in evidence values."""
        for spec in signature.version_extractors:
            if not spec.enabled:
                continue
            match = re.search(spec.pattern, value, re.IGNORECASE)
            if match is None:
                continue
            version = match.group(1) if match.lastindex else match.group(0)
            priority = priority_for_source(spec.source) * (spec.weight / 100.0)
            self._add_candidate(
                candidates,
                seen,
                technology_id=signature.id,
                version=version,
                source=spec.source,
                priority_override=priority,
                evidence_id=evidence_id,
                resource=resource,
                extractor_id=spec.id,
                metadata={"embedded": True},
            )

    def _add_candidate(
        self,
        candidates: list[VersionCandidate],
        seen: set[tuple[str, str, str | None]],
        *,
        technology_id: str,
        version: str,
        source: str,
        evidence_id: str | None = None,
        resource: str | None = None,
        extractor_id: str | None = None,
        priority_override: float | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        """Normalize and store a version candidate."""
        normalized = normalize_version(version)
        if normalized is None:
            return
        key = (normalized, source, evidence_id)
        if key in seen:
            return
        seen.add(key)
        priority = (
            priority_override if priority_override is not None else priority_for_source(source)
        )
        candidates.append(
            VersionCandidate(
                version=normalized,
                source=source,
                priority=priority,
                technology_id=technology_id,
                evidence_id=evidence_id,
                resource=resource,
                extractor_id=extractor_id,
                metadata=dict(metadata or {}),
            ),
        )


def normalize_version(raw: str) -> str | None:
    """Normalize and validate a version string."""
    return validate_and_normalize(raw)
