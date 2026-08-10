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
        matched_resources: frozenset[str] | None = None,
    ) -> tuple[VersionCandidate, ...]:
        """Gather all version candidates without filtering by selection."""
        candidates: list[VersionCandidate] = []
        seen: set[tuple[str, str, str | None]] = set()
        resources = matched_resources or frozenset()

        for item in evidence_items:
            self._collect_from_evidence(
                signature,
                item,
                candidates,
                seen,
                resources=resources,
            )

        for spec in signature.version_extractors:
            if not spec.enabled:
                continue
            for item in evidence_items:
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
        resources: frozenset[str],
    ) -> None:
        """Extract version candidates from a single evidence item."""
        if not self._evidence_relevant(signature, item, resources=resources):
            return

        source = str(item.metadata.get("origin", item.category or ""))
        if not source or source == item.category:
            source = source_from_evidence_type(item.evidence_type.value)

        metadata_version = item.metadata.get("version")
        if isinstance(metadata_version, str):
            self._add_candidate(
                candidates,
                seen,
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
        if not self._haystack_relevant(signature, haystack, item):
            return
        for match in re.finditer(spec.pattern, haystack, re.IGNORECASE):
            version = match.group(1) if match.lastindex else match.group(0)
            priority = priority_for_source(spec.source) * (spec.weight / 100.0)
            self._add_candidate(
                candidates,
                seen,
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
                evidence_id=evidence_id,
                resource=resource,
                extractor_id=extractor_id,
                metadata=dict(metadata or {}),
            ),
        )

    def _evidence_relevant(
        self,
        signature: TechnologySignature,
        item: Evidence,
        *,
        resources: frozenset[str],
    ) -> bool:
        """Return whether evidence may contain version data for the technology."""
        if item.technology and item.technology.lower() == signature.id.lower():
            return True
        metadata_tech = str(item.metadata.get("technology", "")).lower()
        if metadata_tech and metadata_tech == signature.id.lower():
            return True
        runtime_family = str(item.metadata.get("runtime_family", "")).lower()
        if runtime_family and runtime_family == signature.id.lower():
            return True
        package_hint = str(item.metadata.get("package", item.matched_value or "")).lower()
        identifiers = _technology_identifiers(signature)
        if any(identifier in package_hint for identifier in identifiers):
            return True
        resource = item.url or item.file
        if resources and resource and resource in resources:
            return True
        if item.evidence_type == EvidenceType.VERSION_CANDIDATE and resources:
            resource = item.url or item.file
            return resource is None or resource in resources or not resources
        haystack = ((item.matched_value or "") + " " + str(item.metadata)).lower()
        return any(identifier in haystack for identifier in identifiers)

    def _haystack_relevant(
        self,
        signature: TechnologySignature,
        haystack: str,
        item: Evidence,
    ) -> bool:
        """Return whether extractor haystack is linked to the technology."""
        if self._evidence_relevant(signature, item, resources=frozenset()):
            return True
        lowered = haystack.lower()
        return any(identifier in lowered for identifier in _technology_identifiers(signature))


def normalize_version(raw: str) -> str | None:
    """Normalize and validate a version string."""
    return validate_and_normalize(raw)


def _technology_identifiers(signature: TechnologySignature) -> tuple[str, ...]:
    """Return lowercase identifiers used to link evidence to a technology."""
    names = {signature.id.lower(), signature.name.lower()}
    names.update(alias.lower() for alias in signature.aliases)
    if signature.vendor:
        names.add(signature.vendor.lower())
    return tuple(names)
