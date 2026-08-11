"""Adapters that feed extractor output into the canonical version resolver."""

from __future__ import annotations

from typing import TYPE_CHECKING

from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.versioning.confidence import score_method
from techspecter.versioning.models import (
    ExtractedVersion,
    TechnologyVersionResult,
    VersionAttributionState,
    VersionConfidenceLevel,
    VersionEvidenceType,
    VersionOwnershipClass,
)

if TYPE_CHECKING:
    from techspecter.fingerprinting.detection.version.candidates import VersionCandidate
    from techspecter.versioning.resolution import PrimaryVersionResolution

_METHOD_TO_SOURCE: dict[VersionEvidenceType, str] = {
    VersionEvidenceType.RUNTIME_CONSTANT: "runtime",
    VersionEvidenceType.FRAMEWORK_OBJECT: "runtime",
    VersionEvidenceType.PACKAGE_IDENTIFIER: "package",
    VersionEvidenceType.PACKAGE_MANIFEST: "manifest",
    VersionEvidenceType.BUILD_METADATA: "build_metadata",
    VersionEvidenceType.METADATA: "metadata",
    VersionEvidenceType.BANNER: "banner",
    VersionEvidenceType.SOURCE_MAP: "sourcemap",
    VersionEvidenceType.ASSET_FILENAME: "filename",
    VersionEvidenceType.TECHNOLOGY_MARKER: "runtime",
    VersionEvidenceType.REFERENCE: "content",
    VersionEvidenceType.GENERIC_LITERAL: "content",
    VersionEvidenceType.UNKNOWN: "unknown",
}


def source_label_for_method(method: VersionEvidenceType) -> str:
    """Map an extractor evidence method to a resolver source label."""
    return _METHOD_TO_SOURCE.get(method, "content")


def _ownership_for_js_method(
    method: VersionEvidenceType,
    *,
    stamped_class: VersionOwnershipClass | None,
    stamped_confidence: float,
) -> tuple[VersionOwnershipClass, float]:
    """Derive technology-scoped ownership that respects extraction method quality.

    Extractors are technology-scoped, but weak reference/literal methods must not
    inherit default OWNED@95 confirmability. Callers may still stamp stronger
    ownership explicitly for strong methods.
    """
    from techspecter.versioning.confidence import method_supports_confirmation

    if not method_supports_confirmation(method):
        # Keep technology scope, but remain below confirmation thresholds.
        return VersionOwnershipClass.ASSOCIATED, min(stamped_confidence, 60.0)

    ownership_class = stamped_class or VersionOwnershipClass.OWNED
    ownership_confidence = stamped_confidence
    if ownership_class == VersionOwnershipClass.OWNED and ownership_confidence < 65.0:
        ownership_confidence = max(ownership_confidence, 95.0)
    return ownership_class, ownership_confidence


def extracted_versions_to_candidates(
    extracted: list[ExtractedVersion] | tuple[ExtractedVersion, ...],
    *,
    technology_id: str,
) -> tuple[VersionCandidate, ...]:
    """Convert JS extractor output into canonical VersionCandidate observations.

    Extractors remain responsible for extraction only. Ownership is technology-scoped
    because each extractor is registered to a single technology_id.
    """
    from techspecter.fingerprinting.detection.version.candidates import VersionCandidate
    from techspecter.versioning.confidence import score_method as score_extraction_method

    candidates: list[VersionCandidate] = []
    seen: set[tuple[str, str, str | None]] = set()
    for index, item in enumerate(extracted):
        source = source_label_for_method(item.method)
        key = (item.version, source, item.source_url or item.filename)
        if key in seen:
            continue
        seen.add(key)
        primary_evidence = item.evidence[0] if item.evidence else None
        method_confidence, _ = score_extraction_method(item.method)
        # Extractor method confidence is the ranking authority for JS observations.
        priority = method_confidence
        version_confidence = (
            item.version_confidence if item.version_confidence is not None else item.confidence
        )
        ownership_class, ownership_confidence = _ownership_for_js_method(
            item.method,
            stamped_class=item.ownership_class,
            stamped_confidence=item.ownership_confidence,
        )
        candidates.append(
            VersionCandidate(
                version=item.version,
                source=source,
                priority=priority,
                technology_id=technology_id,
                evidence_id=item.evidence_id or f"{technology_id}-js-{index}",
                resource=item.source_url or item.filename,
                extractor_id=item.extractor_id,
                metadata={
                    "origin": "js_extractor",
                    "method": item.method.value,
                },
                source_url=item.source_url,
                source_file=item.filename,
                asset_id=item.asset_id,
                evidence_type=item.method.value,
                matched_pattern=(
                    item.matched_pattern
                    or (primary_evidence.pattern if primary_evidence else None)
                ),
                matched_value=(
                    item.matched_value
                    or (primary_evidence.matched_value if primary_evidence else item.version)
                ),
                ownership_class=ownership_class,
                ownership_confidence=ownership_confidence,
                ownership_basis="js_extractor_technology_scope",
                version_confidence=version_confidence,
                technology_confidence=None,
                attribution_state=VersionAttributionState.CANDIDATE,
            ),
        )
    return tuple(candidates)


def resolve_extracted_versions(
    extracted: list[ExtractedVersion] | tuple[ExtractedVersion, ...],
    *,
    technology_id: str,
    technology_confidence: float | None = None,
) -> PrimaryVersionResolution:
    """Run canonical primary/alternate resolution on extractor observations."""
    from techspecter.versioning.resolution import resolve_primary_version

    candidates = extracted_versions_to_candidates(extracted, technology_id=technology_id)
    return resolve_primary_version(
        candidates,
        technology_confidence=technology_confidence,
    )


def technology_version_result_from_resolution(
    *,
    technology_id: str,
    extracted: list[ExtractedVersion] | tuple[ExtractedVersion, ...],
    outcome: PrimaryVersionResolution,
) -> TechnologyVersionResult | None:
    """Build a TechnologyVersionResult from canonical resolution output."""
    if not extracted and outcome.primary_version == UNKNOWN_VERSION:
        return None

    by_version = {item.version: item for item in extracted}
    primary = by_version.get(outcome.primary_version)
    method = primary.method if primary is not None else VersionEvidenceType.UNKNOWN
    if primary is None and extracted:
        method = extracted[0].method
    confidence = outcome.confidence
    if primary is not None:
        confidence = max(confidence, primary.confidence)
    if confidence <= 0.0 and primary is not None:
        confidence = primary.confidence
    _, level = score_method(method)
    if confidence >= 90.0:
        level = VersionConfidenceLevel.HIGH
    elif confidence >= 75.0:
        level = VersionConfidenceLevel.MEDIUM
    else:
        level = VersionConfidenceLevel.LOW

    evidence = list(primary.evidence) if primary is not None else []
    if not evidence:
        for item in extracted:
            if item.version == outcome.primary_version or (
                outcome.primary_version == UNKNOWN_VERSION
                and item.version in outcome.alternate_versions
            ):
                evidence.extend(item.evidence)

    ownership_class = VersionOwnershipClass.OWNED
    if outcome.ownership_class:
        try:
            ownership_class = VersionOwnershipClass(outcome.ownership_class)
        except ValueError:
            ownership_class = VersionOwnershipClass.OWNED

    return TechnologyVersionResult(
        technology_id=technology_id,
        version=outcome.primary_version,
        confidence=confidence,
        confidence_level=level,
        method=method,
        reason=outcome.reason or "Canonical version resolution",
        evidence=evidence,
        candidates_considered=outcome.candidate_count or len(extracted),
        rejected_candidates=list(outcome.rejected_versions),
        attribution_state=outcome.attribution_state,
        ownership_confidence=outcome.ownership_confidence or 0.0,
        ownership_class=ownership_class,
        version_confidence=outcome.version_confidence or confidence,
        alternate_versions=list(outcome.alternate_versions),
        conflict_class=outcome.conflict_class.value,
    )
