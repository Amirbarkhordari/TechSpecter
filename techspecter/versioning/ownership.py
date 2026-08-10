"""Technology-scoped version evidence ownership rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from techspecter.versioning.models import VersionOwnershipClass

if TYPE_CHECKING:
    from techspecter.fingerprinting.evidence.models import Evidence


@dataclass(frozen=True, slots=True)
class VersionOwnershipAssessment:
    """Structured ownership decision for one evidence item and technology."""

    technology_id: str
    ownership_class: VersionOwnershipClass
    ownership_confidence: float
    reason: str
    basis: str


def evidence_owned_by_technology(technology_id: str, item: Evidence) -> bool:
    """Return True when evidence is explicitly attributable to a technology."""
    assessment = classify_version_evidence_ownership(technology_id, item)
    return assessment.ownership_class == VersionOwnershipClass.OWNED


def version_evidence_relevant(
    technology_id: str,
    item: Evidence,
    *,
    matched_evidence_ids: frozenset[str],
) -> bool:
    """Return True when an evidence item may contribute a version for a technology."""
    from techspecter.fingerprinting.evidence.models import EvidenceType

    assessment = classify_version_evidence_ownership(
        technology_id,
        item,
        matched_evidence_ids=matched_evidence_ids,
    )
    if item.evidence_type == EvidenceType.VERSION_CANDIDATE:
        return assessment.ownership_class == VersionOwnershipClass.OWNED

    if assessment.ownership_class in {
        VersionOwnershipClass.OWNED,
        VersionOwnershipClass.ASSOCIATED,
    }:
        return True

    return False


def classify_version_evidence_ownership(
    technology_id: str,
    item: Evidence,
    *,
    matched_evidence_ids: frozenset[str] | None = None,
) -> VersionOwnershipAssessment:
    """Classify whether version evidence belongs to a technology.

    Ownership is technology-scoped. Shared assets do not imply shared ownership.
    """
    from techspecter.fingerprinting.evidence.models import EvidenceType

    tech_id = technology_id.lower()
    matched_ids = matched_evidence_ids or frozenset()

    if item.technology and item.technology.lower() == tech_id:
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.OWNED,
            ownership_confidence=98.0,
            reason="Evidence technology field matches target technology",
            basis="technology_field",
        )

    metadata_tech = str(item.metadata.get("technology", "")).strip().lower()
    if metadata_tech:
        if metadata_tech == tech_id:
            return VersionOwnershipAssessment(
                technology_id=technology_id,
                ownership_class=VersionOwnershipClass.OWNED,
                ownership_confidence=95.0,
                reason="Evidence metadata technology matches target technology",
                basis="metadata_technology",
            )
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.INCIDENTAL,
            ownership_confidence=5.0,
            reason="Evidence metadata technology belongs to a different technology",
            basis="metadata_technology_mismatch",
        )

    runtime_family = str(item.metadata.get("runtime_family", "")).strip().lower()
    if runtime_family:
        if runtime_family == tech_id:
            return VersionOwnershipAssessment(
                technology_id=technology_id,
                ownership_class=VersionOwnershipClass.OWNED,
                ownership_confidence=90.0,
                reason="Evidence runtime family matches target technology",
                basis="runtime_family",
            )
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.INCIDENTAL,
            ownership_confidence=5.0,
            reason="Evidence runtime family belongs to a different technology",
            basis="runtime_family_mismatch",
        )

    package_hint = str(item.metadata.get("package", "")).strip().lower()
    if package_hint and any(token in package_hint for token in _package_tokens(tech_id)):
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.OWNED,
            ownership_confidence=82.0,
            reason="Package metadata token matches target technology",
            basis="package_hint",
        )

    if item.id in matched_ids and item.evidence_type != EvidenceType.VERSION_CANDIDATE:
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.ASSOCIATED,
            ownership_confidence=72.0,
            reason="Evidence participated in technology detection for this technology",
            basis="matched_detection_evidence",
        )

    value_hint = str(item.matched_value or "").strip().lower()
    if value_hint and any(token in value_hint for token in _package_tokens(tech_id)):
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.OWNED,
            ownership_confidence=55.0,
            reason="Matched value contains a technology package token (weak)",
            basis="value_hint",
        )

    if item.id in matched_ids and item.evidence_type == EvidenceType.VERSION_CANDIDATE:
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.INCIDENTAL,
            ownership_confidence=20.0,
            reason="Untagged version candidate matched detection evidence only",
            basis="matched_evidence_version_candidate",
        )

    return VersionOwnershipAssessment(
        technology_id=technology_id,
        ownership_class=VersionOwnershipClass.UNKNOWN,
        ownership_confidence=0.0,
        reason="No technology-scoped ownership signals",
        basis="none",
    )


def ownership_supports_confirmation(assessment: VersionOwnershipAssessment) -> bool:
    """Return True when ownership is strong enough to confirm a version."""
    if assessment.ownership_class == VersionOwnershipClass.OWNED:
        return assessment.ownership_confidence >= 65.0
    if assessment.ownership_class == VersionOwnershipClass.ASSOCIATED:
        return assessment.ownership_confidence >= 70.0
    return False


def _package_tokens(technology_id: str) -> tuple[str, ...]:
    normalized = technology_id.lower().replace("_", "-")
    if normalized.startswith("package:"):
        normalized = normalized.removeprefix("package:")
    tokens = {normalized, normalized.replace("-", ""), normalized.replace("-", ".")}
    if normalized == "nextjs":
        tokens.add("next")
    if normalized == "react":
        tokens.update({"react-dom", "reactdom"})
    if normalized == "material-ui":
        tokens.update({"mui", "@mui"})
    return tuple(tokens)
