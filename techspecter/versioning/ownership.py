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


# Methods that prove the library is present without needing asset-name affinity.
_SELF_PROVING_METHODS = frozenset(
    {
        "runtime_constant",
        "framework_object",
        "package_identifier",
        "package_manifest",
        "build_metadata",
        "technology_marker",
    },
)


def asset_affinity_for_technology(
    technology_id: str,
    *,
    filename: str | None = None,
    source_url: str | None = None,
) -> float:
    """Return 0–100 affinity between an asset identity and a technology id.

    Generic token matching only — no technology-specific branches beyond the
    shared package-token helpers used elsewhere for ownership.
    """
    tokens = _package_tokens(technology_id)
    file_part = (filename or "").lower()
    url_part = (source_url or "").lower()
    haystack = f"{file_part} {url_part}".strip()
    if not haystack:
        return 0.0

    best = 0.0
    for token in tokens:
        if len(token) < 2:
            continue
        if token in file_part:
            best = max(best, 95.0)
        elif f"/{token}" in url_part or f"{token}@" in url_part or f"{token}-" in url_part:
            best = max(best, 90.0)
        elif token in url_part:
            best = max(best, 75.0)
    return best


def method_requires_asset_affinity(method: str | None) -> bool:
    """Return True when a method needs asset affinity to confirm ownership."""
    if not method:
        return False
    return method.strip().lower() not in _SELF_PROVING_METHODS


def js_extraction_ownership(
    technology_id: str,
    *,
    method: str,
    filename: str | None = None,
    source_url: str | None = None,
    stamped_class: VersionOwnershipClass | None = None,
    stamped_confidence: float = 95.0,
) -> VersionOwnershipAssessment:
    """Classify JS-extractor ownership using method strength and asset affinity.

    Extractors are technology-scoped, but a banner/filename hit inside an
    unrelated asset must not inherit confirmable OWNED ownership. Self-proving
    methods (runtime/package/framework) remain strongly owned.
    """
    from techspecter.versioning.confidence import method_supports_confirmation

    if not method_supports_confirmation(method):
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.ASSOCIATED,
            ownership_confidence=min(stamped_confidence, 60.0),
            reason="Weak extraction method remains associated, not confirmable",
            basis="js_weak_method",
        )

    if not method_requires_asset_affinity(method):
        ownership_class = stamped_class or VersionOwnershipClass.OWNED
        ownership_confidence = stamped_confidence
        if ownership_class == VersionOwnershipClass.OWNED and ownership_confidence < 65.0:
            ownership_confidence = max(ownership_confidence, 95.0)
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=ownership_class,
            ownership_confidence=ownership_confidence,
            reason="Self-proving extraction method owns the version observation",
            basis="js_self_proving_method",
        )

    affinity = asset_affinity_for_technology(
        technology_id,
        filename=filename,
        source_url=source_url,
    )
    if affinity >= 70.0:
        return VersionOwnershipAssessment(
            technology_id=technology_id,
            ownership_class=VersionOwnershipClass.OWNED,
            ownership_confidence=max(stamped_confidence, 90.0),
            reason="Asset identity matches technology tokens for owned banner/path evidence",
            basis="js_asset_affinity",
        )

    # Technology-scoped extractor found evidence, but the asset identity is weak.
    # Remain confirmable alone (OWNED at reduced confidence) while scoring below
    # affinity-backed candidates so incidental mentions cannot veto owned assets.
    return VersionOwnershipAssessment(
        technology_id=technology_id,
        ownership_class=VersionOwnershipClass.OWNED,
        ownership_confidence=70.0,
        reason="Technology-scoped extraction without strong asset affinity",
        basis="js_extractor_low_affinity",
    )


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
