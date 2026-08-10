"""Separate technology knowledge (signatures) from evidence-driven detection.

The fingerprint registry and signature catalog provide **technology knowledge**:
patterns, metadata, version rules, and matcher definitions for technologies
TechSpecter understands.

Detection output must always be **evidence-backed**. Registry membership alone
never produces a confirmed technology match. A technology absent from the
knowledge catalog is not rejected merely for being unknown — it simply lacks
predefined signatures until added. Future phases may emit matches from raw
evidence without catalog lookup; this module defines the shared contract.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import TYPE_CHECKING

from techspecter.fingerprinting.match_attribution import (
    has_attributed_evidence,
    has_structured_evidence,
    is_valid_detection_candidate,
)
from techspecter.fingerprinting.models import PatternEvidence, Technology, TechnologyMatch

if TYPE_CHECKING:
    from techspecter.fingerprinting.signatures.models import TechnologySignature

logger = logging.getLogger(__name__)


class DetectionBasis(StrEnum):
    """How a technology match was established."""

    EVIDENCE = "evidence"
    """Match confirmed by matcher-produced evidence in analyzed assets."""


def is_evidence_backed_match(match: TechnologyMatch) -> bool:
    """Return True when a match is supported by matcher evidence, not registry alone."""
    return is_valid_detection_candidate(match)


def reject_evidence_less_matches(
    matches: list[TechnologyMatch],
) -> tuple[list[TechnologyMatch], list[TechnologyMatch]]:
    """Partition matches into evidence-backed and evidence-less groups.

    Rejection is based on missing detection evidence, not catalog membership.
    Unknown technology IDs are not rejected here.
    """
    accepted: list[TechnologyMatch] = []
    rejected: list[TechnologyMatch] = []
    for match in matches:
        if is_evidence_backed_match(match):
            accepted.append(match)
        else:
            rejected.append(match)
            logger.debug(
                "Rejected evidence-less candidate: %s",
                match.technology.id,
            )
    return accepted, rejected


def annotate_detection_basis(match: TechnologyMatch) -> TechnologyMatch:
    """Tag a match as evidence-driven when structured evidence is present."""
    if not has_structured_evidence(match):
        return match
    if match.detection_basis == DetectionBasis.EVIDENCE:
        return match
    return match.model_copy(update={"detection_basis": DetectionBasis.EVIDENCE})


def build_evidence_driven_match(
    *,
    technology_id: str,
    name: str,
    category: str,
    evidence: list[PatternEvidence],
    confidence: float,
    source_url: str | None = None,
    source_file: str | None = None,
    asset_id: str | None = None,
    version: str | None = None,
) -> TechnologyMatch:
    """Build a technology match directly from evidence without registry lookup.

    Prepares the architecture for universal detection in later phases where
    valid evidence may identify technologies not yet present in the catalog.
    """
    from techspecter.fingerprinting.match_attribution import apply_match_attribution
    from techspecter.fingerprinting.models import UNKNOWN_VERSION

    match = TechnologyMatch(
        technology=Technology(id=technology_id, name=name, category=category),
        version=version or UNKNOWN_VERSION,
        confidence=confidence,
        matched_patterns=[f"{item.matcher}:{item.pattern}" for item in evidence],
        source_url=source_url,
        filename=source_file,
        source_file=source_file,
        asset_id=asset_id,
        evidence=evidence,
        detection_basis=DetectionBasis.EVIDENCE,
        providers=["techspecter"],
        detection_methods=["evidence-driven"],
    )
    return apply_match_attribution(match)


def enrich_match_from_knowledge(
    match: TechnologyMatch,
    signature: TechnologySignature,
) -> TechnologyMatch:
    """Enrich an evidence-backed match with optional catalog metadata."""
    tech_updates: dict[str, object] = {}
    if not match.technology.website and signature.website:
        tech_updates["website"] = signature.website
    if not match.technology.description and signature.description:
        tech_updates["description"] = signature.description
    if not tech_updates:
        return match
    return match.model_copy(
        update={"technology": match.technology.model_copy(update=tech_updates)},
    )


def assert_evidence_collection_purity(*, technology: str | None, collector: str) -> None:
    """Warn when evidence collectors assign a technology (Phase 1 invariant)."""
    if technology is not None:
        logger.warning(
            "Evidence collector '%s' assigned technology '%s'; "
            "collectors must remain technology-agnostic",
            collector,
            technology,
        )
