"""Validate technology candidates into confirmed TechnologyMatch results."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.candidates.mappings import (
    is_conservative_package_name,
    is_relative_module,
)
from techspecter.fingerprinting.detection.candidates.models import (
    CandidateStatus,
    TechnologyCandidate,
)
from techspecter.fingerprinting.detection.knowledge import (
    DetectionBasis,
    annotate_detection_basis,
)
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceType
from techspecter.fingerprinting.match_attribution import apply_match_attribution
from techspecter.fingerprinting.match_quality import MatchQualityGate, is_weak_pattern
from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    PatternEvidence,
    Technology,
    TechnologyMatch,
)
from techspecter.versioning.validator import is_valid_version

logger = logging.getLogger(__name__)

_CONFIRMABLE_TYPES = frozenset(
    {
        EvidenceType.PACKAGE_REFERENCE,
        EvidenceType.RUNTIME_PATTERN,
        EvidenceType.IMPORT_EXPORT,
        EvidenceType.BUNDLE_MARKER,
        EvidenceType.BUNDLE_RUNTIME,
        EvidenceType.HTTP_HEADER,
        EvidenceType.SOURCE_MAP_METADATA,
    },
)

_WEAK_ALONE_TYPES = frozenset(
    {
        EvidenceType.STRING_LITERAL,
        EvidenceType.SCRIPT_CONTENT,
        EvidenceType.FILENAME,
        EvidenceType.HTML_ELEMENT,
        EvidenceType.CUSTOM,
    },
)


@dataclass
class CandidateValidator:
    """Validate candidates using evidence strength and MatchQualityGate."""

    quality_gate: MatchQualityGate = field(default_factory=MatchQualityGate)
    min_confidence: float = 55.0
    open_package_min_confidence: float = 70.0

    def validate(
        self,
        candidates: list[TechnologyCandidate],
    ) -> tuple[list[TechnologyMatch], list[TechnologyCandidate]]:
        """Return confirmed matches and rejected/remaining candidates."""
        confirmed: list[TechnologyMatch] = []
        rejected: list[TechnologyCandidate] = []

        for candidate in candidates:
            match, updated = self._validate_one(candidate)
            if match is None:
                rejected.append(updated)
                continue
            confirmed.append(match)

        return confirmed, rejected

    def _validate_one(
        self,
        candidate: TechnologyCandidate,
    ) -> tuple[TechnologyMatch | None, TechnologyCandidate]:
        if not candidate.evidence:
            return None, candidate.model_copy(
                update={
                    "status": CandidateStatus.REJECTED,
                    "rejection_reason": "evidence-less candidate",
                },
            )

        if any(
            is_relative_module(item.matched_value or "") for item in candidate.evidence
        ):
            return None, candidate.model_copy(
                update={
                    "status": CandidateStatus.REJECTED,
                    "rejection_reason": "relative module path is not a package identity",
                },
            )

        if all(item.evidence_type in _WEAK_ALONE_TYPES for item in candidate.evidence):
            return None, candidate.model_copy(
                update={
                    "status": CandidateStatus.REJECTED,
                    "rejection_reason": "only weak evidence types",
                },
            )

        strong = [
            item for item in candidate.evidence if item.evidence_type in _CONFIRMABLE_TYPES
        ]
        if not strong:
            return None, candidate.model_copy(
                update={
                    "status": CandidateStatus.REJECTED,
                    "rejection_reason": "no strong structured evidence",
                },
            )

        threshold = self.min_confidence
        if not candidate.knowledge_matched:
            threshold = self.open_package_min_confidence
            package_key = candidate.technology_id.removeprefix("package:")
            if is_conservative_package_name(package_key):
                # Ambiguous names require multi-signal correlation to confirm.
                if len(candidate.evidence_types) < 2:
                    return None, candidate.model_copy(
                        update={
                            "status": CandidateStatus.REJECTED,
                            "rejection_reason": (
                                "conservative package name requires multi-signal evidence"
                            ),
                        },
                    )
            # Evidence-native packages need at least one PACKAGE_REFERENCE or
            # source-map node_modules path — import-only is candidate-grade only.
            has_package_ref = any(
                item.evidence_type
                in {EvidenceType.PACKAGE_REFERENCE, EvidenceType.SOURCE_MAP_METADATA}
                for item in strong
            )
            if not has_package_ref and len(strong) < 2:
                return None, candidate.model_copy(
                    update={
                        "status": CandidateStatus.REJECTED,
                        "rejection_reason": (
                            "open package identity requires package reference "
                            "or multi-signal evidence"
                        ),
                    },
                )

        if candidate.confidence < threshold:
            return None, candidate.model_copy(
                update={
                    "status": CandidateStatus.REJECTED,
                    "rejection_reason": f"confidence {candidate.confidence:.1f} below {threshold:.0f}",
                },
            )

        pattern_evidence = [self._to_pattern_evidence(item) for item in strong]
        if all(is_weak_pattern(item.matcher, item.pattern) for item in pattern_evidence):
            return None, candidate.model_copy(
                update={
                    "status": CandidateStatus.REJECTED,
                    "rejection_reason": "only weak matcher patterns",
                },
            )

        version = UNKNOWN_VERSION
        if candidate.version_hint and is_valid_version(candidate.version_hint):
            version = candidate.version_hint

        display_name = candidate.name
        if candidate.technology_id.startswith("package:") and not candidate.knowledge_matched:
            display_name = candidate.technology_id.removeprefix("package:")

        match = TechnologyMatch(
            technology=Technology(
                id=candidate.technology_id,
                name=display_name,
                category=candidate.category,
            ),
            version=version,
            confidence=candidate.confidence,
            matched_patterns=[
                f"{item.evidence_type.value}:{item.matched_value or item.matched_pattern or ''}"
                for item in strong
            ],
            source_url=candidate.source_url,
            filename=candidate.source_file,
            source_file=candidate.source_file,
            asset_id=candidate.asset_id,
            evidence=pattern_evidence,
            supporting_evidence_ids=list(candidate.supporting_evidence_ids),
            evidence_count=len(pattern_evidence),
            detection_reason=candidate.discovery_reason,
            detection_basis=DetectionBasis.EVIDENCE,
            providers=["techspecter"],
            detection_methods=[
                "candidate-engine",
                candidate.discovery_basis.value,
                candidate.identity_kind.value,
            ],
            evidence_sources=sorted({item.source.value for item in strong}),
            version_source="package-metadata" if version != UNKNOWN_VERSION else None,
            version_reason=(
                "Owned package version evidence"
                if version != UNKNOWN_VERSION
                else None
            ),
        )
        match = apply_match_attribution(match)
        match = annotate_detection_basis(match)

        if not self.quality_gate.is_confirmed(match):
            reason = self.quality_gate.rejection_reason(match)
            logger.debug(
                "Candidate '%s' rejected by quality gate: %s",
                candidate.technology_id,
                reason,
            )
            return None, candidate.model_copy(
                update={
                    "status": CandidateStatus.REJECTED,
                    "rejection_reason": reason,
                },
            )

        return match, candidate.model_copy(update={"status": CandidateStatus.CONFIRMED})

    def _to_pattern_evidence(self, item: Evidence) -> PatternEvidence:
        pattern = item.matched_pattern or item.matched_value or item.evidence_type.value
        matcher = item.evidence_type.value
        weight = max(item.confidence_hint, 40.0)
        if item.evidence_type in {
            EvidenceType.PACKAGE_REFERENCE,
            EvidenceType.RUNTIME_PATTERN,
            EvidenceType.BUNDLE_MARKER,
            EvidenceType.SOURCE_MAP_METADATA,
        }:
            weight = max(weight, 70.0)
        return PatternEvidence(
            matcher=matcher,
            pattern=pattern,
            weight=min(100.0, weight),
            detail=item.matched_value or item.reason,
            source_file=item.file,
            asset_id=item.id,
            evidence_type=item.evidence_type.value,
            matched_value=item.matched_value,
        )


def is_strong_candidate_evidence(item: Evidence) -> bool:
    """Return True when evidence is strong enough to support confirmation."""
    return item.evidence_type in _CONFIRMABLE_TYPES
