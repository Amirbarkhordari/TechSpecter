"""Finding deduplication and tracking."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from uuid import uuid4

from techspecter.sensitive_intelligence.candidates.models import SensitiveCandidate, ValidationState
from techspecter.sensitive_intelligence.detectors.base import (
    BaseSensitiveDetector,
    DetectorMatch,
    resolve_finding_category,
)
from techspecter.sensitive_intelligence.models import (
    FindingLocation,
    SensitiveFindingRecord,
)
from techspecter.sensitive_intelligence.sources import TextAssetSource

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FindingTracker:
    """Track and deduplicate confirmed sensitive findings across assets."""

    _findings: dict[str, SensitiveFindingRecord] = field(default_factory=dict)

    def add_confirmed_candidate(self, candidate: SensitiveCandidate) -> SensitiveFindingRecord | None:
        """Add a validated/confirmed candidate with asset attribution.

        Rejected and candidate-only results are ignored (not confirmed findings).
        """
        if candidate.validation_state != ValidationState.CONFIRMED:
            logger.debug(
                "Skipping non-confirmed candidate %s/%s (%s)",
                candidate.finding_type.value,
                candidate.subtype,
                candidate.validation_state.value,
            )
            return None

        match = candidate.match
        key = _finding_key(match)
        location = FindingLocation(
            source_file=candidate.source_file,
            source_url=candidate.source_url,
            relative_path=candidate.relative_path,
            asset_id=candidate.asset_id,
            line_number=match.line_number,
            column_number=match.column_number,
            byte_offset=match.byte_offset,
        )
        existing = self._findings.get(key)
        if existing is not None:
            return self._merge(existing, location, candidate.confidence)

        record = SensitiveFindingRecord(
            finding_id=str(uuid4()),
            finding_type=match.finding_type,
            category=resolve_finding_category(match),
            subtype=match.subtype,
            severity=match.severity,
            confidence=candidate.confidence,
            confidence_level=BaseSensitiveDetector.confidence_level(candidate.confidence),
            matched_value=match.matched_value,
            matched_pattern=match.matched_pattern,
            detector_name=candidate.detector_id,
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            description=match.description,
            recommendation=match.recommendation,
            evidence=match.evidence,
            locations=[location],
            source_files=[candidate.source_file] if candidate.source_file else [],
            relative_paths=[
                candidate.relative_path or candidate.source_file or "",
            ],
            occurrence_count=1,
        )
        # Drop empty relative path placeholders.
        record = record.model_copy(
            update={"relative_paths": [item for item in record.relative_paths if item]},
        )
        self._findings[key] = record
        logger.debug(
            "Created finding %s/%s in %s",
            match.finding_type.value,
            match.subtype,
            candidate.source_file,
        )
        return record

    def add_match(
        self,
        match: DetectorMatch,
        *,
        detector: BaseSensitiveDetector,
        source: TextAssetSource,
    ) -> SensitiveFindingRecord:
        """Legacy helper: add a match without candidate validation.

        Prefer ``add_confirmed_candidate`` via the validation spine. Kept for
        direct tracker unit tests and provenance/dedupe coverage.
        """
        key = _finding_key(match)
        location = FindingLocation(
            source_file=source.filename,
            source_url=source.url,
            relative_path=source.relative_path,
            asset_id=source.asset_id,
            line_number=match.line_number,
            column_number=match.column_number,
            byte_offset=match.byte_offset,
        )
        existing = self._findings.get(key)
        if existing is not None:
            return self._merge(existing, location, match.confidence)

        record = SensitiveFindingRecord(
            finding_id=str(uuid4()),
            finding_type=match.finding_type,
            category=resolve_finding_category(match),
            subtype=match.subtype,
            severity=match.severity,
            confidence=match.confidence,
            confidence_level=detector.confidence_level(match.confidence),
            matched_value=match.matched_value,
            matched_pattern=match.matched_pattern,
            detector_name=detector.detector_id,
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            description=match.description,
            recommendation=match.recommendation,
            evidence=match.evidence,
            locations=[location],
            source_files=[source.filename],
            relative_paths=[source.relative_path or source.filename],
            occurrence_count=1,
        )
        self._findings[key] = record
        logger.debug(
            "Created finding %s/%s in %s",
            match.finding_type.value,
            match.subtype,
            source.filename,
        )
        return record

    def all(self) -> list[SensitiveFindingRecord]:
        """Return all tracked findings."""
        return list(self._findings.values())

    def _merge(
        self,
        existing: SensitiveFindingRecord,
        location: FindingLocation,
        confidence: float,
    ) -> SensitiveFindingRecord:
        locations = list(existing.locations)
        if not _location_exists(locations, location):
            locations.append(location)
        files = sorted(set(existing.source_files) | {location.source_file or ""})
        files = [item for item in files if item]
        rel_paths = sorted(
            set(existing.relative_paths) | {location.relative_path or location.source_file or ""}
        )
        rel_paths = [item for item in rel_paths if item]
        merged_confidence = min(100.0, max(existing.confidence, confidence) + 2.0)
        updated = existing.model_copy(
            update={
                "locations": locations,
                "source_files": files,
                "relative_paths": rel_paths,
                "occurrence_count": existing.occurrence_count + 1,
                "confidence": merged_confidence,
                "confidence_level": BaseSensitiveDetector.confidence_level(merged_confidence),
            },
        )
        self._findings[_finding_key_from_record(updated)] = updated
        logger.debug(
            "Merged duplicate finding %s/%s (occurrences=%d)",
            updated.finding_type.value,
            updated.subtype,
            updated.occurrence_count,
        )
        return updated


def _finding_key(match: DetectorMatch) -> str:
    return "|".join(
        [
            match.finding_type.value,
            match.subtype,
            match.matched_value,
        ],
    )


def _finding_key_from_record(record: SensitiveFindingRecord) -> str:
    return "|".join([record.finding_type.value, record.subtype, record.matched_value])


def _location_exists(locations: list[FindingLocation], candidate: FindingLocation) -> bool:
    for item in locations:
        if (
            item.source_url == candidate.source_url
            and item.line_number == candidate.line_number
            and item.byte_offset == candidate.byte_offset
        ):
            return True
    return False
