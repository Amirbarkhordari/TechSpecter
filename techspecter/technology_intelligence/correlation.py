"""Evidence correlation and confidence adjustment."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from techspecter.fingerprinting.models import TechnologyMatch
from techspecter.technology_intelligence.models import (
    TechnologyDetectionMetadata,
    TechnologyEvidenceRecord,
    TechnologyIntelligenceEntry,
    TechnologyRelationshipRecord,
)
from techspecter.technology_intelligence.relationships import KNOWN_TECHNOLOGY_RELATIONSHIPS
from techspecter.technology_intelligence.tracker import EvidenceTracker

logger = logging.getLogger(__name__)

_FILE_BOOST = 3.0
_EVIDENCE_BOOST = 1.0
_MAX_FILE_BOOST = 12.0
_MAX_EVIDENCE_BOOST = 8.0


@dataclass(slots=True)
class EvidenceCorrelationEngine:
    """Correlate evidence across assets and adjust confidence."""

    def correlate(
        self,
        match: TechnologyMatch,
        evidence: list[TechnologyEvidenceRecord],
        *,
        version_attribution: object | None = None,
        detectors: list[str] | None = None,
    ) -> TechnologyIntelligenceEntry:
        """Build correlated intelligence entry from match and evidence."""
        tracker = EvidenceTracker()
        tracker.add_many(evidence)
        correlated = tracker.all()
        unique_files = tracker.unique_source_files()
        unique_assets = tracker.unique_asset_ids()
        unique_files, unique_assets = self._enrich_attribution(
            match,
            unique_files,
            unique_assets,
            evidence,
        )
        confidence = self.calculate_confidence(
            base=match.confidence,
            file_count=len(unique_files),
            evidence_count=len(correlated),
        )

        metadata = TechnologyDetectionMetadata(
            detection_methods=list(match.detection_methods or match.evidence_sources),
            asset_count=max(len(unique_files), len(match.matched_resources)),
            evidence_count=len(correlated),
            version_source=match.version_source,
            detectors=list(detectors or match.providers or ["techspecter"]),
        )

        entry = TechnologyIntelligenceEntry(
            technology=match.technology,
            version=match.version,
            confidence=confidence,
            evidence=correlated,
            version_attribution=version_attribution,  # type: ignore[arg-type]
            metadata=metadata,
            found_in_files=unique_files or ([match.filename] if match.filename else []),
            found_in_asset_ids=unique_assets,
            detectors=list(detectors or match.providers or ["techspecter"]),
        )

        logger.info(
            "Correlated %s: %d evidence, %d files, confidence %.1f -> %.1f",
            match.technology.id,
            len(correlated),
            len(unique_files),
            match.confidence,
            confidence,
        )
        return entry

    def _enrich_attribution(
        self,
        match: TechnologyMatch,
        files: list[str],
        asset_ids: list[str],
        evidence: list[TechnologyEvidenceRecord],
    ) -> tuple[list[str], list[str]]:
        """Merge match-level provenance into attribution lists."""
        file_set = set(files)
        asset_set = set(asset_ids)

        if match.filename:
            file_set.add(match.filename)
        if match.source_url:
            for item in evidence:
                if item.source_url == match.source_url and item.source_file:
                    file_set.add(item.source_file)
        for url in match.matched_resources:
            for item in evidence:
                if item.source_url == url and item.source_file:
                    file_set.add(item.source_file)
            filename = url.rsplit("/", 1)[-1] if url else None
            if filename and "." in filename:
                file_set.add(filename)
        for item in evidence:
            if item.source_file:
                file_set.add(item.source_file)
            if item.source_asset_id:
                asset_set.add(item.source_asset_id)

        return sorted(file_set), sorted(asset_set)

    def calculate_confidence(
        self,
        *,
        base: float,
        file_count: int,
        evidence_count: int,
    ) -> float:
        """Increase confidence when multiple independent evidence sources exist."""
        file_boost = min(_MAX_FILE_BOOST, max(0, file_count - 1) * _FILE_BOOST)
        evidence_boost = min(_MAX_EVIDENCE_BOOST, max(0, evidence_count - 1) * _EVIDENCE_BOOST)
        return min(100.0, base + file_boost + evidence_boost)

    def merge_entries(
        self,
        entries: list[TechnologyIntelligenceEntry],
    ) -> list[TechnologyIntelligenceEntry]:
        """Merge duplicate technology entries by technology ID."""
        merged: dict[str, TechnologyIntelligenceEntry] = {}
        for entry in entries:
            key = entry.technology.id.lower()
            existing = merged.get(key)
            if existing is None:
                merged[key] = entry
                continue
            merged[key] = self._merge_pair(existing, entry)
        return list(merged.values())

    def resolve_relationships(
        self,
        entries: list[TechnologyIntelligenceEntry],
    ) -> list[TechnologyRelationshipRecord]:
        """Infer dependency relationships from detected technologies."""
        detected_ids = {entry.technology.id.lower() for entry in entries}
        name_by_id = {entry.technology.id.lower(): entry.technology.name for entry in entries}
        relationships: list[TechnologyRelationshipRecord] = []

        for entry in entries:
            rules = KNOWN_TECHNOLOGY_RELATIONSHIPS.get(entry.technology.id.lower(), [])
            for target_id, kind in rules:
                if target_id.lower() not in detected_ids:
                    continue
                relationships.append(
                    TechnologyRelationshipRecord(
                        source_technology_id=entry.technology.id,
                        source_technology_name=entry.technology.name,
                        target_technology_id=target_id,
                        target_technology_name=name_by_id.get(target_id.lower(), target_id),
                        relationship=kind,
                    ),
                )
                logger.debug(
                    "Relationship detected: %s -> %s (%s)",
                    entry.technology.name,
                    name_by_id.get(target_id.lower(), target_id),
                    kind.value,
                )

        return relationships

    def attach_relationships(
        self,
        entries: list[TechnologyIntelligenceEntry],
        relationships: list[TechnologyRelationshipRecord],
    ) -> list[TechnologyIntelligenceEntry]:
        """Attach per-technology relationship lists."""
        by_source: dict[str, list[TechnologyRelationshipRecord]] = {}
        for rel in relationships:
            by_source.setdefault(rel.source_technology_id.lower(), []).append(rel)

        updated: list[TechnologyIntelligenceEntry] = []
        for entry in entries:
            rels = by_source.get(entry.technology.id.lower(), [])
            metadata = entry.metadata.model_copy(
                update={"relationship_count": len(rels)},
            )
            updated.append(
                entry.model_copy(
                    update={"relationships": rels, "metadata": metadata},
                ),
            )
        return updated

    def _merge_pair(
        self,
        left: TechnologyIntelligenceEntry,
        right: TechnologyIntelligenceEntry,
    ) -> TechnologyIntelligenceEntry:
        tracker = EvidenceTracker()
        tracker.add_many(left.evidence)
        tracker.add_many(right.evidence)
        evidence = tracker.all()
        files = sorted(set(left.found_in_files) | set(right.found_in_files))
        assets = sorted(set(left.found_in_asset_ids) | set(right.found_in_asset_ids))
        confidence = self.calculate_confidence(
            base=max(left.confidence, right.confidence),
            file_count=len(files),
            evidence_count=len(evidence),
        )
        version = left.version if left.version != "Unknown" else right.version
        version_attr = left.version_attribution or right.version_attribution
        metadata = TechnologyDetectionMetadata(
            detection_methods=sorted(
                set(left.metadata.detection_methods) | set(right.metadata.detection_methods),
            ),
            asset_count=len(files),
            evidence_count=len(evidence),
            version_source=left.metadata.version_source or right.metadata.version_source,
            detectors=sorted(set(left.detectors) | set(right.detectors)),
        )
        return left.model_copy(
            update={
                "confidence": confidence,
                "evidence": evidence,
                "found_in_files": files,
                "found_in_asset_ids": assets,
                "version": version,
                "version_attribution": version_attr,
                "metadata": metadata,
                "detectors": metadata.detectors,
            },
        )
