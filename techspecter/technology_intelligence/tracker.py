"""Evidence tracking for technology intelligence."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from techspecter.technology_intelligence.models import TechnologyEvidenceRecord

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EvidenceTracker:
    """Track and deduplicate technology evidence records."""

    _records: dict[str, TechnologyEvidenceRecord] = field(default_factory=dict)

    def add(self, record: TechnologyEvidenceRecord) -> TechnologyEvidenceRecord:
        """Add evidence, deduplicating by stable key."""
        key = _evidence_key(record)
        existing = self._records.get(key)
        if existing is not None:
            if record.confidence > existing.confidence:
                self._records[key] = record
            return self._records[key]
        self._records[key] = record
        logger.debug(
            "Tracked evidence for %s from %s",
            record.technology_name,
            record.source_file or record.source_url,
        )
        return record

    def add_many(self, records: list[TechnologyEvidenceRecord]) -> list[TechnologyEvidenceRecord]:
        """Add multiple evidence records."""
        return [self.add(record) for record in records]

    def all(self) -> list[TechnologyEvidenceRecord]:
        """Return all tracked evidence."""
        return list(self._records.values())

    def count(self) -> int:
        """Return evidence count."""
        return len(self._records)

    def unique_source_files(self) -> list[str]:
        """Return unique source filenames."""
        files = {item.source_file for item in self._records.values() if item.source_file}
        return sorted(files)

    def unique_asset_ids(self) -> list[str]:
        """Return unique asset IDs."""
        asset_ids = {
            item.source_asset_id for item in self._records.values() if item.source_asset_id
        }
        return sorted(asset_ids)


def _evidence_key(record: TechnologyEvidenceRecord) -> str:
    """Build deduplication key for evidence."""
    return "|".join(
        [
            record.technology_name.lower(),
            record.evidence_type.value,
            record.matched_pattern or "",
            record.source_url or record.source_file or "",
            record.matched_text or "",
        ],
    )
