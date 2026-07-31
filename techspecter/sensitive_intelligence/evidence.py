"""Evidence helpers for sensitive intelligence."""

from __future__ import annotations

from techspecter.sensitive_intelligence.models import FindingLocation, SensitiveFindingRecord


def evidence_count(finding: SensitiveFindingRecord) -> int:
    """Return total evidence instances for a finding."""
    return max(finding.occurrence_count, len(finding.locations))


def line_numbers(finding: SensitiveFindingRecord) -> list[int]:
    """Return unique line numbers for a finding."""
    values = {item.line_number for item in finding.locations if item.line_number is not None}
    return sorted(values)


def byte_offsets(finding: SensitiveFindingRecord) -> list[int]:
    """Return unique byte offsets for a finding."""
    values = {item.byte_offset for item in finding.locations if item.byte_offset is not None}
    return sorted(values)


def locations_summary(finding: SensitiveFindingRecord) -> list[FindingLocation]:
    """Return deduplicated location records."""
    return list(finding.locations)
