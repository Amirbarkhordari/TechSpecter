"""Evidence-driven technology candidate models.

Candidates are intermediate discovery results. Only validated candidates become
confirmed ``TechnologyMatch`` objects in detection output.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from techspecter.fingerprinting.evidence.models import Evidence
from techspecter.models.base import TechSpecterModel


class CandidateStatus(StrEnum):
    """Lifecycle state of a technology candidate."""

    CANDIDATE = "candidate"
    REJECTED = "rejected"
    CONFIRMED = "confirmed"


class DiscoveryBasis(StrEnum):
    """Structured evidence basis that produced a candidate."""

    PACKAGE = "package"
    RUNTIME = "runtime"
    IMPORT = "import"
    BUNDLE = "bundle"
    HTTP = "http"
    MULTI_SIGNAL = "multi_signal"


class TechnologyCandidate(TechSpecterModel):
    """Intermediate technology discovery result awaiting validation."""

    technology_id: str
    name: str
    category: str = "unknown"
    status: CandidateStatus = CandidateStatus.CANDIDATE
    evidence: tuple[Evidence, ...] = Field(default_factory=tuple)
    source_url: str | None = None
    source_file: str | None = None
    asset_id: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    discovery_basis: DiscoveryBasis
    discovery_reason: str | None = None
    supporting_evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    rejection_reason: str | None = None
    version_hint: str | None = None

    @property
    def evidence_types(self) -> frozenset[str]:
        """Return distinct evidence type values attached to this candidate."""
        return frozenset(item.evidence_type.value for item in self.evidence)
