"""Sensitive candidate models for the Phase 5 validation spine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.models import (
    FindingCategory,
    FindingType,
    SeverityLevel,
)


class ValidationState(StrEnum):
    """Lifecycle state of a sensitive candidate."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    CANDIDATE_ONLY = "candidate_only"
    REJECTED = "rejected"


class ValueStrength(StrEnum):
    """Semantic strength of the analyzed sensitive value."""

    EMPTY = "empty"
    PLACEHOLDER = "placeholder"
    WEAK = "weak"
    RUNTIME = "runtime"
    REALISTIC = "realistic"
    STRUCTURED = "structured"
    UNKNOWN = "unknown"


class ContextKind(StrEnum):
    """Primary context classification for a candidate."""

    STATIC_ASSIGNMENT = "static_assignment"
    RUNTIME_REFERENCE = "runtime_reference"
    SELF_REFERENCE = "self_reference"
    EMPTY_ASSIGNMENT = "empty_assignment"
    PLACEHOLDER_ASSIGNMENT = "placeholder_assignment"
    DOCUMENTATION = "documentation"
    TEST_FIXTURE = "test_fixture"
    GENERATED_TEMPLATE = "generated_template"
    FORM_FIELD = "form_field"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class PositiveEvidence(StrEnum):
    """Signals that support confirmation of a sensitive candidate."""

    STATIC_LITERAL = "static_literal"
    STATIC_ASSIGNMENT = "static_assignment"
    REALISTIC_SECRET_SHAPE = "realistic_secret_shape"
    HIGH_ENTROPY = "high_entropy"
    PROVIDER_SPECIFIC_FORMAT = "provider_specific_format"
    CREDENTIAL_PAIR = "credential_pair"
    CONFIGURATION_ASSIGNMENT = "configuration_assignment"
    STRUCTURED_SECRET = "structured_secret"


class NegativeEvidence(StrEnum):
    """Signals that reduce confidence or reject a sensitive candidate."""

    EMPTY_VALUE = "empty_value"
    PLACEHOLDER_VALUE = "placeholder_value"
    EXAMPLE_VALUE = "example_value"
    WEAK_GENERIC_VALUE = "weak_generic_value"
    RUNTIME_REFERENCE = "runtime_reference"
    FORM_REFERENCE = "form_reference"
    FORM_FIELD = "form_field"
    DOCUMENTATION_CONTEXT = "documentation_context"
    TEST_FIXTURE = "test_fixture"
    GENERATED_TEMPLATE = "generated_template"
    HTML_ATTRIBUTE = "html_attribute"
    SELF_REFERENCE = "self_reference"
    CONTACT_ONLY = "contact_only"


@dataclass(slots=True)
class SensitiveCandidate:
    """Intermediate sensitive match awaiting validation and quality gating.

    Detectors remain evidence producers (``DetectorMatch``). Candidates are the
    confirmation boundary: only validated candidates become findings.
    """

    match: DetectorMatch
    detector_id: str
    source_url: str | None = None
    source_file: str | None = None
    relative_path: str | None = None
    asset_id: str | None = None
    analysis_value: str | None = None
    credential_name: str | None = None
    credential_category: str | None = None
    value_strength: ValueStrength = ValueStrength.UNKNOWN
    context_kind: ContextKind = ContextKind.UNKNOWN
    original_confidence: float = 0.0
    original_severity: SeverityLevel = SeverityLevel.INFORMATIONAL
    adjusted_confidence: float = 0.0
    positive_evidence: list[PositiveEvidence] = field(default_factory=list)
    negative_evidence: list[NegativeEvidence] = field(default_factory=list)
    validation_state: ValidationState = ValidationState.PENDING
    rejection_reason: str | None = None

    @property
    def finding_type(self) -> FindingType:
        return self.match.finding_type

    @property
    def category(self) -> FindingCategory | None:
        return self.match.category

    @property
    def subtype(self) -> str:
        return self.match.subtype

    @property
    def rule_id(self) -> str | None:
        return self.match.rule_id

    @property
    def matched_value(self) -> str:
        return self.match.matched_value

    @property
    def evidence(self) -> str | None:
        return self.match.evidence

    @property
    def confidence(self) -> float:
        return self.adjusted_confidence or self.original_confidence

    @property
    def severity(self) -> SeverityLevel:
        return self.original_severity
