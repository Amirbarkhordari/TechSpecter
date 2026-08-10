"""Sensitive candidate validation spine."""

from techspecter.sensitive_intelligence.candidates.builder import build_candidate
from techspecter.sensitive_intelligence.candidates.models import (
    ContextKind,
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
    ValidationState,
    ValueStrength,
)
from techspecter.sensitive_intelligence.candidates.placeholders import (
    is_placeholder_value,
    normalize_placeholder_token,
)
from techspecter.sensitive_intelligence.candidates.quality_gate import SensitiveMatchQualityGate
from techspecter.sensitive_intelligence.candidates.runtime import is_runtime_reference
from techspecter.sensitive_intelligence.candidates.validator import SensitiveCandidateValidator

__all__ = [
    "ContextKind",
    "NegativeEvidence",
    "PositiveEvidence",
    "SensitiveCandidate",
    "SensitiveCandidateValidator",
    "SensitiveMatchQualityGate",
    "ValidationState",
    "ValueStrength",
    "build_candidate",
    "is_placeholder_value",
    "is_runtime_reference",
    "normalize_placeholder_token",
]
