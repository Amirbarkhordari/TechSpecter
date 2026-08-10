"""Sensitive candidate validation spine."""

from techspecter.sensitive_intelligence.candidates.builder import build_candidate
from techspecter.sensitive_intelligence.candidates.correlation import CandidateCorrelator
from techspecter.sensitive_intelligence.candidates.models import (
    ContextKind,
    CorrelationType,
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
    SensitiveCorrelation,
    ValidationState,
    ValueStrength,
)
from techspecter.sensitive_intelligence.candidates.placeholders import (
    is_placeholder_value,
    normalize_placeholder_token,
)
from techspecter.sensitive_intelligence.candidates.policies import (
    DetectorPolicy,
    resolve_detector_policy,
)
from techspecter.sensitive_intelligence.candidates.quality_gate import SensitiveMatchQualityGate
from techspecter.sensitive_intelligence.candidates.runtime import is_runtime_reference
from techspecter.sensitive_intelligence.candidates.severity import calibrate_candidate
from techspecter.sensitive_intelligence.candidates.validator import SensitiveCandidateValidator

__all__ = [
    "CandidateCorrelator",
    "ContextKind",
    "CorrelationType",
    "DetectorPolicy",
    "NegativeEvidence",
    "PositiveEvidence",
    "SensitiveCandidate",
    "SensitiveCandidateValidator",
    "SensitiveCorrelation",
    "SensitiveMatchQualityGate",
    "ValidationState",
    "ValueStrength",
    "build_candidate",
    "calibrate_candidate",
    "is_placeholder_value",
    "is_runtime_reference",
    "normalize_placeholder_token",
    "resolve_detector_policy",
]
