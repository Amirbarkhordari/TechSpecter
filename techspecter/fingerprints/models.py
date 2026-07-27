"""Backward-compatible re-export."""

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    DetectionResult,
    Fingerprint,
    FingerprintAnalysisResult,
    FingerprintPattern,
    Pattern,
    PatternEvidence,
    Technology,
    TechnologyMatch,
    VersionPattern,
)

__all__ = [
    "DetectionResult",
    "Fingerprint",
    "FingerprintAnalysisResult",
    "FingerprintPattern",
    "MatchContext",
    "Pattern",
    "PatternEvidence",
    "Technology",
    "TechnologyMatch",
    "UNKNOWN_VERSION",
    "VersionPattern",
]
