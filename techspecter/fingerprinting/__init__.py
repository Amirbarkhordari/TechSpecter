"""JavaScript Fingerprinting Core Engine."""

from techspecter.fingerprinting.engine import FingerprintEngine
from techspecter.fingerprinting.extractor import VersionExtractor
from techspecter.fingerprinting.loader import SignatureLoader, resolve_signatures_directory
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
from techspecter.fingerprinting.pipeline import FingerprintPipeline
from techspecter.fingerprinting.scoring import ConfidenceScorer, MatchEvidence
from techspecter.fingerprinting.service import FingerprintService
from techspecter.fingerprinting.validator import (
    FingerprintValidationReport,
    FingerprintValidator,
    validate_fingerprints_or_raise,
)

__all__ = [
    "ConfidenceScorer",
    "DetectionResult",
    "Fingerprint",
    "FingerprintAnalysisResult",
    "FingerprintEngine",
    "FingerprintPattern",
    "FingerprintPipeline",
    "FingerprintService",
    "FingerprintValidationReport",
    "FingerprintValidator",
    "MatchEvidence",
    "Pattern",
    "PatternEvidence",
    "SignatureLoader",
    "Technology",
    "TechnologyMatch",
    "UNKNOWN_VERSION",
    "VersionExtractor",
    "VersionPattern",
    "resolve_signatures_directory",
    "validate_fingerprints_or_raise",
]
