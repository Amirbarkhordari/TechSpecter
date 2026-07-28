"""JavaScript Fingerprinting Core Engine."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from techspecter.fingerprinting.collectors import CollectorRegistry, collector_registry
from techspecter.fingerprinting.evidence import (
    Evidence,
    EvidenceCollection,
    EvidenceResult,
    EvidenceSource,
    EvidenceSummary,
    EvidenceType,
)
from techspecter.fingerprinting.extensions import (
    CollectorPlugin,
    EvidenceProvider,
    EvidenceProviderPlugin,
    FingerprintPluginExtension,
)
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
from techspecter.fingerprinting.pipeline import EvidencePipeline, FingerprintPipeline
from techspecter.fingerprinting.scoring import ConfidenceScorer, MatchEvidence
from techspecter.fingerprinting.signatures import (
    SignatureRule,
    TechnologySignature,
    VersionExtractorSpec,
)
from techspecter.fingerprinting.validator import (
    FingerprintValidationReport,
    FingerprintValidator,
    validate_fingerprints_or_raise,
)

if TYPE_CHECKING:
    from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer
    from techspecter.fingerprinting.engine import FingerprintEngine
    from techspecter.fingerprinting.service import FingerprintService

__all__ = [
    "CollectorRegistry",
    "CollectorPlugin",
    "ConfidenceScorer",
    "DetectionResult",
    "Evidence",
    "EvidenceCollection",
    "EvidencePipeline",
    "EvidenceProvider",
    "EvidenceProviderPlugin",
    "EvidenceResult",
    "EvidenceSource",
    "EvidenceSummary",
    "EvidenceType",
    "Fingerprint",
    "FingerprintAnalysisResult",
    "FingerprintCompatibilityLayer",
    "FingerprintEngine",
    "FingerprintPattern",
    "FingerprintPipeline",
    "FingerprintPluginExtension",
    "FingerprintService",
    "FingerprintValidationReport",
    "FingerprintValidator",
    "MatchEvidence",
    "Pattern",
    "PatternEvidence",
    "SignatureLoader",
    "SignatureRule",
    "Technology",
    "TechnologyMatch",
    "TechnologySignature",
    "UNKNOWN_VERSION",
    "VersionExtractor",
    "VersionExtractorSpec",
    "VersionPattern",
    "collector_registry",
    "resolve_signatures_directory",
    "validate_fingerprints_or_raise",
]


def __getattr__(name: str) -> Any:
    """Lazily import modules that would otherwise create import cycles."""
    if name == "FingerprintService":
        from techspecter.fingerprinting.service import FingerprintService

        return FingerprintService
    if name == "FingerprintEngine":
        from techspecter.fingerprinting.engine import FingerprintEngine

        return FingerprintEngine
    if name == "FingerprintCompatibilityLayer":
        from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer

        return FingerprintCompatibilityLayer
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
