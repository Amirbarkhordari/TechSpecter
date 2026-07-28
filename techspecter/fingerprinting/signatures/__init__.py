"""Signature schema exports."""

from techspecter.fingerprinting.signatures.categories import TechnologyCategory
from techspecter.fingerprinting.signatures.compiler import compile_signature
from techspecter.fingerprinting.signatures.loader import TechnologySignatureLoader
from techspecter.fingerprinting.signatures.models import (
    ConfidenceModifier,
    SignatureIndicator,
    SignatureIndicators,
    SignatureRule,
    TechnologySignature,
    VersionExtractorSpec,
)
from techspecter.fingerprinting.signatures.registry import SignatureRegistry, signature_registry
from techspecter.fingerprinting.signatures.validator import SignatureValidator

__all__ = [
    "ConfidenceModifier",
    "SignatureIndicator",
    "SignatureIndicators",
    "SignatureRegistry",
    "SignatureRule",
    "SignatureValidator",
    "TechnologyCategory",
    "TechnologySignature",
    "TechnologySignatureLoader",
    "VersionExtractorSpec",
    "compile_signature",
    "signature_registry",
]
