"""Fingerprinting extension points."""

from techspecter.fingerprinting.extensions.plugin import (
    CollectorPlugin,
    EvidenceProvider,
    EvidenceProviderPlugin,
    FingerprintPluginExtension,
    merge_collections,
)

__all__ = [
    "CollectorPlugin",
    "EvidenceProvider",
    "EvidenceProviderPlugin",
    "FingerprintPluginExtension",
    "merge_collections",
]
