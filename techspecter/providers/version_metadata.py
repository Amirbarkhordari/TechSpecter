"""Version metadata foundation for Phase 6 intelligence."""

from __future__ import annotations

from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.providers.models import ProviderMatch, ProviderVersionMetadata
from techspecter.providers.validation import ProviderOutputValidator


class ProviderVersionMetadataBuilder:
    """Build structured version metadata from provider matches."""

    def __init__(self, *, validator: ProviderOutputValidator | None = None) -> None:
        """Initialize with optional validator."""
        self._validator = validator or ProviderOutputValidator()

    def build(self, match: ProviderMatch) -> ProviderVersionMetadata:
        """Create version metadata for a provider match."""
        if match.version_metadata is not None:
            return match.version_metadata

        raw_version = match.version
        is_known = bool(
            raw_version
            and raw_version != UNKNOWN_VERSION
            and self._validator.is_valid_version(raw_version),
        )
        location = None
        metadata = match.metadata
        if isinstance(metadata.get("source_file"), str):
            location = str(metadata["source_file"])

        evidence = [item for item in match.evidence if "version" in item.lower()]
        if raw_version and raw_version != UNKNOWN_VERSION:
            evidence.append(f"version:{raw_version}")

        return ProviderVersionMetadata(
            version=raw_version if is_known else UNKNOWN_VERSION,
            confidence=match.confidence if is_known else 0.0,
            evidence=evidence,
            provider=match.provider,
            detection_method=match.detection_method,
            location=location,
            raw_version=raw_version,
            is_known=is_known,
        )

    def build_all(self, match: ProviderMatch) -> ProviderMatch:
        """Attach version metadata to a provider match."""
        metadata = self.build(match)
        return match.model_copy(update={"version_metadata": metadata})
