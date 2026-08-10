"""Provider output validation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.providers.models import ProviderDetectionResult, ProviderMatch
from techspecter.versioning.validator import is_valid_version as is_valid_technology_version

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ValidationOutcome:
    """Result of validating provider output."""

    matches: list[ProviderMatch] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rejected_count: int = 0

    def apply_to_result(self, result: ProviderDetectionResult) -> ProviderDetectionResult:
        """Return a copy of the provider result with validated matches."""
        return result.model_copy(update={"matches": self.matches})


class ProviderOutputValidator:
    """Validate and sanitize provider matches before merge."""

    def validate_matches(self, matches: list[ProviderMatch], *, provider: str) -> ValidationOutcome:
        """Validate normalized provider matches."""
        valid: list[ProviderMatch] = []
        warnings: list[str] = []
        rejected = 0
        seen_ids: set[str] = set()

        for index, match in enumerate(matches):
            issues = self._validate_match(match)
            if issues:
                rejected += 1
                warnings.extend(f"{provider}[{index}]: {issue}" for issue in issues)
                continue
            if match.technology_id in seen_ids:
                warnings.append(
                    f"{provider}[{index}]: duplicate technology '{match.technology_id}' suppressed",
                )
                continue
            seen_ids.add(match.technology_id)
            valid.append(self._sanitize_match(match))

        if rejected:
            logger.info(
                "Provider validation rejected matches",
                extra={
                    "provider_id": provider,
                    "rejected_count": rejected,
                    "accepted_count": len(valid),
                },
            )
        return ValidationOutcome(matches=valid, warnings=warnings, rejected_count=rejected)

    def validate_wappalyzer_payload(
        self,
        payload: dict[str, Any] | list[Any],
    ) -> list[str]:
        """Validate raw Wappalyzer JSON structure."""
        warnings: list[str] = []
        if isinstance(payload, list):
            if not payload:
                warnings.append("Wappalyzer payload is an empty list")
            return warnings
        if not isinstance(payload, dict):
            warnings.append(f"Unsupported Wappalyzer payload type: {type(payload).__name__}")
            return warnings
        if not any(key in payload for key in ("technologies", "urls", "applications")):
            warnings.append("Wappalyzer payload missing known technology keys")
        return warnings

    def validate_retirejs_payload(self, payload: list[Any]) -> list[str]:
        """Validate raw Retire.js JSON structure."""
        warnings: list[str] = []
        if not payload:
            warnings.append("Retire.js payload is empty")
            return warnings
        for index, entry in enumerate(payload):
            if not isinstance(entry, dict):
                warnings.append(f"Retire.js entry[{index}] is not an object")
                continue
            results = entry.get("results")
            if results is not None and not isinstance(results, list):
                warnings.append(f"Retire.js entry[{index}] results is not a list")
        return warnings

    def _validate_match(self, match: ProviderMatch) -> list[str]:
        """Return validation issues for a single match."""
        issues: list[str] = []
        if not match.technology_id.strip():
            issues.append("missing technology_id")
        if not match.name.strip():
            issues.append("missing name")
        if match.confidence < 0.0 or match.confidence > 100.0:
            issues.append(f"invalid confidence: {match.confidence}")
        if match.version not in (UNKNOWN_VERSION, "") and not self._is_valid_version(match.version):
            issues.append(f"malformed version: {match.version}")
        return issues

    def _sanitize_match(self, match: ProviderMatch) -> ProviderMatch:
        """Clamp and normalize safe match fields."""
        confidence = max(0.0, min(100.0, match.confidence))
        version = match.version
        if version and version != UNKNOWN_VERSION and not self._is_valid_version(version):
            version = UNKNOWN_VERSION
        return match.model_copy(update={"confidence": confidence, "version": version})

    def is_valid_version(self, value: str) -> bool:
        """Return whether a version string is well-formed."""
        if not value or value.strip() == UNKNOWN_VERSION:
            return False
        return is_valid_technology_version(value)

    def _is_valid_version(self, value: str) -> bool:
        return self.is_valid_version(value)
