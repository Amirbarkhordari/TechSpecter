"""Signature validation utilities."""

from __future__ import annotations

import logging
import re

from techspecter.fingerprinting.signatures.models import (
    SignatureIndicators,
    SignatureRule,
    TechnologySignature,
)

logger = logging.getLogger(__name__)


class SignatureValidationError(ValueError):
    """Raised when a signature fails platform validation."""


class SignatureValidator:
    """Validate signature quality and consistency."""

    def validate(self, signature: TechnologySignature) -> list[str]:
        """Return validation warnings for a signature."""
        warnings: list[str] = []
        warnings.extend(self._validate_rules(signature.positive_rules, label="positive"))
        warnings.extend(self._validate_rules(signature.required_rules, label="required"))
        warnings.extend(self._validate_version_extractors(signature))
        warnings.extend(self._validate_quality(signature))
        return warnings

    def validate_or_raise(self, signature: TechnologySignature) -> None:
        """Validate signature and raise on critical issues."""
        warnings = self.validate(signature)
        critical = [item for item in warnings if item.startswith("CRITICAL:")]
        if critical:
            raise SignatureValidationError("; ".join(critical))
        for warning in warnings:
            logger.debug("Signature '%s' validation: %s", signature.id, warning)

    def _validate_rules(self, rules: tuple[SignatureRule, ...], *, label: str) -> list[str]:
        """Validate rule patterns."""
        warnings: list[str] = []
        for rule in rules:
            if rule.matcher == "regex":
                try:
                    re.compile(rule.pattern)
                except re.error as exc:
                    warnings.append(f"CRITICAL: invalid {label} regex '{rule.id}': {exc}")
            if len(rule.pattern.strip()) < 2:
                warnings.append(f"weak {label} pattern '{rule.id}'")
        return warnings

    def _validate_version_extractors(self, signature: TechnologySignature) -> list[str]:
        """Validate version extractor patterns."""
        warnings: list[str] = []
        for spec in signature.version_extractors:
            if not spec.enabled:
                continue
            try:
                re.compile(spec.pattern)
            except re.error as exc:
                warnings.append(f"CRITICAL: invalid version extractor '{spec.id}': {exc}")
        return warnings

    def _validate_quality(self, signature: TechnologySignature) -> list[str]:
        """Validate overall signature quality heuristics."""
        warnings: list[str] = []
        total_positive = len(signature.positive_rules) + len(signature.optional_rules)
        indicator_count = sum(
            len(getattr(signature.optional_evidence, field))
            for field in SignatureIndicators.model_fields
        )
        if total_positive + indicator_count < 2 and not signature.required_rules:
            warnings.append(f"weak signature '{signature.id}': fewer than 2 positive indicators")
        if not signature.version_extractors:
            warnings.append(f"no version extractors for '{signature.id}'")
        if not signature.references and not signature.website:
            warnings.append(f"missing references for '{signature.id}'")
        return warnings
