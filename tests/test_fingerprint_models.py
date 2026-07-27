"""Tests for fingerprint data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from techspecter.fingerprints.models import Fingerprint, Pattern, Technology, TechnologyMatch


def test_fingerprint_model_accepts_extra_fields() -> None:
    """Verify fingerprint models allow future schema extensions."""
    fingerprint = Fingerprint(
        id="test",
        name="Test",
        category="library",
        patterns=[Pattern(matcher="string", pattern="test")],
        future_field="enabled",
    )
    assert fingerprint.id == "test"


def test_fingerprint_model_rejects_invalid_matcher() -> None:
    """Verify invalid matcher types are rejected by the model."""
    with pytest.raises(PydanticValidationError):
        Pattern(matcher="invalid", pattern="test")  # type: ignore[arg-type]


def test_technology_match_confidence_bounds() -> None:
    """Verify technology match confidence must remain within 0-100."""
    TechnologyMatch(
        technology=Technology(id="x", name="X", category="library"),
        confidence=100.0,
        version="1.0.0",
    )
    with pytest.raises(PydanticValidationError):
        TechnologyMatch(
            technology=Technology(id="x", name="X", category="library"),
            confidence=101.0,
            version="1.0.0",
        )
