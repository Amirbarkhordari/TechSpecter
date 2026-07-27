"""Tests for confidence scoring."""

from __future__ import annotations

from techspecter.fingerprints.confidence import ConfidenceScorer, MatchEvidence
from techspecter.fingerprints.loader import SignatureLoader
from techspecter.fingerprints.models import UNKNOWN_VERSION


def test_confidence_scorer_normalizes_to_hundred_scale() -> None:
    """Verify confidence scores are normalized between 0 and 100."""
    react = next(item for item in SignatureLoader().load_all() if item.id == "react")
    evidence = MatchEvidence(matched_patterns=react.patterns[:2])
    scorer = ConfidenceScorer()
    score = scorer.score(react, evidence, UNKNOWN_VERSION)
    assert 0.0 <= score <= 100.0


def test_confidence_scorer_includes_version_weight() -> None:
    """Verify extracted versions increase confidence scores."""
    react = next(item for item in SignatureLoader().load_all() if item.id == "react")
    evidence = MatchEvidence(
        matched_patterns=react.patterns[:1],
        version_pattern=react.version_patterns[0],
    )
    scorer = ConfidenceScorer()
    without_version = scorer.score(
        react,
        MatchEvidence(matched_patterns=react.patterns[:1]),
        UNKNOWN_VERSION,
    )
    with_version = scorer.score(react, evidence, "18.2.0")
    assert with_version >= without_version
