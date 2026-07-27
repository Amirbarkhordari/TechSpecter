"""Tests for expanded fingerprint database coverage."""

from __future__ import annotations

from techspecter.fingerprinting.loader import SignatureLoader


def test_database_contains_minimum_technology_count() -> None:
    """Verify the expanded database includes at least 60 technologies."""
    fingerprints = SignatureLoader().load_all(reload=True)
    assert len(fingerprints) >= 60


def test_database_contains_required_technologies() -> None:
    """Verify key technologies from Phase 3B are present."""
    ids = {item.id for item in SignatureLoader().load_all(reload=True)}
    required = {
        "react",
        "reactdom",
        "vue",
        "angular",
        "tailwindcss",
        "lodash",
        "axios",
        "chartjs",
        "d3",
        "monaco",
        "webpack",
        "vite",
        "nextjs",
        "remix",
        "gatsby",
    }
    missing = required - ids
    assert not missing, f"Missing fingerprints: {missing}"


def test_all_fingerprints_have_unique_ids() -> None:
    """Verify every loaded fingerprint has a unique identifier."""
    fingerprints = SignatureLoader().load_all(reload=True)
    ids = [item.id for item in fingerprints]
    assert len(ids) == len(set(ids))
