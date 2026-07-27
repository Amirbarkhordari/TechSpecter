"""Tests for fingerprint database validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from techspecter.exceptions import InvalidFingerprintError
from techspecter.fingerprinting.loader import SignatureLoader
from techspecter.fingerprinting.validator import (
    FingerprintValidator,
    validate_fingerprints_or_raise,
)


def test_validator_accepts_bundled_database() -> None:
    """Verify the bundled fingerprint database passes validation."""
    report = FingerprintValidator().validate_all()
    assert report.is_valid
    assert report.valid_count >= 60
    assert report.error_count == 0


def test_validator_detects_broken_json(tmp_path: Path) -> None:
    """Verify broken JSON files produce validation errors."""
    (tmp_path / "broken.json").write_text("{invalid", encoding="utf-8")
    report = FingerprintValidator(tmp_path).validate_all()
    assert not report.is_valid
    assert report.error_count >= 1


def test_validator_detects_duplicate_ids(tmp_path: Path) -> None:
    """Verify duplicate fingerprint IDs are reported."""
    payload = {
        "id": "dup",
        "name": "Dup",
        "category": "library",
        "patterns": [{"matcher": "string", "pattern": "dup"}],
    }
    (tmp_path / "one.json").write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "two.json").write_text(json.dumps(payload), encoding="utf-8")
    report = FingerprintValidator(tmp_path).validate_all()
    assert not report.is_valid
    assert any("Duplicate ID" in issue.message for issue in report.issues)


def test_validator_detects_invalid_regex(tmp_path: Path) -> None:
    """Verify invalid regex patterns are reported."""
    payload = {
        "id": "bad",
        "name": "Bad",
        "category": "library",
        "patterns": [{"matcher": "regex", "pattern": "(unclosed", "weight": 10}],
    }
    (tmp_path / "bad.json").write_text(json.dumps(payload), encoding="utf-8")
    report = FingerprintValidator(tmp_path).validate_all()
    assert not report.is_valid


def test_validate_fingerprints_or_raise_success() -> None:
    """Verify validate_fingerprints_or_raise returns report when valid."""
    report = validate_fingerprints_or_raise()
    assert report.valid_count >= 60


def test_validate_fingerprints_or_raise_failure(tmp_path: Path) -> None:
    """Verify validate_fingerprints_or_raise raises on invalid database."""
    (tmp_path / "broken.json").write_text("{", encoding="utf-8")
    with pytest.raises(InvalidFingerprintError):
        validate_fingerprints_or_raise(tmp_path)


def test_database_has_expected_categories() -> None:
    """Verify the database includes technologies from major categories."""
    fingerprints = SignatureLoader().load_all(reload=True)
    categories = {item.category for item in fingerprints}
    assert "framework" in categories
    assert "css-framework" in categories
    assert "library" in categories
    assert "visualization" in categories
    assert "build-tool" in categories
    assert "meta-framework" in categories
