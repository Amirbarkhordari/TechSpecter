"""Tests for fingerprint signature loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from techspecter.exceptions import FingerprintLoadError
from techspecter.fingerprinting.loader import SignatureLoader, resolve_signatures_directory


def test_resolve_signatures_directory_uses_bundled_fingerprints() -> None:
    """Verify the default fingerprints directory resolves to the bundled database."""
    path = resolve_signatures_directory()
    assert path.name == "fingerprints"
    assert (path / "react.json").is_file()


def test_signature_loader_loads_all_technologies() -> None:
    """Verify all bundled fingerprint signatures load successfully."""
    loader = SignatureLoader()
    fingerprints = loader.load_all(reload=True)
    ids = {item.id for item in fingerprints}
    assert "react" in ids
    assert "vue" in ids
    assert "jquery" in ids
    assert len(fingerprints) >= 60


def test_signature_loader_ignores_malformed_file(tmp_path: Path) -> None:
    """Verify malformed JSON files are ignored without failing the load."""
    (tmp_path / "valid.json").write_text(
        json.dumps(
            {
                "id": "valid",
                "name": "Valid",
                "category": "library",
                "patterns": [{"matcher": "string", "pattern": "valid"}],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "broken.json").write_text("{not-json", encoding="utf-8")
    loader = SignatureLoader(tmp_path)
    fingerprints = loader.load_all()
    assert len(fingerprints) == 1
    assert fingerprints[0].id == "valid"


def test_signature_loader_rejects_duplicate_ids(tmp_path: Path) -> None:
    """Verify duplicate fingerprint IDs are ignored."""
    payload = {
        "id": "dup",
        "name": "Duplicate",
        "category": "library",
        "patterns": [{"matcher": "string", "pattern": "dup"}],
    }
    (tmp_path / "one.json").write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "two.json").write_text(json.dumps(payload), encoding="utf-8")
    loader = SignatureLoader(tmp_path)
    fingerprints = loader.load_all()
    assert len(fingerprints) == 1


def test_signature_loader_raises_when_directory_missing(tmp_path: Path) -> None:
    """Verify missing signatures directories raise FingerprintLoadError."""
    with pytest.raises(FingerprintLoadError):
        SignatureLoader(tmp_path / "missing")
