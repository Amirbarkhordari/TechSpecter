"""Reusable indicator patterns for signature authoring."""

from __future__ import annotations

from techspecter.fingerprinting.signatures.models import SignatureIndicator, VersionExtractorSpec

SEMVER = r"([0-9]+(?:\.[0-9]+){1,3}(?:[-+][\\w.-]+)?)"


def ind(
    id: str,
    pattern: str,
    *,
    weight: float = 70.0,
    matcher: str = "contains",
    description: str | None = None,
) -> SignatureIndicator:
    """Create a signature indicator."""
    return SignatureIndicator(
        id=id,
        pattern=pattern,
        weight=weight,
        matcher=matcher,
        description=description,
    )


def ver(
    id: str,
    pattern: str,
    *,
    source: str = "banner",
    weight: float = 90.0,
) -> VersionExtractorSpec:
    """Create a version extractor spec."""
    return VersionExtractorSpec(
        id=id,
        pattern=pattern,
        source=source,
        weight=weight,
        enabled=True,
    )


def req_regex(tech_id: str, pattern: str, *, description: str | None = None) -> dict[str, object]:
    """Create a required regex rule payload."""
    return {
        "id": f"{tech_id}-required",
        "matcher": "regex",
        "pattern": pattern,
        "target": "content",
        "weight": 1.0,
        "description": description or f"{tech_id} required signal",
    }
