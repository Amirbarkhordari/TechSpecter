"""Version extraction confidence scoring."""

from __future__ import annotations

from techspecter.versioning.models import VersionConfidenceLevel, VersionEvidenceType

_METHOD_WEIGHTS: dict[VersionEvidenceType, float] = {
    VersionEvidenceType.RUNTIME_CONSTANT: 95.0,
    VersionEvidenceType.FRAMEWORK_OBJECT: 92.0,
    VersionEvidenceType.PACKAGE_IDENTIFIER: 90.0,
    VersionEvidenceType.PACKAGE_MANIFEST: 89.0,
    VersionEvidenceType.BUILD_METADATA: 88.0,
    VersionEvidenceType.TECHNOLOGY_MARKER: 86.0,
    VersionEvidenceType.METADATA: 85.0,
    VersionEvidenceType.BANNER: 80.0,
    VersionEvidenceType.SOURCE_MAP: 75.0,
    VersionEvidenceType.ASSET_FILENAME: 70.0,
    VersionEvidenceType.REFERENCE: 50.0,
    VersionEvidenceType.GENERIC_LITERAL: 55.0,
    VersionEvidenceType.UNKNOWN: 40.0,
}

# Methods that may participate in primary confirmation (ownership still required).
_CONFIRMABLE_METHODS = frozenset(
    {
        VersionEvidenceType.RUNTIME_CONSTANT,
        VersionEvidenceType.FRAMEWORK_OBJECT,
        VersionEvidenceType.PACKAGE_IDENTIFIER,
        VersionEvidenceType.PACKAGE_MANIFEST,
        VersionEvidenceType.BUILD_METADATA,
        VersionEvidenceType.TECHNOLOGY_MARKER,
        VersionEvidenceType.METADATA,
        VersionEvidenceType.BANNER,
        VersionEvidenceType.SOURCE_MAP,
        VersionEvidenceType.ASSET_FILENAME,
    },
)

# Source labels that are reference/weak observations only when paired with
# weak methods or low priority. Dedicated version_candidate evidence uses its
# own source label and is not listed here.
_WEAK_SOURCE_LABELS = frozenset(
    {
        "bundle",
        "inline",
        "global",
        "minified",
        "regex",
        "unknown",
        "reference",
        "generic_literal",
    },
)

# Minimum extractor/evidence priority before a candidate can confirm a primary.
_MIN_CONFIRMABLE_PRIORITY = 65.0


def score_method(method: VersionEvidenceType) -> tuple[float, VersionConfidenceLevel]:
    """Return numeric confidence and level for an extraction method."""
    confidence = _METHOD_WEIGHTS.get(method, 60.0)
    if confidence >= 90.0:
        level = VersionConfidenceLevel.HIGH
    elif confidence >= 75.0:
        level = VersionConfidenceLevel.MEDIUM
    else:
        level = VersionConfidenceLevel.LOW
    return confidence, level


def method_supports_confirmation(method: VersionEvidenceType | str | None) -> bool:
    """Return True when an extraction method is strong enough to confirm."""
    if method is None:
        return True  # Evidence-path candidates rely on source/priority instead.
    if isinstance(method, VersionEvidenceType):
        return method in _CONFIRMABLE_METHODS
    try:
        return VersionEvidenceType(str(method)) in _CONFIRMABLE_METHODS
    except ValueError:
        normalized = str(method).strip().lower()
        if normalized in {item.value for item in _CONFIRMABLE_METHODS}:
            return True
        return normalized not in {
            VersionEvidenceType.REFERENCE.value,
            VersionEvidenceType.GENERIC_LITERAL.value,
            VersionEvidenceType.UNKNOWN.value,
        }


def evidence_quality_supports_confirmation(
    *,
    source: str | None,
    priority: float,
    evidence_type: str | None = None,
    method: VersionEvidenceType | str | None = None,
) -> bool:
    """Return True when evidence quality alone may support primary confirmation.

    Ownership remains a separate gate. Weak reference/literal observations must
    not enter the strong-conflict path merely because ownership was stamped high.
    """
    resolved_method = method if method is not None else evidence_type
    if resolved_method is not None and not method_supports_confirmation(resolved_method):
        # Explicit weak extractor methods never confirm.
        try:
            as_enum = (
                resolved_method
                if isinstance(resolved_method, VersionEvidenceType)
                else VersionEvidenceType(str(resolved_method))
            )
        except ValueError:
            as_enum = None
        if as_enum in {
            VersionEvidenceType.REFERENCE,
            VersionEvidenceType.GENERIC_LITERAL,
            VersionEvidenceType.UNKNOWN,
        } or str(resolved_method).lower() in {
            VersionEvidenceType.REFERENCE.value,
            VersionEvidenceType.GENERIC_LITERAL.value,
            VersionEvidenceType.UNKNOWN.value,
        }:
            return False
    if priority < _MIN_CONFIRMABLE_PRIORITY:
        return False
    if source and source.strip().lower() in _WEAK_SOURCE_LABELS:
        return False
    return True
