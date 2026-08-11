"""Global separation of detector/rule metadata from source-derived secret values."""

from __future__ import annotations

import hashlib
import re

from techspecter.sensitive_intelligence.candidates.models import SensitiveCandidate
from techspecter.sensitive_intelligence.models import FindingCategory

_REDACTED_LABEL = re.compile(r"\s*\[redacted\]\s*$", re.I)
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

_PLAINTEXT_CATEGORIES = frozenset(
    {
        FindingCategory.SENSITIVE_CONFIGURATION,
        FindingCategory.DEVELOPER_ARTIFACTS,
        FindingCategory.CONTACT_INFORMATION,
        FindingCategory.OTHER,
    },
)


def normalize_metadata_token(value: str | None) -> str:
    """Normalize identifiers for metadata-vs-value comparisons."""
    if not value:
        return ""
    return _NON_ALNUM.sub("_", value.strip().lower()).strip("_")


def metadata_tokens(candidate: SensitiveCandidate) -> set[str]:
    """Collect rule/detector/credential identifiers that must never be secrets."""
    match = candidate.match
    raw_tokens = {
        candidate.subtype,
        candidate.rule_id,
        candidate.detector_id,
        candidate.credential_name,
        candidate.credential_category,
        match.rule_id,
        match.rule_name,
        match.subtype,
        match.finding_type.value if match.finding_type else None,
        match.category.value if match.category else None,
    }
    tokens: set[str] = set()
    for item in raw_tokens:
        normalized = normalize_metadata_token(item if isinstance(item, str) else None)
        if normalized:
            tokens.add(normalized)
            tokens.add(normalized.replace("_", "-"))
            tokens.add(normalized.replace("_", ""))
    return tokens


def strip_redaction_label(value: str | None) -> str:
    """Remove a trailing ``[redacted]`` display marker."""
    if not value:
        return ""
    return _REDACTED_LABEL.sub("", value).strip()


def is_metadata_as_value(candidate: SensitiveCandidate, value: str | None) -> bool:
    """Return True when *value* is detector/rule metadata rather than content."""
    if value is None:
        return False
    stripped = strip_redaction_label(value)
    if not stripped:
        return False
    token = normalize_metadata_token(stripped)
    if not token:
        return False
    return token in metadata_tokens(candidate)


def source_derived_secret_value(candidate: SensitiveCandidate) -> str | None:
    """Return the source-derived secret payload used for confirmation and reporting.

    Preference order:
    1. ``analysis_value`` (builder/context resolved literal)
    2. ``match.raw_value`` when it is not metadata and not a redaction label
    Never falls back to redacted ``matched_value`` labels or rule identifiers.
    """
    for value in (candidate.analysis_value, candidate.match.raw_value):
        if value is None:
            continue
        text = value.strip()
        if not text:
            continue
        if "[redacted]" in text.lower() and is_metadata_as_value(candidate, text):
            continue
        if is_metadata_as_value(candidate, text):
            continue
        # Credential *names* are not secret values.
        if candidate.credential_name and normalize_metadata_token(
            text,
        ) == normalize_metadata_token(candidate.credential_name):
            continue
        return text
    return None


def has_source_derived_secret(candidate: SensitiveCandidate) -> bool:
    """Return True when confirmation has an actual source-derived payload."""
    return source_derived_secret_value(candidate) is not None


def redact_secret_for_display(value: str) -> str:
    """Build a display-safe form of a source-derived secret (never metadata labels)."""
    text = value.strip()
    if len(text) <= 8:
        return "[redacted]"
    if len(text) <= 16:
        return f"{text[:2]}…{text[-2:]} [redacted]"
    return f"{text[:4]}…{text[-4:]} [redacted]"


def finding_display_value(candidate: SensitiveCandidate) -> str | None:
    """Display value for a confirmed finding: source content, never metadata labels."""
    secret = source_derived_secret_value(candidate)
    if secret is None:
        return None
    category = None
    if candidate.match.category is not None:
        category = candidate.match.category
    elif candidate.credential_category:
        try:
            category = FindingCategory(candidate.credential_category)
        except ValueError:
            category = None
    if category in _PLAINTEXT_CATEGORIES:
        return secret if len(secret) <= 120 else f"{secret[:117]}..."
    return redact_secret_for_display(secret)


def finding_content_key(candidate: SensitiveCandidate, display_value: str) -> str:
    """Stable dedupe key based on source-derived content identity."""
    secret = source_derived_secret_value(candidate) or display_value
    digest = hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()[:32]
    return "|".join(
        [
            candidate.finding_type.value,
            candidate.subtype or "",
            digest,
        ],
    )
