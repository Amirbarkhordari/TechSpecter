"""Centralized placeholder detection for sensitive values."""

from __future__ import annotations

import re

# Exact placeholders after normalization (lowercase, separators → underscore).
_EXACT_PLACEHOLDERS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "changeme",
        "change_me",
        "change_me_now",
        "changeit",
        "placeholder",
        "example",
        "sample",
        "dummy",
        "fake",
        "default",
        "null",
        "none",
        "undefined",
        "test",
        "testing",
        "todo",
        "fixme",
        "redacted",
        "secret123",
        "password123",
        "passw0rd",
        "123456",
        "12345678",
        "123456789",
        "qwerty",
        "admin",
        "root",
        "user",
        "username",
        "login",
        "guest",
        "invalid_password",
        "your_password",
        "your_password_here",
        "your_api_key",
        "your_api_key_here",
        "your_secret",
        "your_secret_here",
        "your_token",
        "your_token_here",
        "insert_password",
        "enter_password",
        "replace_me",
        "replace_me_now",
        "password_here",
        "api_key_here",
        "secret_here",
        "token_here",
        "xxx",
        "xxxx",
        "xxxxx",
    },
)

_INSTRUCTIONAL_PREFIXES = (
    "your_",
    "example_",
    "sample_",
    "dummy_",
    "fake_",
    "replace_",
    "insert_",
    "enter_",
    "change_",
    "put_",
    "set_",
)

_INSTRUCTIONAL_SUFFIXES = (
    "_here",
    "_placeholder",
    "_example",
    "_sample",
    "_todo",
)

_ANGLE_PLACEHOLDER = re.compile(r"^<[^>]{2,80}>$")
_BRACE_PLACEHOLDER = re.compile(r"^\{\{[^}]{1,80}\}\}$")
_X_MASK = re.compile(r"^x{3,}$", re.I)
_STAR_MASK = re.compile(r"[*]{3,}")
_WEAK_PASSWORD_STEM = re.compile(
    r"^(?:password|passwd|pwd|secret|token|apikey|api_key)(?:\d{0,4}|123|!+)?$",
    re.I,
)


def normalize_placeholder_token(value: str) -> str:
    """Normalize separators/case so YOUR_API_KEY and your api key compare equal."""
    lowered = value.strip().lower()
    lowered = lowered.strip("\"'`")
    # Strip common angle/brace wrappers for comparison of inner token.
    if lowered.startswith("<") and lowered.endswith(">") and len(lowered) > 2:
        lowered = lowered[1:-1]
    if lowered.startswith("{{") and lowered.endswith("}}") and len(lowered) > 4:
        lowered = lowered[2:-2]
    normalized = re.sub(r"[\s\-./]+", "_", lowered)
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return normalized


def is_placeholder_value(value: str | None) -> bool:
    """Return True when a value is an obvious placeholder/example token."""
    if value is None:
        return False
    stripped = value.strip()
    if not stripped:
        return False

    if _ANGLE_PLACEHOLDER.match(stripped) or _BRACE_PLACEHOLDER.match(stripped):
        return True
    if _X_MASK.fullmatch(stripped) or _STAR_MASK.fullmatch(stripped):
        return True

    normalized = normalize_placeholder_token(stripped)
    if not normalized:
        return True
    if normalized in _EXACT_PLACEHOLDERS:
        return True
    if any(normalized.startswith(prefix) for prefix in _INSTRUCTIONAL_PREFIXES):
        # Avoid treating realistic secrets that merely start with "set_" etc. as placeholders
        # unless the remainder is instructional/credential-shaped.
        remainder = normalized
        for prefix in _INSTRUCTIONAL_PREFIXES:
            if normalized.startswith(prefix):
                remainder = normalized[len(prefix) :]
                break
        if remainder in _EXACT_PLACEHOLDERS or remainder in {
            "password",
            "api_key",
            "apikey",
            "secret",
            "token",
            "key",
            "me",
            "me_now",
        }:
            return True
        if remainder.endswith(tuple(_INSTRUCTIONAL_SUFFIXES)):
            return True
    if any(normalized.endswith(suffix) for suffix in _INSTRUCTIONAL_SUFFIXES):
        return True
    if _WEAK_PASSWORD_STEM.fullmatch(normalized):
        return True
    return False


def is_example_value(value: str | None) -> bool:
    """Return True when a value is explicitly an example/sample token."""
    if value is None:
        return False
    normalized = normalize_placeholder_token(value)
    return (
        normalized in {"example", "sample", "dummy", "fake"}
        or normalized.startswith(("example_", "sample_", "dummy_", "fake_"))
        or "example" in normalized
        and len(normalized) <= 24
    )
