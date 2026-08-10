"""Centralized runtime / empty / self-reference detection."""

from __future__ import annotations

import re

_EMPTY_LITERALS = frozenset(
    {
        "",
        '""',
        "''",
        "``",
        "null",
        "none",
        "undefined",
        "nil",
        "n/a",
        "na",
    },
)

_RUNTIME_VALUE = re.compile(
    r"""^(?:
        process\.env(?:\.[A-Za-z_][\w]*|\[['\"][^'\"]+['\"]\]) |
        env(?:ironment)?(?:\.[A-Za-z_][\w]*|\[['\"][^'\"]+['\"]\]) |
        ENV(?:\.[A-Za-z_][\w]*|\[['\"][^'\"]+['\"]\]) |
        (?:config|settings|secrets?|credentials)\.[A-Za-z_][\w.]* |
        (?:os\.environ(?:\.get)?\([^)]*\) |
           os\.getenv\([^)]*\)) |
        (?:get|load|read|fetch|resolve)(?:Secret|Token|Password|Credential|ApiKey|Key)s?\s*\([^)]*\) |
        (?:form\.[A-Za-z_][\w.]*\.value |
           [A-Za-z_][\w.]*\.password\.value |
           getElementById\([^)]+\)\.value |
           querySelector\([^)]+\)\.value)
    )$""",
    re.I | re.VERBOSE,
)

_RUNTIME_ASSIGNMENT = re.compile(
    r"""(?:password|passwd|pwd|username|user_name|login|token|secret|api[_-]?key|key|sid|client_secret)"""
    r"""\s*[:=]\s*(?!['\"])"""
    r"""(
        process\.env(?:\.[A-Za-z_][\w]*|\[['\"][^'\"]+['\"]\]) |
        env(?:ironment)?(?:\.[A-Za-z_][\w]*|\[['\"][^'\"]+['\"]\]) |
        ENV(?:\.[A-Za-z_][\w]*|\[['\"][^'\"]+['\"]\]) |
        (?:config|settings|secrets?|credentials)\.[A-Za-z_][\w.]* |
        (?:get|load|read|fetch|resolve)(?:Secret|Token|Password|Credential|ApiKey|Key)s?\s*\([^)]*\) |
        [A-Za-z_$][\w.$]*(?:\([^)]*\))?
    )""",
    re.I | re.VERBOSE,
)

_SELF_ASSIGNMENT = re.compile(
    r"""\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|key|username|client_secret)\b"""
    r"""\s*[:=]\s*\1\b""",
    re.I,
)

_FORM_VALUE = re.compile(
    r"""(?:form\.[A-Za-z_][\w.]*\.value|[A-Za-z_][\w.]*\.password\.value)"""
    r"""|getElementById\([^)]+\)\.value|querySelector\([^)]+\)\.value""",
    re.I,
)

_TEMPLATE_VALUE = re.compile(
    r"""(?:\{\{[^}]+\}\}|\$\{[^}]+\}|<%=?[^%]+%>|^__\w+__$|^<<\w+>>$)""",
)

_SECRET_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "key",
        "apikey",
        "api_key",
        "username",
        "client_secret",
        "access_token",
        "refresh_token",
    },
)


def is_empty_literal(value: str | None) -> bool:
    """Return True for empty / null / undefined-style values."""
    if value is None:
        return False
    stripped = value.strip()
    return stripped.lower() in _EMPTY_LITERALS


def is_form_reference(value: str | None, *, evidence: str | None = None) -> bool:
    """Return True when the value or evidence points at an HTML/form field."""
    if value and (_FORM_VALUE.search(value) or value.strip().endswith(".value")):
        return True
    if evidence and _FORM_VALUE.search(evidence):
        return True
    return False


def is_template_value(value: str | None) -> bool:
    """Return True for generated/template placeholders."""
    if not value:
        return False
    return bool(_TEMPLATE_VALUE.search(value.strip()))


def is_runtime_reference(value: str | None, *, evidence: str | None = None) -> bool:
    """Return True for strong runtime configuration / loader references."""
    if value:
        stripped = value.strip()
        if _RUNTIME_VALUE.match(stripped):
            return True
        lowered = stripped.lower()
        if lowered.startswith(("process.env", "env.", "environment.", "config.", "settings.", "secrets.")):
            return True
        # Object property paths such as config.password / settings.secret.
        if re.fullmatch(r"[A-Za-z_$][\w]*\.(?:password|passwd|pwd|secret|token|key|value|api_?key)", stripped, re.I):
            return True
    if evidence and _RUNTIME_ASSIGNMENT.search(evidence):
        # Ignore when the same snippet also has a quoted literal assignment.
        if not re.search(
            r"""(?:password|passwd|pwd|token|secret|api[_-]?key|key|client_secret)\s*[:=]\s*['\"][^'\"]+['\"]""",
            evidence,
            re.I,
        ):
            return True
    return False


def is_self_reference(
    value: str | None,
    *,
    evidence: str | None = None,
    credential_name: str | None = None,
    subtype: str | None = None,
) -> bool:
    """Return True when a value refers to itself (token = token)."""
    if evidence and _SELF_ASSIGNMENT.search(evidence):
        return True
    if not value:
        return False
    token = value.strip().lower()
    names = set(_SECRET_NAMES)
    if credential_name:
        names.add(credential_name.strip().lower())
    if subtype:
        names.add(subtype.lower().replace("-", "_"))
    return token in names


def extract_runtime_target(evidence: str | None) -> str | None:
    """Return the RHS runtime expression when present."""
    if not evidence:
        return None
    match = _RUNTIME_ASSIGNMENT.search(evidence)
    if not match:
        return None
    return match.group(1).strip()
