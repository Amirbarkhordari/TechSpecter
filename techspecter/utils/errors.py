"""User-facing error formatting helpers."""

from __future__ import annotations

from techspecter.exceptions import TechSpecterError


def format_user_error(exc: Exception, *, debug: bool = False) -> str:
    """Format an exception for CLI display without exposing stack traces by default."""
    if isinstance(exc, TechSpecterError):
        return str(exc)
    if debug:
        return f"{type(exc).__name__}: {exc}"
    return "An unexpected error occurred. Re-run with --debug for details."
