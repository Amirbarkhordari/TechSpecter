"""Validation helpers that translate internal errors to public exceptions."""

from __future__ import annotations

from pydantic import ValidationError as PydanticValidationError

from techspecter.exceptions import InvalidTargetUrlError, ValidationError
from techspecter.models.discovery import ScriptResource, Target


def _format_pydantic_error(exc: PydanticValidationError) -> str:
    """Convert a Pydantic validation error into a readable message.

    Args:
        exc: Original Pydantic validation error.

    Returns:
        Human-readable validation error message.
    """
    messages = [error.get("msg", "Invalid value") for error in exc.errors()]
    return "; ".join(messages)


def build_target(*, url: str, original_url: str) -> Target:
    """Create a ``Target`` model without leaking Pydantic exceptions.

    Args:
        url: Normalized target URL string.
        original_url: Original user-provided URL string.

    Returns:
        Validated ``Target`` instance.

    Raises:
        InvalidTargetUrlError: If the URL cannot be validated by the model layer.
    """
    try:
        return Target(url=url, original_url=original_url)  # type: ignore[arg-type]
    except PydanticValidationError as exc:
        msg = f"Invalid target URL '{original_url}': {_format_pydantic_error(exc)}"
        raise InvalidTargetUrlError(msg) from None


def build_script_resource(*, url: str, original_url: str) -> ScriptResource:
    """Create a ``ScriptResource`` model without leaking Pydantic exceptions.

    Args:
        url: Absolute script URL string.
        original_url: Script URL as discovered in HTML.

    Returns:
        Validated ``ScriptResource`` instance.

    Raises:
        ValidationError: If the script URL cannot be validated by the model layer.
    """
    try:
        return ScriptResource(url=url, original_url=original_url)  # type: ignore[arg-type]
    except PydanticValidationError as exc:
        msg = f"Invalid script URL '{original_url}': {_format_pydantic_error(exc)}"
        raise ValidationError(msg) from None
