"""Shared CLI formatting helpers for TechSpecter reports."""

from __future__ import annotations

import re

from rich.console import Console
from rich.text import Text

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")

DEFAULT_METRIC_WIDTH = 28
DEFAULT_VALUE_MAX_LEN = 100
DEFAULT_CONTEXT_MAX_LEN = 120


def format_metric_line(label: str, value: int | str, *, width: int = DEFAULT_METRIC_WIDTH) -> str:
    """Format a dot-aligned metric line for CLI summaries."""
    value_text = str(value)
    dot_count = max(1, width - len(label) - len(value_text) - 1)
    return f"{label} {'.' * dot_count} {value_text}"


def normalize_display_value(value: str, *, max_length: int = DEFAULT_VALUE_MAX_LEN) -> str:
    """Trim, collapse whitespace, strip control chars, and truncate long values."""
    cleaned = _CONTROL_CHARS.sub("", value).strip()
    cleaned = _WHITESPACE.sub(" ", cleaned)
    if not cleaned:
        return "-"
    if len(cleaned) <= max_length:
        return cleaned
    return cleaned[: max_length - 3] + "..."


def escape_rich_markup(value: str) -> str:
    """Escape user-controlled text so Rich does not interpret markup."""
    return value.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def print_label_value(
    console: Console, label: str, value: str, *, max_length: int = DEFAULT_VALUE_MAX_LEN
) -> None:
    """Print a bold label followed by a normalized, escaped value."""
    console.print(f"[bold]{label}[/bold] ", end="")
    console.print(Text(escape_rich_markup(normalize_display_value(value, max_length=max_length))))


def format_context_snippet(
    evidence: str | None,
    matched_value: str,
    *,
    max_length: int = DEFAULT_CONTEXT_MAX_LEN,
) -> str:
    """Build a short context snippet around a matched value."""
    if not evidence:
        return "-"
    snippet = normalize_display_value(evidence, max_length=max_length * 2)
    if len(snippet) > max_length:
        snippet = snippet[: max_length - 3] + "..."
    return snippet


def print_context_snippet(
    console: Console,
    evidence: str | None,
    matched_value: str,
    *,
    max_length: int = DEFAULT_CONTEXT_MAX_LEN,
) -> None:
    """Print a context snippet, highlighting the matched portion when found."""
    if not evidence:
        return
    raw = normalize_display_value(evidence, max_length=max_length * 3)
    needle = matched_value.replace(" [redacted]", "").strip()
    console.print("[bold]Context[/bold]")
    console.print("-" * 32)
    if needle and needle != "-" and len(needle) >= 4 and needle in raw:
        start = max(0, raw.index(needle) - 20)
        end = min(len(raw), raw.index(needle) + len(needle) + 20)
        segment = raw[start:end]
        text = Text()
        if start > 0:
            text.append("...")
        before, _, after = segment.partition(needle)
        text.append(escape_rich_markup(before))
        text.append(escape_rich_markup(needle), style="bold")
        text.append(escape_rich_markup(after))
        if end < len(raw):
            text.append("...")
        console.print(text)
    else:
        console.print(Text(escape_rich_markup(format_context_snippet(evidence, matched_value))))
    console.print("")
