"""Safe console rendering helpers for sensitive intelligence output."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text


def escape_rich_markup(value: str) -> str:
    """Escape user-controlled text so Rich does not interpret markup."""
    return value.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def print_label_value(console: Console, label: str, value: str) -> None:
    """Print a bold label followed by escaped user content."""
    console.print(f"[bold]{label}[/bold] ", end="")
    console.print(Text(escape_rich_markup(value)))
