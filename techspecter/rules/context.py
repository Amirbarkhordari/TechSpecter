"""Rule execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RuleExecutionContext:
    """Data passed to the rule engine during execution."""

    target_url: str
    content: str | None = None
    headers: dict[str, str] | None = None
    filename: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def header_items(self) -> list[tuple[str, str]]:
        """Return normalized header key/value pairs."""
        if not self.headers:
            return []
        return [(key, value) for key, value in self.headers.items()]
