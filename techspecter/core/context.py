"""Shared scan context passed through the processing pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ScanContext:
    """Mutable context object shared across pipeline stages and plugins.

    Attributes:
        target_url: The primary URL under analysis.
        metadata: Arbitrary key-value metadata collected during a scan.
    """

    target_url: str
    metadata: dict[str, Any] = field(default_factory=dict)
