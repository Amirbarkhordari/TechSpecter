"""Confidence score utilities for analysis findings."""

from __future__ import annotations


def clamp_confidence(value: float) -> float:
    """Clamp a confidence score to the 0–100 range."""
    return max(0.0, min(100.0, value))


def normalize_confidence(value: float) -> float:
    """Normalize a confidence score to two decimal places within 0–100."""
    return round(clamp_confidence(value), 2)
