"""Shared pytest fixtures and test isolation helpers."""

from __future__ import annotations

import logging

import pytest

from techspecter.utils.logging import reset_logging


@pytest.fixture(autouse=True)
def isolate_logging() -> None:
    """Reset logging handlers after each test to avoid cross-test interference."""
    yield
    reset_logging()
    logging.getLogger().setLevel(logging.WARNING)
