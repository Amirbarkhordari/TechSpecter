"""Resilience utilities for optional external detection providers."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from techspecter.configuration.models import ProviderEntryConfig

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ExternalProviderPolicy:
    """Timeout and retry policy for optional external providers."""

    timeout_seconds: int = 120
    retry_count: int = 0
    retry_delay_seconds: float = 1.0

    @classmethod
    def from_config(cls, config: ProviderEntryConfig) -> ExternalProviderPolicy:
        """Build policy from provider configuration."""
        return cls(
            timeout_seconds=config.timeout_seconds,
            retry_count=config.retry_count,
            retry_delay_seconds=config.retry_delay_seconds,
        )


@dataclass(slots=True)
class ExternalProviderRunner:
    """Execute external provider operations with timeout, retry, and logging."""

    provider_id: str
    policy: ExternalProviderPolicy = ExternalProviderPolicy()

    def run(
        self,
        operation: Callable[[], T],
        *,
        target_url: str,
        operation_name: str = "detect",
    ) -> T:
        """Run an operation with configured retries and structured logging."""
        attempts = self.policy.retry_count + 1
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            started = time.perf_counter()
            try:
                result = operation()
                elapsed_ms = (time.perf_counter() - started) * 1000
                logger.info(
                    "External provider operation succeeded",
                    extra=self._log_context(
                        target_url=target_url,
                        operation=operation_name,
                        attempt=attempt,
                        elapsed_ms=elapsed_ms,
                        status="success",
                    ),
                )
                return result
            except Exception as exc:
                last_error = exc
                elapsed_ms = (time.perf_counter() - started) * 1000
                logger.warning(
                    "External provider operation failed",
                    extra=self._log_context(
                        target_url=target_url,
                        operation=operation_name,
                        attempt=attempt,
                        elapsed_ms=elapsed_ms,
                        status="failure",
                        error=str(exc),
                        will_retry=attempt < attempts,
                    ),
                )
                if attempt < attempts and self.policy.retry_delay_seconds > 0:
                    time.sleep(self.policy.retry_delay_seconds)

        assert last_error is not None
        raise last_error

    def _log_context(self, **fields: Any) -> dict[str, Any]:
        """Build structured logging context."""
        return {
            "provider_id": self.provider_id,
            **fields,
        }
