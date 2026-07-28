"""Shared external provider execution lifecycle."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from techspecter.providers.external import ExternalProviderPolicy, ExternalProviderRunner
from techspecter.providers.health import log_health_report
from techspecter.providers.models import (
    ProviderDetectionResult,
    ProviderHealthState,
    ProviderHealthStatus,
    ProviderTarget,
)
from techspecter.providers.validation import ProviderOutputValidator

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ExternalProviderLifecycle:
    """Reusable lifecycle for optional external detection providers."""

    provider_id: str
    display_name: str
    policy: ExternalProviderPolicy = field(default_factory=ExternalProviderPolicy)
    validator: ProviderOutputValidator = field(default_factory=ProviderOutputValidator)

    def check_health(
        self,
        *,
        is_available: Callable[[], bool],
        backend_id: str | None = None,
        backend_version: Callable[[], str | None] | None = None,
        unavailable_reason: str = "Backend unavailable",
    ) -> ProviderHealthStatus:
        """Evaluate provider health before execution."""
        try:
            available = is_available()
        except Exception as exc:
            return ProviderHealthStatus(
                provider_id=self.provider_id,
                display_name=self.display_name,
                state=ProviderHealthState.UNAVAILABLE,
                backend_id=backend_id,
                reason=str(exc),
            )

        if not available:
            return ProviderHealthStatus(
                provider_id=self.provider_id,
                display_name=self.display_name,
                state=ProviderHealthState.SKIPPED,
                backend_id=backend_id,
                reason=unavailable_reason,
            )

        version = None
        if backend_version is not None:
            try:
                version = backend_version()
            except Exception:
                version = None

        return ProviderHealthStatus(
            provider_id=self.provider_id,
            display_name=self.display_name,
            state=ProviderHealthState.AVAILABLE,
            backend_id=backend_id,
            backend_version=version,
        )

    def execute(
        self,
        target: ProviderTarget,
        *,
        health: ProviderHealthStatus,
        operation: Callable[[], Any],
        normalize: Callable[[Any, float], ProviderDetectionResult],
        validate_raw: Callable[[Any], list[str]] | None = None,
        operation_name: str = "detect",
    ) -> ProviderDetectionResult:
        """Run the full external provider lifecycle."""
        started = time.perf_counter()
        if health.state != ProviderHealthState.AVAILABLE:
            log_health_report([health])
            return self._failure(
                target,
                error=health.reason or f"{self.display_name} unavailable",
                health=health,
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )

        runner = ExternalProviderRunner(provider_id=self.provider_id, policy=self.policy)
        try:
            payload = runner.run(
                operation,
                target_url=target.url,
                operation_name=operation_name,
            )
            raw_warnings = validate_raw(payload) if validate_raw else []
            elapsed_ms = (time.perf_counter() - started) * 1000
            result = normalize(payload, elapsed_ms)
            validated = self.validator.validate_matches(result.matches, provider=self.provider_id)
            result = validated.apply_to_result(result)
            result.health = health
            result.backend_id = health.backend_id
            result.validation_warnings = [*raw_warnings, *validated.warnings]
            logger.info(
                "External provider completed",
                extra={
                    "provider_id": self.provider_id,
                    "target_url": target.url,
                    "match_count": len(result.matches),
                    "elapsed_ms": elapsed_ms,
                    "backend_id": health.backend_id,
                    "validation_warnings": len(result.validation_warnings),
                },
            )
            return result
        except Exception as exc:
            logger.warning(
                "External provider failed; continuing with remaining providers",
                extra={
                    "provider_id": self.provider_id,
                    "target_url": target.url,
                    "error": str(exc),
                    "backend_id": health.backend_id,
                },
            )
            failed_health = health.model_copy(
                update={"state": ProviderHealthState.FAILED, "reason": str(exc)},
            )
            return self._failure(
                target,
                error=str(exc),
                health=failed_health,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                backend_id=health.backend_id,
            )

    def _failure(
        self,
        target: ProviderTarget,
        *,
        error: str,
        health: ProviderHealthStatus,
        elapsed_ms: float,
        backend_id: str | None = None,
    ) -> ProviderDetectionResult:
        return ProviderDetectionResult(
            provider=self.provider_id,
            target_url=target.url,
            success=False,
            error=error,
            elapsed_ms=elapsed_ms,
            health=health,
            backend_id=backend_id,
        )
