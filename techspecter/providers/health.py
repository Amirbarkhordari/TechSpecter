"""Provider health checks and reporting."""

from __future__ import annotations

import logging

from techspecter.providers.models import ProviderHealthState, ProviderHealthStatus

logger = logging.getLogger(__name__)


def format_health_report(statuses: list[ProviderHealthStatus]) -> str:
    """Format provider health statuses for console output."""
    lines: list[str] = []
    for status in statuses:
        label = _state_label(status.state)
        line = f"{status.display_name:<22} {label}"
        if status.backend_id:
            line += f" ({status.backend_id})"
        lines.append(line)
        if status.reason and status.state != ProviderHealthState.AVAILABLE:
            lines.append(f"  Reason: {status.reason}")
    return "\n".join(lines)


def log_health_report(statuses: list[ProviderHealthStatus]) -> None:
    """Log structured provider health summary."""
    for status in statuses:
        logger.info(
            "Provider health check",
            extra={
                "provider_id": status.provider_id,
                "display_name": status.display_name,
                "state": status.state.value,
                "backend_id": status.backend_id,
                "backend_version": status.backend_version,
                "reason": status.reason,
            },
        )


def _state_label(state: ProviderHealthState) -> str:
    mapping = {
        ProviderHealthState.AVAILABLE: "Available",
        ProviderHealthState.SKIPPED: "Skipped",
        ProviderHealthState.UNAVAILABLE: "Unavailable",
        ProviderHealthState.FAILED: "Failed",
    }
    return mapping.get(state, state.value)
