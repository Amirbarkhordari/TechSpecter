"""Retire.js passive JavaScript library provider."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from techspecter.providers.backends.retirejs import CliRetireJsBackend, RetireJsBackend
from techspecter.providers.base import BaseDetectionProvider
from techspecter.providers.external import ExternalProviderPolicy
from techspecter.providers.lifecycle import ExternalProviderLifecycle
from techspecter.providers.models import (
    ProviderDetectionResult,
    ProviderHealthStatus,
    ProviderTarget,
)
from techspecter.providers.normalizer import ProviderNormalizer
from techspecter.providers.validation import ProviderOutputValidator

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RetireJsProvider(BaseDetectionProvider):
    """Run an optional Retire.js backend for passive JavaScript intelligence."""

    provider_id: str = field(default="retirejs", init=False)
    display_name: str = field(default="Retire.js", init=False)
    backend: RetireJsBackend = field(default_factory=CliRetireJsBackend)
    normalizer: ProviderNormalizer = field(default_factory=ProviderNormalizer)
    policy: ExternalProviderPolicy = field(default_factory=ExternalProviderPolicy)
    validator: ProviderOutputValidator = field(default_factory=ProviderOutputValidator)

    def __post_init__(self) -> None:
        self._lifecycle = ExternalProviderLifecycle(
            provider_id=self.provider_id,
            display_name=self.display_name,
            policy=self.policy,
            validator=self.validator,
        )

    def is_available(self) -> bool:
        """Return whether the configured Retire.js backend is available."""
        try:
            return self.backend.is_available()
        except Exception as exc:
            logger.warning(
                "Retire.js availability check failed",
                extra={"provider_id": self.provider_id, "error": str(exc)},
            )
            return False

    def check_health(self) -> ProviderHealthStatus:
        """Return Retire.js health with backend details."""
        return self._lifecycle.check_health(
            is_available=self.backend.is_available,
            backend_id=self.backend.backend_id(),
            backend_version=self.backend.backend_version,
            unavailable_reason=self.backend.unavailable_reason(),
        )

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Scan discovered JavaScript with the Retire.js backend."""
        health = self.check_health()
        urls, scripts = self._collect_scripts(target)

        def _scan() -> list[dict[str, Any]]:
            payload: list[dict[str, Any]] = []
            if urls:
                payload.extend(
                    self.backend.scan_urls(urls, timeout_seconds=self.policy.timeout_seconds),
                )
            if scripts:
                payload.extend(
                    self.backend.scan_scripts(
                        scripts,
                        timeout_seconds=self.policy.timeout_seconds,
                    ),
                )
            return payload

        def _normalize(payload: Any, elapsed_ms: float) -> ProviderDetectionResult:
            return self.normalizer.from_retirejs(
                payload,
                target_url=target.url,
                elapsed_ms=elapsed_ms,
            )

        return self._lifecycle.execute(
            target,
            health=health,
            operation=_scan,
            normalize=_normalize,
            validate_raw=self.validator.validate_retirejs_payload,
            operation_name="retirejs_scan",
        )

    def _collect_scripts(
        self,
        target: ProviderTarget,
    ) -> tuple[list[str], list[tuple[str, str]]]:
        """Collect script URLs and inline content from discovery."""
        urls: list[str] = []
        scripts: list[tuple[str, str]] = []
        if target.discovery is None:
            return urls, scripts

        from techspecter.models.discovery import DiscoveryResult

        if not isinstance(target.discovery, DiscoveryResult):
            return urls, scripts

        for download in target.discovery.downloads:
            if download.download_success and download.content:
                url = str(download.url)
                urls.append(url)
                scripts.append((download.filename or url, download.content))

        for inline in target.discovery.inline_scripts:
            scripts.append((f"inline-script-{inline.index}.js", inline.content))

        return urls, scripts
