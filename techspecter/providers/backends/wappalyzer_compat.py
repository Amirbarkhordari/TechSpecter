"""Wappalyzer compatibility layer with multiple execution strategies."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class WappalyzerAdapter(Protocol):
    """Single Wappalyzer execution strategy."""

    adapter_id: str
    display_name: str

    def is_available(self) -> bool:
        """Return whether this adapter can run."""

    def detect(self, target_url: str, *, timeout_seconds: int) -> dict[str, Any] | list[Any]:
        """Execute Wappalyzer and return parsed JSON."""

    def version(self) -> str | None:
        """Return adapter or CLI version when available."""


@dataclass(frozen=True, slots=True)
class SkippedAdapter:
    """Record of an adapter that was not selected."""

    adapter_id: str
    reason: str


class _SubprocessWappalyzerAdapter:
    """Base adapter that runs Wappalyzer via subprocess."""

    adapter_id: str
    display_name: str
    command_prefix: tuple[str, ...]

    def is_available(self) -> bool:
        executable = self.command_prefix[0]
        return shutil.which(executable) is not None

    def version(self) -> str | None:
        return None

    def detect(self, target_url: str, *, timeout_seconds: int) -> dict[str, Any] | list[Any]:
        full_command = [*self.command_prefix, target_url, "--json"]
        logger.info(
            "Running Wappalyzer adapter",
            extra={"adapter_id": self.adapter_id, "command": " ".join(full_command)},
        )
        try:
            completed = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            msg = f"Wappalyzer timed out after {timeout_seconds}s"
            raise RuntimeError(msg) from exc
        except OSError as exc:
            msg = f"Failed to execute Wappalyzer: {exc}"
            raise RuntimeError(msg) from exc

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            stdout = (completed.stdout or "").strip()
            detail = stderr or stdout or f"exit code {completed.returncode}"
            raise RuntimeError(f"Wappalyzer execution failed: {detail}")

        output = (completed.stdout or "").strip()
        if not output:
            raise RuntimeError("Wappalyzer returned empty output")

        try:
            parsed: dict[str, Any] | list[Any] = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ValueError("Wappalyzer output was not valid JSON") from exc
        return parsed


class NativeWappalyzerAdapter(_SubprocessWappalyzerAdapter):
    """Native `wappalyzer` CLI on PATH."""

    adapter_id = "wappalyzer-cli"
    display_name = "Wappalyzer CLI"
    command_prefix = ("wappalyzer",)


class NpxWappalyzerPackageAdapter(_SubprocessWappalyzerAdapter):
    """Wappalyzer via npx @wappalyzer/wappalyzer."""

    adapter_id = "npx-wappalyzer-package"
    display_name = "npx @wappalyzer/wappalyzer"
    command_prefix = ("npx", "-y", "@wappalyzer/wappalyzer")


class NpxWappalyzerLegacyAdapter(_SubprocessWappalyzerAdapter):
    """Wappalyzer via npx wappalyzer."""

    adapter_id = "npx-wappalyzer-legacy"
    display_name = "npx wappalyzer"
    command_prefix = ("npx", "-y", "wappalyzer")


@dataclass(slots=True)
class WappalyzerCompatibilityLayer:
    """Select the first usable Wappalyzer adapter."""

    adapters: list[WappalyzerAdapter] = field(default_factory=list)
    _selected: WappalyzerAdapter | None = field(default=None, init=False)
    _skipped: list[SkippedAdapter] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if not self.adapters:
            self.adapters = [
                NativeWappalyzerAdapter(),
                NpxWappalyzerPackageAdapter(),
                NpxWappalyzerLegacyAdapter(),
            ]

    @property
    def selected_adapter(self) -> WappalyzerAdapter | None:
        """Return the currently selected adapter."""
        return self._selected

    @property
    def skipped_adapters(self) -> list[SkippedAdapter]:
        """Return adapters that were skipped during selection."""
        return list(self._skipped)

    def select_adapter(self) -> WappalyzerAdapter | None:
        """Detect and select the first available adapter."""
        self._skipped.clear()
        for adapter in self.adapters:
            try:
                if adapter.is_available():
                    self._selected = adapter
                    logger.info(
                        "Selected Wappalyzer adapter",
                        extra={"adapter_id": adapter.adapter_id},
                    )
                    return adapter
                self._skipped.append(
                    SkippedAdapter(adapter_id=adapter.adapter_id, reason="CLI unavailable"),
                )
            except Exception as exc:
                self._skipped.append(
                    SkippedAdapter(adapter_id=adapter.adapter_id, reason=str(exc)),
                )
        self._selected = None
        for skipped in self._skipped:
            logger.info(
                "Skipped Wappalyzer adapter",
                extra={"adapter_id": skipped.adapter_id, "reason": skipped.reason},
            )
        return None

    def is_available(self) -> bool:
        """Return whether any adapter is available."""
        if self._selected is not None:
            return True
        return self.select_adapter() is not None

    def backend_id(self) -> str | None:
        """Return selected adapter identifier."""
        adapter = self._selected or self.select_adapter()
        return adapter.adapter_id if adapter else None

    def version(self) -> str | None:
        """Return selected adapter version."""
        adapter = self._selected or self.select_adapter()
        if adapter is None:
            return None
        try:
            return adapter.version()
        except Exception:
            return None

    def detect(self, target_url: str, *, timeout_seconds: int) -> dict[str, Any] | list[Any]:
        """Run detection using the selected adapter."""
        adapter = self._selected or self.select_adapter()
        if adapter is None:
            reasons = ", ".join(item.reason for item in self._skipped) or "CLI unavailable"
            raise RuntimeError(f"No Wappalyzer backend available: {reasons}")
        return adapter.detect(target_url, timeout_seconds=timeout_seconds)

    def unavailable_reason(self) -> str:
        """Build a human-readable reason when no adapter is available."""
        if not self._skipped:
            self.select_adapter()
        if not self._skipped:
            return "CLI unavailable"
        return "; ".join(f"{item.adapter_id}: {item.reason}" for item in self._skipped)
