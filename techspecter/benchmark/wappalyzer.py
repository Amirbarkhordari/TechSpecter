"""Wappalyzer execution helpers."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

_WAPPALYZER_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("wappalyzer",),
    ("npx", "-y", "@wappalyzer/wappalyzer"),
    ("npx", "-y", "wappalyzer"),
)


class WappalyzerExecutor:
    """Run Wappalyzer CLI or load an existing JSON report."""

    def load_json(self, path: Path | str) -> dict[str, Any] | list[Any]:
        """Load a Wappalyzer JSON report from disk."""
        file_path = Path(path)
        if not file_path.is_file():
            msg = f"Wappalyzer result file not found: {file_path}"
            raise FileNotFoundError(msg)
        try:
            return cast(
                dict[str, Any] | list[Any], json.loads(file_path.read_text(encoding="utf-8"))
            )
        except json.JSONDecodeError as exc:
            msg = f"Invalid JSON in Wappalyzer result file: {file_path}"
            raise ValueError(msg) from exc

    def is_available(self) -> bool:
        """Return whether a Wappalyzer CLI executable appears to be available."""
        return self.find_executable() is not None

    def find_executable(self) -> tuple[str, ...] | None:
        """Find an available Wappalyzer command tuple."""
        for command in _WAPPALYZER_COMMANDS:
            if command[0] == "wappalyzer" and shutil.which("wappalyzer") is None:
                continue
            if command[0] == "npx" and shutil.which("npx") is None:
                continue
            return command
        return None

    def run(self, target_url: str, *, timeout_seconds: int = 120) -> dict[str, Any] | list[Any]:
        """Execute Wappalyzer against a target URL and return parsed JSON."""
        command = self.find_executable()
        if command is None:
            msg = (
                "Wappalyzer CLI is not available. Install Wappalyzer or provide "
                "a JSON report with --wappalyzer-result."
            )
            raise RuntimeError(msg)

        full_command = [
            *command,
            target_url,
            "--json",
        ]
        logger.info("Running Wappalyzer: %s", " ".join(full_command))
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
            msg = f"Wappalyzer execution failed: {detail}"
            raise RuntimeError(msg)

        output = (completed.stdout or "").strip()
        if not output:
            msg = "Wappalyzer returned empty output"
            raise RuntimeError(msg)

        try:
            return cast(dict[str, Any] | list[Any], json.loads(output))
        except json.JSONDecodeError as exc:
            msg = "Wappalyzer output was not valid JSON"
            raise ValueError(msg) from exc
