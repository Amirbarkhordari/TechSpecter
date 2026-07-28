"""Retire.js passive JavaScript library scanner."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

_RETIRE_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("retire",),
    ("npx", "-y", "retire"),
)


class RetireJsExecutor:
    """Execute Retire.js against discovered JavaScript resources."""

    def is_available(self) -> bool:
        """Return whether Retire.js CLI is available."""
        return self.find_executable() is not None

    def find_executable(self) -> tuple[str, ...] | None:
        """Find an available Retire.js command."""
        for command in _RETIRE_COMMANDS:
            if command[0] == "retire" and shutil.which("retire") is None:
                continue
            if command[0] == "npx" and shutil.which("npx") is None:
                continue
            return command
        return None

    def scan_urls(
        self,
        urls: list[str],
        *,
        timeout_seconds: int = 120,
    ) -> list[dict[str, Any]]:
        """Scan remote JavaScript URLs with Retire.js."""
        if not urls:
            return []
        command = self.find_executable()
        if command is None:
            msg = "Retire.js CLI is not available"
            raise RuntimeError(msg)

        results: list[dict[str, Any]] = []
        for url in urls[:50]:
            file_results = self._scan_single_url(
                command,
                url,
                timeout_seconds=timeout_seconds,
            )
            if file_results is not None:
                results.append(file_results)
        return results

    def scan_discovery_scripts(
        self,
        scripts: list[tuple[str, str]],
        *,
        timeout_seconds: int = 120,
    ) -> list[dict[str, Any]]:
        """Scan in-memory JavaScript content via temporary files."""
        if not scripts:
            return []
        command = self.find_executable()
        if command is None:
            msg = "Retire.js CLI is not available"
            raise RuntimeError(msg)

        results: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory(prefix="techspecter-retire-") as tmp_dir:
            tmp_path = Path(tmp_dir)
            for index, (filename, content) in enumerate(scripts[:50]):
                safe_name = filename.replace("/", "_").replace("\\", "_") or f"script-{index}.js"
                file_path = tmp_path / safe_name
                file_path.write_text(content, encoding="utf-8")
                file_results = self._scan_path(
                    command,
                    file_path,
                    logical_name=filename,
                    timeout_seconds=timeout_seconds,
                )
                if file_results is not None:
                    results.append(file_results)
        return results

    def _scan_single_url(
        self,
        command: tuple[str, ...],
        url: str,
        *,
        timeout_seconds: int,
    ) -> dict[str, Any] | None:
        """Scan one remote JavaScript URL."""
        full_command = [*command, "--js", url, "--outputformat", "json"]
        payload = self._run_command(full_command, timeout_seconds=timeout_seconds)
        if payload is None:
            return None
        if isinstance(payload, list) and payload:
            first = payload[0]
            if isinstance(first, dict):
                first.setdefault("file", url)
                return first
        return {"file": url, "results": payload if isinstance(payload, list) else []}

    def _scan_path(
        self,
        command: tuple[str, ...],
        path: Path,
        *,
        logical_name: str,
        timeout_seconds: int,
    ) -> dict[str, Any] | None:
        """Scan a local file path."""
        full_command = [*command, "--path", str(path), "--outputformat", "json"]
        payload = self._run_command(full_command, timeout_seconds=timeout_seconds)
        if payload is None:
            return None
        if isinstance(payload, list):
            for entry in payload:
                if isinstance(entry, dict):
                    entry.setdefault("file", logical_name)
                    return entry
        return {"file": logical_name, "results": []}

    def _run_command(
        self,
        command: list[str],
        *,
        timeout_seconds: int,
    ) -> list[Any] | dict[str, Any] | None:
        """Execute Retire.js and parse JSON output."""
        logger.info("Running Retire.js: %s", " ".join(command))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Retire.js execution failed: %s", exc)
            return None

        output = (completed.stdout or "").strip()
        if not output:
            return None
        try:
            return cast(list[Any] | dict[str, Any], json.loads(output))
        except json.JSONDecodeError:
            logger.warning("Retire.js returned invalid JSON")
            return None
