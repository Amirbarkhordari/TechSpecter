"""Shared configuration test fixtures."""

from __future__ import annotations

from pathlib import Path


def write_yaml_config(path: Path) -> None:
    """Write a sample YAML configuration file."""
    path.write_text(
        """
logging:
  level: WARNING
  debug: false
downloader:
  request_timeout: 45
  max_retries: 5
analysis:
  min_confidence: 25
  disabled_analyzers:
    - legacy-analyzer
reporting:
  output_directory: ./reports
  theme: dark
""".strip()
        + "\n",
        encoding="utf-8",
    )


def write_json_config(path: Path) -> None:
    """Write a sample JSON configuration file."""
    path.write_text(
        """
{
  "logging": {"level": "ERROR"},
  "analysis": {"min_confidence": 10}
}
""".strip(),
        encoding="utf-8",
    )
