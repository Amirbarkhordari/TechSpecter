"""Release engineering, packaging, and documentation validation tests."""

from __future__ import annotations

import importlib.metadata
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from techspecter import __version__, version_display
from techspecter.cli import app

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def test_version_is_semver_rc() -> None:
    """Verify centralized version matches release candidate format."""
    assert __version__ == "1.0.0rc1"
    assert version_display() == "1.0.0-rc1"


def test_package_metadata_version_matches() -> None:
    """Verify installed package metadata exposes the same version."""
    dist = importlib.metadata.metadata("techspecter")
    assert dist["Name"] == "techspecter"
    assert dist["Version"] == __version__


def test_console_script_entry_point_exists() -> None:
    """Verify the techspecter console script entry point is registered."""
    entry_points = importlib.metadata.entry_points(group="console_scripts")
    scripts = {entry.name: entry.value for entry in entry_points}
    assert scripts.get("techspecter") == "techspecter.cli:main"


def test_doctor_command_runs() -> None:
    """Verify doctor diagnostics command executes successfully."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "TechSpecter Doctor" in result.stdout
    assert version_display() in result.stdout


def test_doctor_json_output() -> None:
    """Verify doctor JSON diagnostics are valid."""
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["version"] == __version__
    assert payload["status"] == "ok"


def test_cli_version_display() -> None:
    """Verify CLI version output uses display formatting."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"TechSpecter {version_display()}" in result.stdout


@pytest.mark.parametrize(
    "relative_path",
    [
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "SUPPORT.md",
        "ROADMAP.md",
        "docs/QUICKSTART.md",
        "docs/INSTALLATION.md",
        "docs/CONFIGURATION.md",
        "docs/ARCHITECTURE.md",
        "docs/DEVELOPER.md",
        "docs/PLUGIN_SDK.md",
        "docs/MIGRATION.md",
        "docs/RELEASE_NOTES.md",
        "docs/SBOM.md",
        "examples/README.md",
        "examples/config/techspecter.yaml",
        "examples/reports/sample-analysis-report.json",
    ],
)
def test_documentation_files_exist(relative_path: str) -> None:
    """Verify required documentation and example files exist."""
    assert (ROOT / relative_path).is_file()


def test_example_configuration_is_valid_yaml() -> None:
    """Verify sample configuration parses as YAML."""
    config_path = ROOT / "examples/config/techspecter.yaml"
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert "performance" in payload


def test_sample_report_is_valid_json() -> None:
    """Verify sample report JSON is well-formed."""
    report_path = ROOT / "examples/reports/sample-analysis-report.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["tool_name"] == "TechSpecter"


@pytest.mark.parametrize(
    "workflow",
    ["ci.yml", "codeql.yml", "dependency-review.yml", "sbom.yml"],
)
def test_github_workflows_exist(workflow: str) -> None:
    """Verify GitHub Actions workflow files exist."""
    path = ROOT / ".github/workflows" / workflow
    assert path.is_file()
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert parsed["name"]
    assert "jobs" in parsed


def test_dependabot_configuration_exists() -> None:
    """Verify Dependabot configuration is present."""
    path = ROOT / ".github/dependabot.yml"
    assert path.is_file()


def test_package_builds_successfully() -> None:
    """Verify wheel and sdist build without errors."""
    result = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", "dist/test-build"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    dist_dir = ROOT / "dist/test-build"
    assert any(dist_dir.glob("*.whl"))
    assert any(dist_dir.glob("*.tar.gz"))
