"""Shared rule test fixtures."""

from __future__ import annotations

from pathlib import Path

from techspecter.rules.models import Rule, RuleCategory, RuleType
from techspecter.analysis.models.finding import Severity


def sample_string_rule(**overrides: object) -> Rule:
    """Build a sample string rule."""
    data = {
        "id": "test-string-rule",
        "name": "Test String Rule",
        "description": "Detects a test marker.",
        "category": RuleCategory.INFORMATION_DISCLOSURE,
        "severity": Severity.INFO,
        "confidence": 55.0,
        "enabled": True,
        "type": RuleType.STRING,
        "pattern": "TEST-MARKER",
        "target": "content",
    }
    data.update(overrides)
    return Rule(**data)  # type: ignore[arg-type]


def write_rules_file(path: Path) -> None:
    """Write a sample rules YAML file."""
    path.write_text(
        """
rules:
  - id: file-string-rule
    name: File String Rule
    description: Detects marker in file content.
    category: Information Disclosure
    severity: INFO
    confidence: 60
    enabled: true
    type: string
    pattern: FILE-MARKER
    target: content
  - id: file-regex-rule
    name: File Regex Rule
    description: Detects version-like values.
    category: Metadata
    severity: LOW
    confidence: 70
    enabled: true
    type: regex
    pattern: "version\\\\s*=\\\\s*[0-9]+"
    target: content
""".strip()
        + "\n",
        encoding="utf-8",
    )
