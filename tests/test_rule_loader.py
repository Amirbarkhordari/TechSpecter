"""Tests for rule loading and validation."""

from __future__ import annotations

import pytest

from techspecter.exceptions import RuleValidationError
from techspecter.rules.loader import RuleLoader
from techspecter.rules.validator import RuleValidator
from tests.rules_fixtures import sample_string_rule, write_rules_file


def test_rule_loader_discovers_yaml_rules(tmp_path) -> None:
    """Verify rule loader discovers YAML rule files."""
    write_rules_file(tmp_path / "rules.yaml")
    rules = RuleLoader(rule_directories=[tmp_path], use_cache=False).load_all()
    assert len(rules) == 2
    assert {rule.id for rule in rules} == {"file-string-rule", "file-regex-rule"}


def test_rule_loader_uses_cache(tmp_path) -> None:
    """Verify loaded rules are cached when enabled."""
    write_rules_file(tmp_path / "rules.yaml")
    loader = RuleLoader(rule_directories=[tmp_path], use_cache=True)
    first = loader.load_all()
    second = loader.load_all()
    assert first == second


def test_rule_validator_detects_duplicate_ids() -> None:
    """Verify duplicate rule IDs fail validation."""
    rules = [
        sample_string_rule(id="dup"),
        sample_string_rule(id="dup", name="Duplicate"),
    ]
    report = RuleValidator().validate(rules)
    assert not report.is_valid
    assert any("Duplicate" in error for error in report.errors)


def test_rule_validator_detects_malformed_regex() -> None:
    """Verify malformed regex patterns fail validation."""
    from techspecter.rules.models import RuleType

    rules = [
        sample_string_rule(
            id="bad-regex",
            type=RuleType.REGEX,
            pattern="(?P<unclosed",
        ),
    ]
    with pytest.raises(RuleValidationError):
        RuleValidator().validate_or_raise(rules)


def test_builtin_example_rules_validate() -> None:
    """Verify bundled example rules pass validation."""
    rules = RuleLoader(use_cache=False).load_all()
    report = RuleValidator().validate(rules)
    assert report.is_valid
