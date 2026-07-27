"""Tests for rule execution and finding generation."""

from __future__ import annotations

from techspecter.rules.context import RuleExecutionContext
from techspecter.rules.executors.header import HeaderRuleExecutor
from techspecter.rules.executors.regex import RegexRuleExecutor
from techspecter.rules.executors.string import StringRuleExecutor
from techspecter.rules.models import RuleType
from techspecter.rules.runner import RuleRunner
from tests.rules_fixtures import sample_string_rule


def test_string_executor_generates_match() -> None:
    """Verify string rules match literal content."""
    rule = sample_string_rule(pattern="SECRET-MARKER")
    context = RuleExecutionContext(
        target_url="https://example.com/app.js",
        content="contains SECRET-MARKER value",
        filename="app.js",
    )
    match = StringRuleExecutor().execute(rule, context)
    assert match is not None
    assert match.matched_value == "SECRET-MARKER"


def test_regex_executor_generates_match() -> None:
    """Verify regex rules match content patterns."""
    rule = sample_string_rule(
        id="regex-rule",
        type=RuleType.REGEX,
        pattern=r"version\s*=\s*[0-9]+",
    )
    context = RuleExecutionContext(
        target_url="https://example.com/app.js",
        content="var version = 123;",
    )
    match = RegexRuleExecutor().execute(rule, context)
    assert match is not None
    assert "version" in match.matched_value


def test_header_executor_generates_match() -> None:
    """Verify header rules match response headers."""
    rule = sample_string_rule(
        id="header-rule",
        type=RuleType.HEADER,
        pattern="x-frame-options",
        target="header_name",
    )
    context = RuleExecutionContext(
        target_url="https://example.com",
        headers={"X-Frame-Options": "DENY"},
    )
    match = HeaderRuleExecutor().execute(rule, context)
    assert match is not None


def test_rule_runner_returns_findings() -> None:
    """Verify the rule runner converts matches into findings."""
    rule = sample_string_rule(pattern="FIND-ME")
    context = RuleExecutionContext(
        target_url="https://example.com",
        content="prefix FIND-ME suffix",
    )
    result = RuleRunner(min_confidence=0, loader=None).run(context, rules=[rule])  # type: ignore[arg-type]
    assert len(result.findings) == 1
    assert result.findings[0].id == "rule:test-string-rule"
    assert result.findings[0].analyzer == "rule-engine"


def test_rule_runner_skips_disabled_rules() -> None:
    """Verify disabled rules are not executed."""
    rule = sample_string_rule(enabled=False, pattern="FIND-ME")
    context = RuleExecutionContext(target_url="https://example.com", content="FIND-ME")
    result = RuleRunner(loader=None).run(context, rules=[rule])  # type: ignore[arg-type]
    assert result.findings == []


def test_rule_runner_respects_min_confidence() -> None:
    """Verify minimum confidence threshold filters rules."""
    rule = sample_string_rule(confidence=10.0, pattern="FIND-ME")
    context = RuleExecutionContext(target_url="https://example.com", content="FIND-ME")
    result = RuleRunner(min_confidence=50, loader=None).run(context, rules=[rule])  # type: ignore[arg-type]
    assert result.findings == []
