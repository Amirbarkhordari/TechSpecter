"""Performance tests for the rule engine."""

from __future__ import annotations

import time

from techspecter.rules.cache import RegexCache
from techspecter.rules.context import RuleExecutionContext
from techspecter.rules.loader import RuleLoader
from techspecter.rules.runner import RuleRunner
from tests.rules_fixtures import sample_string_rule


def test_regex_cache_reuses_compiled_patterns() -> None:
    """Verify regex patterns are compiled once and reused."""
    cache = RegexCache()
    first = cache.compile(r"abc\d+")
    second = cache.compile(r"abc\d+")
    assert first is second


def test_rule_loader_cache_avoids_reload(tmp_path) -> None:
    """Verify cached rule loading returns the same collection."""
    from tests.rules_fixtures import write_rules_file

    write_rules_file(tmp_path / "rules.yaml")
    loader = RuleLoader(rule_directories=[tmp_path], use_cache=True)
    first = loader.load_all()
    second = loader.load_all()
    assert first == second


def test_rule_runner_executes_many_rules_quickly() -> None:
    """Verify rule execution remains fast for moderate rule sets."""
    rules = [
        sample_string_rule(
            id=f"rule-{index}",
            pattern=f"MARKER-{index}",
        )
        for index in range(100)
    ]
    content = " ".join(f"MARKER-{index}" for index in range(100))
    context = RuleExecutionContext(target_url="https://example.com", content=content)

    started = time.perf_counter()
    result = RuleRunner(min_confidence=0, loader=None).run(context, rules=rules)  # type: ignore[arg-type]
    elapsed_ms = (time.perf_counter() - started) * 1000

    assert result.rules_matched == 100
    assert elapsed_ms < 1000
