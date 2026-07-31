"""Tests for Phase 8 rule-based sensitive intelligence engine."""

from __future__ import annotations

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine
from techspecter.sensitive_intelligence.javascript_intel import extract_javascript_config_snippets
from techspecter.sensitive_intelligence.models import FindingCategory, SeverityLevel
from techspecter.sensitive_intelligence.rules.catalog import builtin_rules
from techspecter.sensitive_intelligence.rules.engine import RuleEngine
from techspecter.sensitive_intelligence.rules.models import RuleCategory
from techspecter.sensitive_intelligence.rules.validators import (
    validate_aws_access_key,
    validate_github_token,
    validate_jwt,
    validate_pem,
)

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsWPU"
)


def test_validators_reject_invalid_samples() -> None:
    """Verify validators reduce false positives."""
    import re

    assert validate_jwt("not-a-jwt", re.match(r".*", "not-a-jwt")) is False
    assert validate_aws_access_key("AKIAINVALID", re.match(r".*", "AKIAINVALID")) is False
    assert validate_github_token("ghp_short", re.match(r".*", "ghp_short")) is False
    assert validate_pem("-----BEGIN PUBLIC KEY-----", re.match(r".*", "x")) is False


def test_validators_accept_valid_samples() -> None:
    """Verify validators accept well-formed samples."""
    import re

    token = JWT_SAMPLE
    assert validate_jwt(token, re.match(r".*", token)) is True
    assert validate_aws_access_key("AKIAIOSFODNN7EXAMPLE", re.match(r".*", "x")) is True
    assert validate_pem("-----BEGIN RSA PRIVATE KEY-----", re.match(r".*", "x")) is True


def test_rule_engine_detects_aws_and_jwt() -> None:
    """Verify rule engine finds AWS keys and JWT tokens."""
    engine = RuleEngine()
    content = f'const cfg = {{ key: "AKIAIOSFODNN7EXAMPLE", token: "{JWT_SAMPLE}" }};'
    matches = engine.scan_category(content, RuleCategory.SECRETS)
    subtypes = {match.subtype for match in matches}
    assert "aws-access-key" in subtypes
    assert "jwt-token" in subtypes
    assert all(match.recommendation for match in matches)


def test_rule_engine_detects_sensitive_configuration() -> None:
    """Verify sensitive configuration rules match internal endpoints."""
    engine = RuleEngine()
    content = 'fetch("/api/internal/users"); const host = "10.0.0.12";'
    matches = engine.scan_category(content, RuleCategory.SENSITIVE_CONFIGURATION)
    subtypes = {match.subtype for match in matches}
    assert "internal-api-endpoint" in subtypes
    assert "internal-ip" in subtypes


def test_rule_engine_detects_developer_artifacts() -> None:
    """Verify developer artifact rules match TODO and debug markers."""
    engine = RuleEngine()
    content = "// TODO: remove debug endpoint\nconsole.debug('state', data);"
    matches = engine.scan_category(content, RuleCategory.DEVELOPER_ARTIFACTS)
    subtypes = {match.subtype for match in matches}
    assert "todo-comment" in subtypes
    assert "debug-marker" in subtypes or "console-debug" in subtypes


def test_javascript_intel_extracts_next_data() -> None:
    """Verify JavaScript config extraction inspects Next.js payloads."""
    api_key = "AIzaSyB12345678901234567890123456789012"
    content = f'window.__NEXT_DATA__ = {{"props":{{"pageProps":{{"apiKey":"{api_key}"}}}}}};'
    snippets = extract_javascript_config_snippets(content)
    assert snippets
    engine = RuleEngine()
    matches = engine.scan(" ".join(snippets))
    assert any(match.subtype == "google-api-key" for match in matches)


def test_credential_correlation_detects_username_password_pair() -> None:
    """Verify correlated username/password pairs are reported."""
    content = """
    const creds = {
      username: "admin",
      password: "SuperSecret123!",
    };
    """
    report = SensitiveIntelligenceEngine().build(
        DiscoveryResult(
            target=Target(url="https://example.com/", original_url="https://example.com"),
            downloads=[
                DownloadResult(
                    url="https://example.com/config.js",
                    filename="config.js",
                    download_success=True,
                    content=content,
                ),
            ],
        ),
    )
    assert any(item.subtype == "correlated-credentials" for item in report.findings)
    assert any(item.subtype == "password-field" for item in report.findings)


def test_engine_assigns_categories_and_evidence() -> None:
    """Verify engine findings include category metadata and evidence."""
    report = SensitiveIntelligenceEngine().build(
        DiscoveryResult(
            target=Target(url="https://example.com/", original_url="https://example.com"),
            downloads=[
                DownloadResult(
                    url="https://example.com/app.js",
                    filename="app.js",
                    download_success=True,
                    content=f'const token = "{JWT_SAMPLE}"; // FIXME: rotate',
                ),
            ],
        ),
    )
    assert report.findings
    secret = next(item for item in report.findings if item.category == FindingCategory.SECRETS)
    assert secret.evidence
    assert secret.recommendation
    assert secret.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}


def test_builtin_rules_cover_phase8_categories() -> None:
    """Verify built-in catalog includes all Phase 8 categories."""
    rules = builtin_rules()
    categories = {rule.category for rule in rules}
    assert RuleCategory.SECRETS in categories
    assert RuleCategory.CREDENTIALS in categories
    assert RuleCategory.SENSITIVE_CONFIGURATION in categories
    assert RuleCategory.DEVELOPER_ARTIFACTS in categories
    assert len(rules) >= 40


def test_negative_samples_do_not_match_secrets() -> None:
    """Verify benign content does not trigger secret rules."""
    engine = RuleEngine()
    content = "const message = 'hello world'; function add(a, b) { return a + b; }"
    matches = engine.scan_category(content, RuleCategory.SECRETS)
    assert matches == []
