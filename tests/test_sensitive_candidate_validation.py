"""Tests for Phase 5 sensitive candidate validation spine."""

from __future__ import annotations

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.sensitive_intelligence.candidates import (
    SensitiveCandidateValidator,
    ValidationState,
)
from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel
from techspecter.sensitive_intelligence.rules.engine import RuleEngine
from techspecter.sensitive_intelligence.rules.models import RuleCategory
from techspecter.sensitive_intelligence.sources import TextAssetSource
from techspecter.sensitive_intelligence.tracker import FindingTracker

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsWPU"
)
PEM_SAMPLE = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/0Q==\n"
    "-----END RSA PRIVATE KEY-----"
)
GITHUB_TOKEN = "ghp_" + ("a" * 36)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
REAL_PASSWORD = "SuperSecret123!"
REAL_API_KEY = "live_sk_9f8a7b6c5d4e3f2a1b0c"


def _source(content: str = "") -> TextAssetSource:
    return TextAssetSource(
        url="https://example.com/app.js",
        filename="app.js",
        content=content,
        asset_id="asset-1",
        relative_path="static/app.js",
    )


def _engine_report(content: str):
    return SensitiveIntelligenceEngine().build(
        DiscoveryResult(
            target=Target(url="https://example.com/", original_url="https://example.com"),
            downloads=[
                DownloadResult(
                    url="https://example.com/app.js",
                    filename="app.js",
                    download_success=True,
                    content=content,
                ),
            ],
        ),
    )


def _subtypes(report) -> set[str]:
    return {item.subtype for item in report.findings}


def test_placeholder_passwords_are_not_confirmed() -> None:
    """Weak and placeholder password assignments must not become findings."""
    samples = [
        'password: ""',
        'password: "password"',
        'password: "123456"',
        'password: "example"',
        'password: "YOUR_PASSWORD"',
        'password: "YOUR_PASSWORD_HERE"',
        'password: "form.password.value"',
        "const token = token;",
        '<input type="password" name="password" />',
        'const msg = "INVALID_PASSWORD";',
    ]
    for content in samples:
        report = _engine_report(content)
        assert "password-field" not in _subtypes(report), content
        assert "correlated-credentials" not in _subtypes(report), content


def test_realistic_password_and_api_key_are_confirmed() -> None:
    """Realistic static credentials remain confirmable."""
    content = f"""
    const cfg = {{
      password: "{REAL_PASSWORD}",
      api_key: "{REAL_API_KEY}",
    }};
    """
    report = _engine_report(content)
    subtypes = _subtypes(report)
    assert "password-field" in subtypes
    assert "generic-api-key" in subtypes


def test_structured_secrets_are_preserved() -> None:
    """JWT/PEM/AWS/GitHub and bearer tokens remain confirmed."""
    content = f"""
    const secrets = {{
      jwt: "{JWT_SAMPLE}",
      aws: "{AWS_KEY}",
      github: "{GITHUB_TOKEN}",
      auth: "Bearer {JWT_SAMPLE}",
      pem: `{PEM_SAMPLE}`,
      db: "postgres://user:Str0ngP@ss!@db.internal:5432/app",
      host: "10.0.0.12",
    }};
    """
    report = _engine_report(content)
    subtypes = _subtypes(report)
    assert "jwt-token" in subtypes
    assert "aws-access-key" in subtypes
    assert "github-token" in subtypes
    assert "bearer-token" in subtypes or "jwt-token" in subtypes
    assert "private-key" in subtypes or "ssh-private-key" in subtypes
    assert "postgresql-uri" in subtypes
    assert "internal-ip" in subtypes


def test_weak_correlation_is_not_critical_finding() -> None:
    """Nearby weak username/password pairs must not confirm as CRITICAL."""
    content = """
    const creds = {
      username: "test",
      password: "password",
    };
    """
    report = _engine_report(content)
    assert "correlated-credentials" not in _subtypes(report)
    assert "password-field" not in _subtypes(report)


def test_strong_correlation_remains_confirmable() -> None:
    """Strong nearby username/password pairs remain detectable."""
    content = f"""
    const creds = {{
      username: "deploy_bot",
      password: "{REAL_PASSWORD}",
    }};
    """
    report = _engine_report(content)
    assert "correlated-credentials" in _subtypes(report)
    assert "password-field" in _subtypes(report)
    correlated = next(item for item in report.findings if item.subtype == "correlated-credentials")
    assert correlated.severity == SeverityLevel.CRITICAL


def test_confirmed_finding_preserves_provenance() -> None:
    """Confirmed findings keep source, asset, location, evidence, and rule metadata."""
    content = f'password: "{REAL_PASSWORD}";'
    report = _engine_report(content)
    finding = next(item for item in report.findings if item.subtype == "password-field")
    assert finding.detector_name
    assert finding.rule_id == "password-field"
    assert finding.evidence
    assert finding.matched_value
    assert finding.locations
    assert finding.locations[0].source_url.endswith("app.js")
    assert finding.locations[0].line_number is not None
    assert finding.source_files


def test_tracker_deduplicates_confirmed_candidates() -> None:
    """FindingTracker continues to merge duplicate confirmed candidates."""
    validator = SensitiveCandidateValidator()
    tracker = FindingTracker()
    engine = RuleEngine()
    content = f'password: "{REAL_PASSWORD}";'
    matches = engine.scan_category(content, RuleCategory.CREDENTIALS)
    password_matches = [item for item in matches if item.subtype == "password-field"]
    assert password_matches
    match = password_matches[0]
    for filename in ("a.js", "b.js"):
        candidate = validator.validate_match(
            match,
            detector_id="credentials-rule-engine",
            source=TextAssetSource(
                url=f"https://example.com/{filename}",
                filename=filename,
                content=content,
            ),
        )
        assert candidate.validation_state == ValidationState.CONFIRMED
        tracker.add_confirmed_candidate(candidate)
    findings = tracker.all()
    assert len(findings) == 1
    assert findings[0].occurrence_count == 2
    assert len(findings[0].source_files) == 2


def test_contact_matches_are_candidate_only() -> None:
    """Contact regex matches are not auto-confirmed as security findings."""
    report = _engine_report("Contact support@example.com for help.")
    assert not any(item.finding_type == FindingType.EMAIL for item in report.findings)


def test_validator_rejects_runtime_and_documentation_examples() -> None:
    """Direct validator coverage for runtime references and docs placeholders."""
    validator = SensitiveCandidateValidator()
    source = _source()
    match = DetectorMatch(
        finding_type=FindingType.CREDENTIAL,
        subtype="password-field",
        matched_value="password-field [redacted]",
        matched_pattern="password",
        confidence=92.0,
        severity=SeverityLevel.CRITICAL,
        evidence="password: form.password.value",
        rule_id="password-field",
        rule_name="Hardcoded Password",
        raw_value="password: form.password.value",
    )
    candidate = validator.validate_match(match, detector_id="credentials-rule-engine", source=source)
    assert candidate.validation_state == ValidationState.REJECTED

    docs = DetectorMatch(
        finding_type=FindingType.CREDENTIAL,
        subtype="password-field",
        matched_value="password-field [redacted]",
        matched_pattern="password",
        confidence=92.0,
        severity=SeverityLevel.CRITICAL,
        evidence='// example: password: "YOUR_PASSWORD_HERE"',
        rule_id="password-field",
        rule_name="Hardcoded Password",
        raw_value='password: "YOUR_PASSWORD_HERE"',
    )
    docs_candidate = validator.validate_match(
        docs,
        detector_id="credentials-rule-engine",
        source=source,
    )
    assert docs_candidate.validation_state == ValidationState.REJECTED
