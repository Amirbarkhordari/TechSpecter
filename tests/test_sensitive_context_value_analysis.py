"""Tests for Phase 5 Step 3 context / value / negative-evidence hardening."""

from __future__ import annotations

import pytest

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.sensitive_intelligence.candidates import (
    ContextKind,
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidateValidator,
    ValidationState,
    ValueStrength,
    is_placeholder_value,
    normalize_placeholder_token,
)
from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine
from techspecter.sensitive_intelligence.models import FindingCategory, FindingType, SeverityLevel
from techspecter.sensitive_intelligence.sources import TextAssetSource

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
REAL_CLIENT_SECRET = "csec_9f8a7b6c5d4e3f2a1b0c9d8e"


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


def _password_candidate(raw: str, *, evidence: str | None = None) -> ValidationState:
    validator = SensitiveCandidateValidator()
    match = DetectorMatch(
        finding_type=FindingType.CREDENTIAL,
        subtype="password-field",
        matched_value="password-field [redacted]",
        matched_pattern="password",
        confidence=92.0,
        severity=SeverityLevel.CRITICAL,
        evidence=evidence or raw,
        category=FindingCategory.CREDENTIALS,
        rule_id="password-field",
        rule_name="Hardcoded Password",
        raw_value=raw,
    )
    return validator.validate_match(
        match,
        detector_id="credentials-rule-engine",
        source=_source(evidence or raw),
    ).validation_state


@pytest.mark.parametrize(
    "raw",
    [
        "YOUR_API_KEY",
        "your-api-key",
        "your api key",
        "YOUR_PASSWORD",
        "YOUR_PASSWORD_HERE",
        "CHANGE_ME",
        "CHANGE_ME_NOW",
        "REPLACE_ME",
        "<your-password>",
        "<api-key>",
        "example",
        "sample",
        "dummy",
        "password123",
    ],
)
def test_placeholder_normalization_and_detection(raw: str) -> None:
    """Placeholder variants normalize to the same semantic class."""
    assert is_placeholder_value(raw)
    assert normalize_placeholder_token("YOUR_API_KEY") == normalize_placeholder_token("your api key")


@pytest.mark.parametrize(
    "content",
    [
        'password: ""',
        "password: null",
        "password: undefined",
        'password: "password"',
        'password: "password123"',
        'password: "123456"',
        'password: "example"',
        'password: "sample"',
        'password: "dummy"',
        'password: "YOUR_PASSWORD"',
        'password: "YOUR_PASSWORD_HERE"',
        'api_key: "YOUR_API_KEY"',
        'secret: "CHANGE_ME"',
        'secret: "<your-secret>"',
        'password: "form.password.value"',
        '<input type="password" name="password" />',
        '// example configuration\npassword: "YOUR_PASSWORD"',
        'fixture_password = "password"',
        'mock_token = "test"',
        'sample_api_key = "example"',
        'token: "${PASSWORD}"',
        'secret: "{{PASSWORD}}"',
    ],
)
def test_must_not_confirm_weak_or_placeholder_assignments(content: str) -> None:
    """Weak/placeholder/runtime/doc/fixture noise must not become findings."""
    report = _engine_report(content)
    assert "password-field" not in _subtypes(report), content
    assert "generic-api-key" not in _subtypes(report), content
    assert "correlated-credentials" not in _subtypes(report), content


@pytest.mark.parametrize(
    ("evidence", "raw_value"),
    [
        ("token = process.env.TOKEN", "process.env.TOKEN"),
        ("token = env.TOKEN", "env.TOKEN"),
        ("token = getToken()", "getToken()"),
        ("const token = token", "token"),
        ("password = form.password.value", "form.password.value"),
    ],
)
def test_runtime_and_self_reference_candidates_rejected(evidence: str, raw_value: str) -> None:
    """Runtime/self references are negative evidence and not confirmed."""
    validator = SensitiveCandidateValidator()
    match = DetectorMatch(
        finding_type=FindingType.SECRET,
        subtype="session-token",
        matched_value="session-token [redacted]",
        matched_pattern="token",
        confidence=85.0,
        severity=SeverityLevel.MEDIUM,
        evidence=evidence,
        category=FindingCategory.SECRETS,
        rule_id="session-token",
        rule_name="Session Token",
        raw_value=raw_value,
    )
    candidate = validator.validate_match(
        match,
        detector_id="secrets-rule-engine",
        source=_source(evidence),
    )
    assert candidate.validation_state == ValidationState.REJECTED
    assert {
        NegativeEvidence.RUNTIME_REFERENCE,
        NegativeEvidence.SELF_REFERENCE,
        NegativeEvidence.FORM_REFERENCE,
        NegativeEvidence.FORM_FIELD,
    } & set(candidate.negative_evidence)


def test_context_kinds_for_static_runtime_placeholder_and_form() -> None:
    """Context analyzer classifies static, runtime, placeholder, and form contexts."""
    validator = SensitiveCandidateValidator()
    source = _source()

    static = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.CREDENTIAL,
            subtype="password-field",
            matched_value="password-field [redacted]",
            matched_pattern="password",
            confidence=92.0,
            severity=SeverityLevel.CRITICAL,
            evidence=f'password: "{REAL_PASSWORD}"',
            category=FindingCategory.CREDENTIALS,
            rule_id="password-field",
            raw_value=f'password: "{REAL_PASSWORD}"',
        ),
        detector_id="credentials-rule-engine",
        source=source,
    )
    assert static.context_kind == ContextKind.STATIC_ASSIGNMENT
    assert PositiveEvidence.STATIC_ASSIGNMENT in static.positive_evidence
    assert static.validation_state == ValidationState.CONFIRMED
    assert static.value_strength == ValueStrength.REALISTIC

    runtime = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.SECRET,
            subtype="session-token",
            matched_value="session-token [redacted]",
            matched_pattern="token",
            confidence=85.0,
            severity=SeverityLevel.MEDIUM,
            evidence="token = process.env.TOKEN",
            category=FindingCategory.SECRETS,
            rule_id="session-token",
            raw_value="token = process.env.TOKEN",
        ),
        detector_id="secrets-rule-engine",
        source=source,
    )
    assert runtime.context_kind == ContextKind.RUNTIME_REFERENCE
    assert NegativeEvidence.RUNTIME_REFERENCE in runtime.negative_evidence
    assert runtime.validation_state == ValidationState.REJECTED

    placeholder = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.CREDENTIAL,
            subtype="password-field",
            matched_value="password-field [redacted]",
            matched_pattern="password",
            confidence=92.0,
            severity=SeverityLevel.CRITICAL,
            evidence='password: "YOUR_PASSWORD_HERE"',
            category=FindingCategory.CREDENTIALS,
            rule_id="password-field",
            raw_value='password: "YOUR_PASSWORD_HERE"',
        ),
        detector_id="credentials-rule-engine",
        source=source,
    )
    assert placeholder.context_kind == ContextKind.PLACEHOLDER_ASSIGNMENT
    assert NegativeEvidence.PLACEHOLDER_VALUE in placeholder.negative_evidence
    assert placeholder.validation_state == ValidationState.REJECTED

    form = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.CREDENTIAL,
            subtype="password-field",
            matched_value="password-field [redacted]",
            matched_pattern="password",
            confidence=92.0,
            severity=SeverityLevel.CRITICAL,
            evidence='<input type="password" name="password" value="">',
            category=FindingCategory.CREDENTIALS,
            rule_id="password-field",
            raw_value='type="password"',
        ),
        detector_id="credentials-rule-engine",
        source=source,
    )
    assert form.context_kind == ContextKind.FORM_FIELD
    assert form.validation_state == ValidationState.REJECTED


def test_must_preserve_realistic_and_structured_secrets() -> None:
    """Realistic static secrets and provider formats remain confirmable."""
    content = f"""
    const cfg = {{
      password: "{REAL_PASSWORD}",
      api_key: "{REAL_API_KEY}",
      client_secret: "{REAL_CLIENT_SECRET}",
      jwt: "{JWT_SAMPLE}",
      aws: "{AWS_KEY}",
      github: "{GITHUB_TOKEN}",
      auth: "Bearer {JWT_SAMPLE}",
      pem: `{PEM_SAMPLE}`,
      db: "postgres://user:Str0ngP@ss!@db.internal:5432/app",
      host: "10.0.0.12",
    }};
    // leaked: password: "{REAL_PASSWORD}"
    """
    report = _engine_report(content)
    subtypes = _subtypes(report)
    assert "password-field" in subtypes
    assert "generic-api-key" in subtypes
    assert "jwt-token" in subtypes
    assert "aws-access-key" in subtypes
    assert "github-token" in subtypes
    assert "private-key" in subtypes or "ssh-private-key" in subtypes
    assert "postgresql-uri" in subtypes
    assert "internal-ip" in subtypes


def test_documentation_placeholder_rejected_but_realistic_comment_leak_preserved() -> None:
    """Docs placeholders reject; realistic secrets inside comments remain findings."""
    docs = _engine_report('// Example configuration\npassword: "YOUR_PASSWORD"')
    assert "password-field" not in _subtypes(docs)

    leak = _engine_report(f'// temporary hack\npassword: "{REAL_PASSWORD}"')
    assert "password-field" in _subtypes(leak)


def test_candidate_preserves_semantic_fields_for_correlation() -> None:
    """Candidates expose credential name/category/value strength for future correlation."""
    validator = SensitiveCandidateValidator()
    candidate = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.CREDENTIAL,
            subtype="password-field",
            matched_value="password-field [redacted]",
            matched_pattern="password",
            confidence=92.0,
            severity=SeverityLevel.CRITICAL,
            evidence=f'password: "{REAL_PASSWORD}"',
            category=FindingCategory.CREDENTIALS,
            rule_id="password-field",
            raw_value=f'password: "{REAL_PASSWORD}"',
        ),
        detector_id="credentials-rule-engine",
        source=_source(),
    )
    assert candidate.credential_name == "password"
    assert candidate.credential_category == "credentials"
    assert candidate.value_strength == ValueStrength.REALISTIC
    assert candidate.source_url
    assert candidate.evidence
