"""Generic Sensitive Intelligence metadata vs extracted-value contract tests."""

from __future__ import annotations

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.sensitive_intelligence.candidates.builder import build_candidate
from techspecter.sensitive_intelligence.candidates.content_contract import (
    is_metadata_as_value,
    source_derived_secret_value,
)
from techspecter.sensitive_intelligence.candidates.models import ValidationState
from techspecter.sensitive_intelligence.candidates.validator import SensitiveCandidateValidator
from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine
from techspecter.sensitive_intelligence.models import FindingCategory, FindingType, SeverityLevel
from techspecter.sensitive_intelligence.sources import TextAssetSource
from techspecter.sensitive_intelligence.tracker import FindingTracker

REAL_PASSWORD = "S3cure!Passphrase#2024"
REAL_API_KEY = "live_sk_9f3a2c1b0e8d7c6b5a4938271605"
JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
PEM_SAMPLE = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGFwq8N3J0YV4bQ==\n"
    "-----END RSA PRIVATE KEY-----"
)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + ("a" * 36)
BEARER = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
DB_URI = "postgresql://app_user:S3cureDbPass!@db.internal:5432/prod"


def _source(content: str = "", name: str = "app.js") -> TextAssetSource:
    return TextAssetSource(
        url=f"https://example.com/{name}",
        filename=name,
        content=content,
        relative_path=f"/static/{name}",
        asset_id=f"asset-{name}",
    )


def _report(content: str):
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


def test_rule_metadata_without_source_value_not_confirmed() -> None:
    validator = SensitiveCandidateValidator()
    match = DetectorMatch(
        finding_type=FindingType.SECRET,
        subtype="brand-new-api-key-rule",
        matched_value="brand-new-api-key-rule [redacted]",
        matched_pattern="rule",
        confidence=99.0,
        severity=SeverityLevel.CRITICAL,
        evidence="no literal assignment present",
        category=FindingCategory.SECRETS,
        rule_id="brand-new-api-key-rule",
        rule_name="Brand New API Key Rule",
        raw_value=None,
    )
    candidate = validator.validate_match(
        match,
        detector_id="future-detector",
        source=_source(),
    )
    assert candidate.validation_state != ValidationState.CONFIRMED
    tracker = FindingTracker()
    assert tracker.add_confirmed_candidate(candidate) is None


def test_detector_metadata_without_source_value_not_confirmed() -> None:
    validator = SensitiveCandidateValidator()
    match = DetectorMatch(
        finding_type=FindingType.SECRET,
        subtype="some-new-api-key-rule",
        matched_value="some-new-api-key-rule [redacted]",
        matched_pattern="x",
        confidence=95.0,
        severity=SeverityLevel.HIGH,
        evidence="detector matched metadata only",
        category=FindingCategory.SECRETS,
        rule_id="some-new-api-key-rule",
        raw_value="some-new-api-key-rule",
    )
    candidate = build_candidate(match, detector_id="some-new-detector", source=_source())
    assert is_metadata_as_value(candidate, candidate.analysis_value or match.raw_value)
    validated = validator.validate(candidate)
    assert validated.validation_state != ValidationState.CONFIRMED


def test_finding_subtype_cannot_become_secret_value() -> None:
    validator = SensitiveCandidateValidator()
    match = DetectorMatch(
        finding_type=FindingType.SECRET,
        subtype="generic-api-key",
        matched_value="generic-api-key [redacted]",
        matched_pattern="api_key",
        confidence=88.0,
        severity=SeverityLevel.HIGH,
        evidence='const label = "generic-api-key";',
        category=FindingCategory.SECRETS,
        rule_id="generic-api-key",
        raw_value="generic-api-key",
    )
    candidate = validator.validate_match(match, detector_id="secrets-rule-engine", source=_source())
    assert candidate.validation_state != ValidationState.CONFIRMED


def test_credential_name_cannot_become_secret_value() -> None:
    validator = SensitiveCandidateValidator()
    match = DetectorMatch(
        finding_type=FindingType.CREDENTIAL,
        subtype="password-field",
        matched_value="password-field [redacted]",
        matched_pattern="password",
        confidence=92.0,
        severity=SeverityLevel.CRITICAL,
        evidence="password",
        category=FindingCategory.CREDENTIALS,
        rule_id="password-field",
        raw_value="password",
    )
    candidate = validator.validate_match(
        match,
        detector_id="credentials-rule-engine",
        source=_source(),
    )
    assert source_derived_secret_value(candidate) is None
    assert candidate.validation_state != ValidationState.CONFIRMED


def test_source_derived_api_key_remains_detectable() -> None:
    report = _report(f'api_key = "{REAL_API_KEY}"')
    assert "generic-api-key" in _subtypes(report)
    finding = next(item for item in report.findings if item.subtype == "generic-api-key")
    assert finding.matched_value != "generic-api-key"
    assert "generic-api-key" not in finding.matched_value.replace(" [redacted]", "")
    assert "[redacted]" in finding.matched_value or "…" in finding.matched_value


def test_source_derived_password_remains_detectable() -> None:
    report = _report(f'password = "{REAL_PASSWORD}"')
    assert "password-field" in _subtypes(report)
    finding = next(item for item in report.findings if item.subtype == "password-field")
    assert finding.matched_value != "password-field [redacted]"
    assert finding.matched_value != "password"


def test_jwt_remains_detectable() -> None:
    assert "jwt-token" in _subtypes(_report(JWT_SAMPLE))


def test_pem_remains_detectable() -> None:
    assert "private-key" in _subtypes(_report(PEM_SAMPLE)) or "ssh-private-key" in _subtypes(
        _report(PEM_SAMPLE),
    )


def test_aws_credentials_remain_detectable() -> None:
    assert "aws-access-key" in _subtypes(_report(AWS_KEY))


def test_github_tokens_remain_detectable() -> None:
    assert "github-token" in _subtypes(_report(GITHUB_TOKEN))


def test_bearer_tokens_remain_detectable() -> None:
    subtypes = _subtypes(_report(f'authorization = "{BEARER}"'))
    assert "bearer-token" in subtypes or "session-token" in subtypes or "jwt-token" in subtypes


def test_db_credentials_remain_detectable() -> None:
    subtypes = _subtypes(_report(f"const db = '{DB_URI}';"))
    assert "postgresql-uri" in subtypes or "connection-string" in subtypes


def test_internal_hostname_remains_detectable() -> None:
    assert "internal-hostname" in _subtypes(_report("host: api.corp.internal"))


def test_strong_correlated_credentials_remain_detectable() -> None:
    report = _report(f'username="deploy_bot"; password="{REAL_PASSWORD}"')
    subtypes = _subtypes(report)
    assert "password-field" in subtypes
    assert "correlated-credentials" in subtypes or "username-field" in subtypes


def test_placeholder_values_remain_rejected() -> None:
    report = _report('password = "YOUR_PASSWORD_HERE"')
    assert "password-field" not in _subtypes(report)


def test_runtime_references_remain_rejected() -> None:
    report = _report("password = process.env.PASSWORD")
    assert "password-field" not in _subtypes(report)


def test_form_references_remain_rejected() -> None:
    report = _report("password = form.password.value")
    assert "password-field" not in _subtypes(report)


def test_documentation_noise_remains_protected() -> None:
    report = _report('// example docs: password = "example"')
    assert "password-field" not in _subtypes(report)


def test_provenance_references_actual_source_content() -> None:
    content = f'api_key = "{REAL_API_KEY}"'
    report = _report(content)
    finding = next(item for item in report.findings if item.subtype == "generic-api-key")
    assert finding.evidence
    assert REAL_API_KEY in (finding.evidence or "")
    assert finding.locations
    assert finding.locations[0].source_url
    assert finding.rule_id == "generic-api-key"
    assert finding.matched_value != "generic-api-key [redacted]"
    assert finding.matched_value != finding.rule_id



def test_deduplication_remains_correct_for_distinct_secrets() -> None:
    tracker = FindingTracker()
    validator = SensitiveCandidateValidator()
    first = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.SECRET,
            subtype="generic-api-key",
            matched_value="generic-api-key [redacted]",
            matched_pattern="api",
            confidence=88.0,
            severity=SeverityLevel.HIGH,
            evidence=f'api_key = "{REAL_API_KEY}"',
            category=FindingCategory.SECRETS,
            rule_id="generic-api-key",
            raw_value=f'api_key = "{REAL_API_KEY}"',
        ),
        detector_id="secrets-rule-engine",
        source=_source(name="a.js"),
    )
    second_key = "live_sk_aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    second = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.SECRET,
            subtype="generic-api-key",
            matched_value="generic-api-key [redacted]",
            matched_pattern="api",
            confidence=88.0,
            severity=SeverityLevel.HIGH,
            evidence=f'api_key = "{second_key}"',
            category=FindingCategory.SECRETS,
            rule_id="generic-api-key",
            raw_value=f'api_key = "{second_key}"',
        ),
        detector_id="secrets-rule-engine",
        source=_source(name="b.js"),
    )
    assert first.validation_state == ValidationState.CONFIRMED
    assert second.validation_state == ValidationState.CONFIRMED
    tracker.add_confirmed_candidate(first)
    tracker.add_confirmed_candidate(second)
    assert len(tracker.all()) == 2
