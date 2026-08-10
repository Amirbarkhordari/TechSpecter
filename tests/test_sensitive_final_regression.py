"""Phase 5 Step 5 final Sensitive Intelligence regression corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.sensitive_intelligence.candidates import (
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidateValidator,
    ValidationState,
)
from techspecter.sensitive_intelligence.cli_display import filter_fingerprint_cli_findings
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel
from techspecter.sensitive_intelligence.report import build_report_sensitive_intelligence
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
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
REAL_PASSWORD = "SuperSecret123!"
REAL_API_KEY = "live_sk_9f8a7b6c5d4e3f2a1b0c"
REAL_CLIENT_ID = "client_prod_ab12cd34"
REAL_CLIENT_SECRET = "csec_9f8a7b6c5d4e3f2a1b0c9d8e"
REAL_DB_PASSWORD = "DbP@ssw0rd!2024x"

_SECRET_SUBTYPES = frozenset(
    {
        "password-field",
        "generic-api-key",
        "session-token",
        "client-secret-field",
        "correlated-credentials",
        "correlated-client-credentials",
        "correlated-aws-credentials",
        "correlated-token-authorization",
        "correlated-database-credentials",
        "high-entropy-secret",
        "bearer-token",
    },
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


def _assert_no_secret_findings(content: str) -> None:
    report = _report(content)
    leaked = _subtypes(report) & _SECRET_SUBTYPES
    assert not leaked, f"unexpected secret findings for {content!r}: {leaked}"
    assert not any(item.severity == SeverityLevel.CRITICAL for item in report.findings), content


@pytest.mark.parametrize(
    "content",
    [
        'password = ""',
        'token = ""',
        'api_key = ""',
        'secret = ""',
        "password = null",
        "password = undefined",
        "token = null",
        'password = "password"',
        'password = "password123"',
        'password = "123456"',
        'password = "admin"',
        'password = "qwerty"',
        'password = "YOUR_PASSWORD"',
        'password = "YOUR_PASSWORD_HERE"',
        'api_key = "YOUR_API_KEY"',
        'secret = "YOUR_SECRET"',
        'secret = "CHANGE_ME"',
        'secret = "REPLACE_ME"',
        'token = "<your-token>"',
        'client_secret = "example"',
        "token = process.env.TOKEN",
        "password = process.env.PASSWORD",
        "api_key = env.API_KEY",
        "secret = config.secret",
        "token = getToken()",
        "secret = loadSecret()",
        "token = token",
        "password = password",
        "secret = secret",
        "password = form.password.value",
        "token = input.value",
        '<input type="password">',
        '<input name="password">',
        '<input type="password" value="">',
        '// password = "YOUR_PASSWORD"',
        '// api_key = "example"',
        'mock_password = "password"',
        'fixture_token = "test"',
        'sample_secret = "example"',
        'secret = "${PASSWORD}"',
        'secret = "{{PASSWORD}}"',
        "secret = <%= PASSWORD %>",
        "Contact support@example.com",
        "Call +1-555-0100 today",
        "Visit https://example.com/docs",
        "Hosted at example.com",
        "id = 550e8400-e29b-41d4-a716-446655440000",
    ],
)
def test_final_false_positive_corpus_rejects_noise(content: str) -> None:
    """Final FP corpus: empty/placeholder/runtime/form/docs/contact noise."""
    _assert_no_secret_findings(content)


def test_final_true_positive_corpus_preserves_strong_secrets() -> None:
    """Final TP corpus: realistic static and provider-shaped secrets remain confirmed."""
    content = f"""
    password = "{REAL_PASSWORD}"
    api_key = "{REAL_API_KEY}"
    client_id = "{REAL_CLIENT_ID}"
    client_secret = "{REAL_CLIENT_SECRET}"
    jwt = "{JWT_SAMPLE}"
    aws_access_key_id = "{AWS_KEY}"
    aws_secret_access_key = "{AWS_SECRET}"
    auth = "Bearer {JWT_SAMPLE}"
    pem = `{PEM_SAMPLE}`
    github = "{GITHUB_TOKEN}"
    DB_HOST = "internal-db.example"
    DB_USER = "appuser"
    DB_PASSWORD = "{REAL_DB_PASSWORD}"
    DATABASE_URL = "postgres://appuser:{REAL_DB_PASSWORD}@internal-db.example/db"
    host = "10.0.0.12"
    """
    report = _report(content)
    subtypes = _subtypes(report)
    assert "password-field" in subtypes
    assert "generic-api-key" in subtypes
    assert "client-secret-field" in subtypes
    assert "jwt-token" in subtypes
    assert "aws-access-key" in subtypes
    assert "aws-secret-key" in subtypes
    assert "github-token" in subtypes
    assert "private-key" in subtypes or "ssh-private-key" in subtypes
    assert "bearer-token" in subtypes or "jwt-token" in subtypes
    assert "postgresql-uri" in subtypes or "correlated-database-credentials" in subtypes
    assert "internal-ip" in subtypes
    assert any(item.severity in {SeverityLevel.CRITICAL, SeverityLevel.HIGH} for item in report.findings)


@pytest.mark.parametrize(
    ("content", "must_have", "must_not_have"),
    [
        (
            f'username="deploy"; password="{REAL_PASSWORD}"',
            {"correlated-credentials"},
            set(),
        ),
        (
            'username="test"; password="password"',
            set(),
            {"correlated-credentials", "password-field"},
        ),
        (
            f'client_id="{REAL_CLIENT_ID}"; client_secret="{REAL_CLIENT_SECRET}"',
            {"correlated-client-credentials"},
            set(),
        ),
        (
            'client_id="example"; client_secret="CHANGE_ME"',
            set(),
            {"correlated-client-credentials", "client-secret-field"},
        ),
        (
            f'aws_access_key_id="{AWS_KEY}"; aws_secret_access_key="{AWS_SECRET}"',
            {"correlated-aws-credentials"},
            set(),
        ),
        (
            f'const token="{JWT_SAMPLE}"; Authorization: "Bearer {JWT_SAMPLE}"',
            {"correlated-token-authorization"},
            set(),
        ),
        (
            'token="test"; Authorization: "Bearer test"',
            set(),
            {"correlated-token-authorization"},
        ),
        (
            f'DB_HOST="internal-db.example"; DB_USER="appuser"; DB_PASSWORD="{REAL_DB_PASSWORD}"',
            {"correlated-database-credentials"},
            set(),
        ),
        (
            'DB_HOST="localhost"; DB_PASSWORD="password"',
            set(),
            {"correlated-database-credentials"},
        ),
    ],
)
def test_final_correlation_matrix(
    content: str,
    must_have: set[str],
    must_not_have: set[str],
) -> None:
    """Final correlation confirm/reject matrix."""
    subtypes = _subtypes(_report(content))
    assert must_have <= subtypes
    assert not (must_not_have & subtypes)


def test_negative_evidence_blocks_correlation_override() -> None:
    """Correlation must not promote placeholder pairs to Critical."""
    report = _report('username="test"; password="YOUR_PASSWORD"')
    assert "correlated-credentials" not in _subtypes(report)
    assert not any(item.severity == SeverityLevel.CRITICAL for item in report.findings)


def test_confirmed_finding_keeps_full_provenance_chain() -> None:
    """Provenance survives candidate → validation → correlation → tracker."""
    report = _report(f'username="deploy_bot"; password="{REAL_PASSWORD}"')
    finding = next(item for item in report.findings if item.subtype == "password-field")
    assert finding.source_files
    assert finding.locations
    assert finding.locations[0].source_url
    assert finding.locations[0].line_number is not None
    assert finding.detector_name
    assert finding.rule_id == "password-field"
    assert finding.evidence
    assert finding.matched_value
    assert finding.confidence > 0
    assert finding.severity in {SeverityLevel.CRITICAL, SeverityLevel.HIGH}


def test_deduplication_merges_generic_and_pair_paths() -> None:
    """Duplicate pair detections collapse to one logical pair finding."""
    report = _report(f'username="deploy_bot"; password="{REAL_PASSWORD}"')
    pairs = [item for item in report.findings if item.subtype == "correlated-credentials"]
    assert len(pairs) == 1
    assert pairs[0].occurrence_count >= 1


def test_reporting_excludes_candidate_only_contacts() -> None:
    """Rejected/candidate-only contacts never become confirmed report findings."""
    report = _report("hello@example.com and https://example.com/page")
    export_model = build_report_sensitive_intelligence(report)
    assert not any(item.finding_type == FindingType.EMAIL.value for item in export_model.findings)
    filtered = filter_fingerprint_cli_findings(report.findings)
    assert not any(item.finding_type == FindingType.EMAIL for item in filtered)
    payload = json.loads(report.model_dump_json())
    assert payload["summary"]["emails"] == 0


def test_json_report_roundtrip_preserves_counts(tmp_path: Path) -> None:
    """JSON serialization preserves severity/category counters for confirmed findings."""
    report = _report(f'password="{REAL_PASSWORD}"; const token="{JWT_SAMPLE}";')
    path = tmp_path / "si.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["summary"]["total_findings"] == report.summary.total_findings
    assert loaded["summary"]["critical_severity"] == report.summary.critical_severity
    assert loaded["findings"]
    assert all("severity" in item and "confidence" in item for item in loaded["findings"])


def test_provider_positive_evidence_survives_validation() -> None:
    """Provider validators remain authoritative positive evidence."""
    validator = SensitiveCandidateValidator()
    from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
    from techspecter.sensitive_intelligence.models import FindingCategory

    candidate = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.SECRET,
            subtype="jwt-token",
            matched_value="jwt [redacted]",
            matched_pattern="jwt",
            confidence=94.0,
            severity=SeverityLevel.HIGH,
            evidence=JWT_SAMPLE,
            category=FindingCategory.SECRETS,
            rule_id="jwt-token",
            raw_value=JWT_SAMPLE,
        ),
        detector_id="secrets-rule-engine",
        source=TextAssetSource(url="https://example.com/a.js", filename="a.js", content=""),
    )
    assert candidate.validation_state == ValidationState.CONFIRMED
    assert PositiveEvidence.PROVIDER_SPECIFIC_FORMAT in candidate.positive_evidence
    assert NegativeEvidence.PLACEHOLDER_VALUE not in candidate.negative_evidence


@pytest.mark.parametrize(
    "content",
    [
        'NON_STANDARD_NODE_ENV:function(){return el},PAGES_DIR_ALIAS:function(){return x}',
        "el='You are using a non-standard \"NODE_ENV\" value in your environment. This creates'",
        'const msg = "NODE_ENV must be production or development";',
    ],
)
def test_framework_node_env_noise_is_not_environment_config(content: str) -> None:
    """Bare NODE_ENV identifiers in framework strings must not become findings."""
    report = _report(content)
    assert "environment-config" not in _subtypes(report)


def test_real_environment_config_assignments_remain_detectable() -> None:
    """Structured env access and NODE_ENV assignments remain detectable."""
    report = _report(
        'const mode = process.env.NODE_ENV; '
        'const url = import.meta.env.VITE_API_URL; '
        'REACT_APP_API_URL="https://api.internal.example"; '
        'NODE_ENV="production";'
    )
    assert "environment-config" in _subtypes(report)


def test_internal_hostname_development_domain_remains_detectable() -> None:
    """Internal .local hostnames in public bundles remain findings."""
    report = _report('get DOMAIN_DEVELOPMENT(){return"https://next.time.local:8001"}')
    assert "internal-hostname" in _subtypes(report)
