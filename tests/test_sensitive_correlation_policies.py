"""Tests for Phase 5 Step 4 correlation, policies, and severity calibration."""

from __future__ import annotations

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.sensitive_intelligence.candidates import (
    CandidateCorrelator,
    CorrelationType,
    PositiveEvidence,
    SensitiveCandidateValidator,
    ValidationState,
    calibrate_candidate,
    resolve_detector_policy,
)
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine
from techspecter.sensitive_intelligence.models import SeverityLevel
from techspecter.sensitive_intelligence.sources import TextAssetSource

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsWPU"
)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
REAL_PASSWORD = "SuperSecret123!"
REAL_CLIENT_SECRET = "csec_9f8a7b6c5d4e3f2a1b0c9d8e"
REAL_CLIENT_ID = "client_prod_ab12cd34"


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


def _find(report, subtype: str):
    return next(item for item in report.findings if item.subtype == subtype)


def test_strong_username_password_correlation_confirms() -> None:
    """Strong username/password pairs produce correlated findings."""
    content = f'''
    const creds = {{
      username: "deploy_bot",
      password: "{REAL_PASSWORD}",
    }};
    '''
    report = _engine_report(content)
    assert "correlated-credentials" in _subtypes(report)
    assert "password-field" in _subtypes(report)
    correlated = _find(report, "correlated-credentials")
    assert correlated.severity == SeverityLevel.CRITICAL
    assert correlated.confidence >= 90
    assert correlated.evidence
    assert correlated.locations
    assert correlated.detector_name


def test_weak_username_password_correlation_does_not_escalate() -> None:
    """Weak pairs must not become Critical via correlation."""
    content = """
    const creds = {
      username: "test",
      password: "password",
    };
    """
    report = _engine_report(content)
    assert "correlated-credentials" not in _subtypes(report)
    assert "password-field" not in _subtypes(report)
    assert not any(item.severity == SeverityLevel.CRITICAL for item in report.findings)


def test_client_id_secret_correlation() -> None:
    """Client ID + strong client secret correlates; weak secret does not."""
    strong = _engine_report(
        f'''
        client_id: "{REAL_CLIENT_ID}",
        client_secret: "{REAL_CLIENT_SECRET}",
        ''',
    )
    assert "correlated-client-credentials" in _subtypes(strong)
    assert "client-secret-field" in _subtypes(strong)

    weak = _engine_report(
        """
        client_id: "example",
        client_secret: "CHANGE_ME",
        """,
    )
    assert "correlated-client-credentials" not in _subtypes(weak)
    assert "client-secret-field" not in _subtypes(weak)


def test_aws_credential_correlation() -> None:
    """AWS access + secret correlate when both are strong; examples do not escalate alone."""
    content = f'''
    aws_access_key_id = "{AWS_KEY}"
    aws_secret_access_key = "{AWS_SECRET}"
    '''
    report = _engine_report(content)
    assert "aws-access-key" in _subtypes(report)
    assert "aws-secret-key" in _subtypes(report)
    assert "correlated-aws-credentials" in _subtypes(report)
    correlated = _find(report, "correlated-aws-credentials")
    assert correlated.severity == SeverityLevel.CRITICAL


def test_token_authorization_correlation() -> None:
    """Matching JWT assignment + Bearer authorization correlate."""
    content = f'''
    const token = "{JWT_SAMPLE}";
    const headers = {{ Authorization: "Bearer {JWT_SAMPLE}" }};
    '''
    report = _engine_report(content)
    assert "jwt-token" in _subtypes(report)
    assert "bearer-token" in _subtypes(report) or "jwt-token" in _subtypes(report)
    assert "correlated-token-authorization" in _subtypes(report)


def test_database_credential_correlation() -> None:
    """DB host/user/strong password correlate; weak password does not escalate."""
    strong = _engine_report(
        f'''
        db_host: "db.internal",
        db_user: "app_user",
        db_password: "{REAL_PASSWORD}",
        ''',
    )
    assert "correlated-database-credentials" in _subtypes(strong)

    weak = _engine_report(
        """
        DB_HOST: "localhost",
        DB_PASSWORD: "password",
        """,
    )
    assert "correlated-database-credentials" not in _subtypes(weak)
    assert not any(
        item.subtype == "password-field" and item.severity == SeverityLevel.CRITICAL
        for item in weak.findings
    )

    uri = _engine_report('DATABASE_URL: "postgres://user:Str0ngP@ss!@db.internal:5432/app"')
    assert "postgresql-uri" in _subtypes(uri) or "correlated-database-credentials" in _subtypes(uri)


def test_detector_policies_differ_by_family() -> None:
    """Generic password, JWT, and contact families resolve distinct policies."""
    validator = SensitiveCandidateValidator()
    source = TextAssetSource(url="https://example.com/a.js", filename="a.js", content="")

    from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
    from techspecter.sensitive_intelligence.models import FindingCategory, FindingType

    password = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.CREDENTIAL,
            subtype="password-field",
            matched_value="x",
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
    jwt = validator.validate_match(
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
        source=source,
    )
    email = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.EMAIL,
            subtype="email",
            matched_value="a@b.com",
            matched_pattern="email",
            confidence=80.0,
            severity=SeverityLevel.MEDIUM,
            evidence="a@b.com",
            raw_value="a@b.com",
        ),
        detector_id="email-detector",
        source=source,
    )
    assert resolve_detector_policy(password).policy_id == "generic-password"
    assert resolve_detector_policy(jwt).require_provider_format is True
    assert resolve_detector_policy(email).policy_id == "contact-only"
    assert email.validation_state == ValidationState.CANDIDATE_ONLY
    assert password.validation_state == ValidationState.CONFIRMED
    assert jwt.validation_state == ValidationState.CONFIRMED


def test_severity_calibration_no_critical_for_weak_pairs() -> None:
    """Calibration must not escalate weak correlated candidates to Critical."""
    report = _engine_report(
        """
        username: "example",
        password: "YOUR_PASSWORD",
        """,
    )
    assert not any(item.severity == SeverityLevel.CRITICAL for item in report.findings)


def test_correlation_deduplicates_pair_findings() -> None:
    """The same credential pair must not explode into multiple identical pair findings."""
    content = f'''
    username: "deploy_bot",
    password: "{REAL_PASSWORD}",
    '''
    report = _engine_report(content)
    pairs = [item for item in report.findings if item.subtype == "correlated-credentials"]
    assert len(pairs) == 1


def test_correlation_preserves_provenance_and_candidate_linkage() -> None:
    """Correlated findings retain source/evidence and member candidates gain correlation ids."""
    validator = SensitiveCandidateValidator()
    correlator = CandidateCorrelator()
    source = TextAssetSource(
        url="https://example.com/cfg.js",
        filename="cfg.js",
        content="",
        asset_id="asset-9",
    )
    from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
    from techspecter.sensitive_intelligence.models import FindingCategory, FindingType

    user = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.CREDENTIAL,
            subtype="username-field",
            matched_value="deploy_bot",
            matched_pattern="username",
            confidence=70.0,
            severity=SeverityLevel.MEDIUM,
            evidence='username: "deploy_bot"',
            line_number=2,
            category=FindingCategory.CREDENTIALS,
            rule_id="username-field",
            raw_value='username: "deploy_bot"',
        ),
        detector_id="credentials-rule-engine",
        source=source,
    )
    password = validator.validate_match(
        DetectorMatch(
            finding_type=FindingType.CREDENTIAL,
            subtype="password-field",
            matched_value="password-field [redacted]",
            matched_pattern="password",
            confidence=92.0,
            severity=SeverityLevel.CRITICAL,
            evidence=f'password: "{REAL_PASSWORD}"',
            line_number=3,
            category=FindingCategory.CREDENTIALS,
            rule_id="password-field",
            raw_value=f'password: "{REAL_PASSWORD}"',
        ),
        detector_id="credentials-rule-engine",
        source=source,
    )
    correlations = correlator.correlate([user, password])
    assert correlations
    assert correlations[0].correlation_type == CorrelationType.USERNAME_PASSWORD_PAIR
    assert correlations[0].validation_state == ValidationState.CONFIRMED
    assert set(correlations[0].candidate_ids) == {user.candidate_id, password.candidate_id}
    emitted = correlator.apply_correlations([user, password], correlations)
    assert emitted
    assert PositiveEvidence.CORRELATION in password.positive_evidence
    assert correlations[0].correlation_id in password.correlation_ids
    calibrated = calibrate_candidate(password, correlations=correlations)
    assert calibrated.confidence >= password.original_confidence
    assert calibrated.severity == SeverityLevel.CRITICAL
