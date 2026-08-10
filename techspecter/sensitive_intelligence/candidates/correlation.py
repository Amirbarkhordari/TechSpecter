"""Candidate-based sensitive evidence correlation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from uuid import uuid4

from techspecter.sensitive_intelligence.candidates.models import (
    CorrelationType,
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
    SensitiveCorrelation,
    ValidationState,
    ValueStrength,
)
from techspecter.sensitive_intelligence.candidates.value import is_strong_secret_value
from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.models import FindingCategory, FindingType, SeverityLevel

_MAX_LINE_DISTANCE = 8

_BLOCKING_NEGATIVES = frozenset(
    {
        NegativeEvidence.EMPTY_VALUE,
        NegativeEvidence.PLACEHOLDER_VALUE,
        NegativeEvidence.RUNTIME_REFERENCE,
        NegativeEvidence.SELF_REFERENCE,
        NegativeEvidence.FORM_FIELD,
        NegativeEvidence.FORM_REFERENCE,
        NegativeEvidence.WEAK_GENERIC_VALUE,
        NegativeEvidence.GENERATED_TEMPLATE,
        NegativeEvidence.HTML_ATTRIBUTE,
        NegativeEvidence.EXAMPLE_VALUE,
    },
)

_STRONG_STRENGTHS = frozenset({ValueStrength.REALISTIC, ValueStrength.STRUCTURED})

_USERNAME_RULES = frozenset({"username-field", "db-user-field"})
_PASSWORD_RULES = frozenset({"password-field"})
_CLIENT_ID_RULES = frozenset({"client-id-field"})
_CLIENT_SECRET_RULES = frozenset({"client-secret-field"})
_AWS_ACCESS_RULES = frozenset({"aws-access-key"})
_AWS_SECRET_RULES = frozenset({"aws-secret-key"})
_TOKEN_RULES = frozenset(
    {"session-token", "jwt-token", "bearer-token", "high-entropy-secret", "generic-api-key"},
)
_AUTH_RULES = frozenset({"bearer-token", "jwt-token", "basic-auth-token"})
_DB_HOST_RULES = frozenset({"db-host-field", "internal-hostname", "internal-ip"})
_DB_USER_RULES = frozenset({"db-user-field", "username-field"})
_DB_PASSWORD_RULES = frozenset({"password-field"})
_DB_URI_RULES = frozenset(
    {"mongodb-uri", "postgresql-uri", "mysql-uri", "redis-uri", "connection-string"},
)


@dataclass(slots=True)
class CandidateCorrelator:
    """Correlate validated SensitiveCandidates within a bounded local scope."""

    max_line_distance: int = _MAX_LINE_DISTANCE

    def correlate(self, candidates: list[SensitiveCandidate]) -> list[SensitiveCorrelation]:
        """Build correlations for candidates that share asset/source scope."""
        by_scope: dict[tuple[str | None, str | None], list[SensitiveCandidate]] = defaultdict(list)
        for candidate in candidates:
            if candidate.finding_type in {
                FindingType.EMAIL,
                FindingType.PHONE,
                FindingType.URL,
                FindingType.DOMAIN,
                FindingType.UUID,
            }:
                continue
            # Rejected secret shells never participate; rejected identifiers with only
            # placeholder/weak names may still pair with a strong secret.
            if candidate.validation_state == ValidationState.REJECTED:
                if _has_hard_shell(candidate):
                    continue
                if _rule(candidate) not in (
                    _USERNAME_RULES
                    | _CLIENT_ID_RULES
                    | _DB_USER_RULES
                    | _DB_HOST_RULES
                ):
                    continue
            key = (candidate.asset_id or candidate.source_url, candidate.source_url)
            by_scope[key].append(candidate)

        correlations: list[SensitiveCorrelation] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()
        for scoped in by_scope.values():
            for builder in (
                self._username_password,
                self._client_id_secret,
                self._aws_pair,
                self._token_authorization,
                self._database_set,
            ):
                for correlation in builder(scoped):
                    dedupe_key = (
                        correlation.correlation_type.value,
                        tuple(sorted(correlation.candidate_ids)),
                    )
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    correlations.append(correlation)
        return correlations

    def apply_correlations(
        self,
        candidates: list[SensitiveCandidate],
        correlations: list[SensitiveCorrelation],
    ) -> list[SensitiveCandidate]:
        """Attach correlation evidence and emit confirmed pair candidates when strong."""
        by_id = {item.candidate_id: item for item in candidates}
        emitted: list[SensitiveCandidate] = []
        for correlation in correlations:
            members = [by_id[cid] for cid in correlation.candidate_ids if cid in by_id]
            if not members:
                continue
            if correlation.validation_state != ValidationState.CONFIRMED:
                continue
            for member in members:
                if PositiveEvidence.CORRELATION not in member.positive_evidence:
                    member.positive_evidence.append(PositiveEvidence.CORRELATION)
                if PositiveEvidence.CREDENTIAL_PAIR not in member.positive_evidence:
                    member.positive_evidence.append(PositiveEvidence.CREDENTIAL_PAIR)
                if correlation.correlation_id not in member.correlation_ids:
                    member.correlation_ids.append(correlation.correlation_id)
                member.adjusted_confidence = min(
                    100.0,
                    member.confidence + correlation.confidence_contribution,
                )
            pair_candidate = _correlation_to_candidate(correlation, members[0])
            emitted.append(pair_candidate)
        return emitted

    def _username_password(self, candidates: list[SensitiveCandidate]) -> list[SensitiveCorrelation]:
        users = [item for item in candidates if _rule(item) in _USERNAME_RULES]
        passwords = [item for item in candidates if _rule(item) in _PASSWORD_RULES]
        return self._pair_correlations(
            users,
            passwords,
            correlation_type=CorrelationType.USERNAME_PASSWORD_PAIR,
            subtype="correlated-credentials",
            relationship="username+password proximity",
            secret_required=True,
            severity_hint=SeverityLevel.CRITICAL,
            base_confidence=94.0,
            description="Username and password assignments found near each other.",
            recommendation="Remove hardcoded credential pairs from client-side assets.",
        )

    def _client_id_secret(self, candidates: list[SensitiveCandidate]) -> list[SensitiveCorrelation]:
        ids = [item for item in candidates if _rule(item) in _CLIENT_ID_RULES]
        secrets = [item for item in candidates if _rule(item) in _CLIENT_SECRET_RULES]
        return self._pair_correlations(
            ids,
            secrets,
            correlation_type=CorrelationType.CLIENT_ID_SECRET_PAIR,
            subtype="correlated-client-credentials",
            relationship="client_id+client_secret proximity",
            secret_required=True,
            severity_hint=SeverityLevel.CRITICAL,
            base_confidence=93.0,
            description="Client ID and client secret assignments found near each other.",
            recommendation="Move OAuth client secrets to server-side configuration.",
        )

    def _aws_pair(self, candidates: list[SensitiveCandidate]) -> list[SensitiveCorrelation]:
        access = [item for item in candidates if _rule(item) in _AWS_ACCESS_RULES]
        secrets = [item for item in candidates if _rule(item) in _AWS_SECRET_RULES]
        return self._pair_correlations(
            access,
            secrets,
            correlation_type=CorrelationType.AWS_ACCESS_KEY_SECRET_PAIR,
            subtype="correlated-aws-credentials",
            relationship="aws_access_key+aws_secret proximity",
            secret_required=True,
            severity_hint=SeverityLevel.CRITICAL,
            base_confidence=96.0,
            description="AWS access key and secret key assignments found near each other.",
            recommendation="Rotate exposed AWS credentials immediately.",
            allow_provider_override=True,
        )

    def _token_authorization(
        self,
        candidates: list[SensitiveCandidate],
    ) -> list[SensitiveCorrelation]:
        tokens = [
            item
            for item in candidates
            if _rule(item) in _TOKEN_RULES and _rule(item) != "bearer-token"
        ]
        auths = [item for item in candidates if _rule(item) in _AUTH_RULES]
        return self._pair_correlations(
            tokens,
            auths,
            correlation_type=CorrelationType.TOKEN_AUTHORIZATION_PAIR,
            subtype="correlated-token-authorization",
            relationship="token+Authorization proximity",
            secret_required=True,
            severity_hint=SeverityLevel.HIGH,
            base_confidence=92.0,
            description="Token assignment correlated with an Authorization bearer value.",
            recommendation="Avoid embedding long-lived bearer tokens in client assets.",
            allow_provider_override=True,
            require_overlapping_values=True,
        )

    def _database_set(self, candidates: list[SensitiveCandidate]) -> list[SensitiveCorrelation]:
        hosts = [item for item in candidates if _rule(item) in _DB_HOST_RULES]
        users = [item for item in candidates if _rule(item) in _DB_USER_RULES]
        passwords = [item for item in candidates if _rule(item) in _DB_PASSWORD_RULES]
        uris = [item for item in candidates if _rule(item) in _DB_URI_RULES]
        results: list[SensitiveCorrelation] = []

        # URI with embedded credentials is already a strong database credential set.
        for uri in uris:
            if uri.validation_state == ValidationState.REJECTED:
                continue
            if not _is_secret_eligible(uri, allow_provider_override=True):
                continue
            results.append(
                _build_correlation(
                    correlation_type=CorrelationType.DATABASE_CREDENTIAL_SET,
                    members=[uri],
                    subtype="correlated-database-credentials",
                    relationship="database_uri_credentials",
                    severity_hint=SeverityLevel.CRITICAL,
                    base_confidence=95.0,
                    description="Database connection URI with embedded credentials.",
                    recommendation="Rotate database credentials and remove URIs from clients.",
                    confirmed=True,
                    confidence_contribution=4.0,
                ),
            )

        for host in hosts:
            for user in users:
                for password in passwords:
                    if not _nearby(host, user, self.max_line_distance):
                        continue
                    if not _nearby(user, password, self.max_line_distance):
                        continue
                    members = [host, user, password]
                    confirmed = _is_secret_eligible(password, allow_provider_override=False)
                    if _has_blocking(password) and not _has_provider(password):
                        confirmed = False
                    results.append(
                        _build_correlation(
                            correlation_type=CorrelationType.DATABASE_CREDENTIAL_SET,
                            members=members,
                            subtype="correlated-database-credentials",
                            relationship="db_host+db_user+db_password proximity",
                            severity_hint=SeverityLevel.CRITICAL,
                            base_confidence=94.0,
                            description="Database host, user, and password found near each other.",
                            recommendation="Remove database credentials from client-side assets.",
                            confirmed=confirmed,
                            confidence_contribution=6.0 if confirmed else 0.0,
                            rejection_reason=None
                            if confirmed
                            else "database_correlation_weak_password",
                            raw_value=_pair_raw(user, password),
                        ),
                    )
        return results

    def _pair_correlations(
        self,
        lefts: list[SensitiveCandidate],
        rights: list[SensitiveCandidate],
        *,
        correlation_type: CorrelationType,
        subtype: str,
        relationship: str,
        secret_required: bool,
        severity_hint: SeverityLevel,
        base_confidence: float,
        description: str,
        recommendation: str,
        allow_provider_override: bool = False,
        require_overlapping_values: bool = False,
    ) -> list[SensitiveCorrelation]:
        results: list[SensitiveCorrelation] = []
        for left in lefts:
            for right in rights:
                if left.candidate_id == right.candidate_id:
                    continue
                if not _nearby(left, right, self.max_line_distance):
                    continue
                if require_overlapping_values and not _values_overlap(left, right):
                    continue
                secret = right if secret_required else left
                confirmed = _is_secret_eligible(
                    secret,
                    allow_provider_override=allow_provider_override,
                )
                # Identifier side may be weak/candidate-only, but cannot be empty/runtime/form.
                if _has_hard_shell(left) or _has_hard_shell(right):
                    confirmed = False
                if _has_blocking(secret) and not (
                    allow_provider_override and _has_provider(secret)
                ):
                    confirmed = False
                results.append(
                    _build_correlation(
                        correlation_type=correlation_type,
                        members=[left, right],
                        subtype=subtype,
                        relationship=relationship,
                        severity_hint=severity_hint,
                        base_confidence=base_confidence,
                        description=description,
                        recommendation=recommendation,
                        confirmed=confirmed,
                        confidence_contribution=6.0 if confirmed else 0.0,
                        rejection_reason=None if confirmed else "correlation_weak_or_negative",
                        raw_value=_pair_raw(left, right),
                    ),
                )
        return results


def _rule(candidate: SensitiveCandidate) -> str:
    return candidate.rule_id or candidate.subtype


def _nearby(left: SensitiveCandidate, right: SensitiveCandidate, max_distance: int) -> bool:
    if left.asset_id and right.asset_id and left.asset_id != right.asset_id:
        return False
    if left.source_url and right.source_url and left.source_url != right.source_url:
        return False
    left_line = left.line_number or 0
    right_line = right.line_number or 0
    if left_line and right_line:
        return abs(left_line - right_line) <= max_distance
    # Same asset without line metadata: allow only when evidence snippets overlap heavily.
    return (left.evidence or "")[:80] == (right.evidence or "")[:80]


def _has_blocking(candidate: SensitiveCandidate) -> bool:
    return bool(set(candidate.negative_evidence) & _BLOCKING_NEGATIVES)


def _has_hard_shell(candidate: SensitiveCandidate) -> bool:
    return bool(
        set(candidate.negative_evidence)
        & {
            NegativeEvidence.EMPTY_VALUE,
            NegativeEvidence.RUNTIME_REFERENCE,
            NegativeEvidence.FORM_FIELD,
            NegativeEvidence.FORM_REFERENCE,
            NegativeEvidence.SELF_REFERENCE,
            NegativeEvidence.HTML_ATTRIBUTE,
            NegativeEvidence.GENERATED_TEMPLATE,
        },
    )


def _has_provider(candidate: SensitiveCandidate) -> bool:
    return bool(
        {
            PositiveEvidence.PROVIDER_SPECIFIC_FORMAT,
            PositiveEvidence.STRUCTURED_SECRET,
        }
        & set(candidate.positive_evidence),
    )


def _is_secret_eligible(
    candidate: SensitiveCandidate,
    *,
    allow_provider_override: bool,
) -> bool:
    if candidate.validation_state == ValidationState.REJECTED and not (
        allow_provider_override and _has_provider(candidate)
    ):
        return False
    if _has_blocking(candidate) and not (allow_provider_override and _has_provider(candidate)):
        return False
    if candidate.value_strength in _STRONG_STRENGTHS:
        return True
    if allow_provider_override and _has_provider(candidate):
        return True
    return is_strong_secret_value(candidate.analysis_value)


def _values_overlap(left: SensitiveCandidate, right: SensitiveCandidate) -> bool:
    left_val = (left.analysis_value or "").strip()
    right_val = (right.analysis_value or "").strip()
    if not left_val or not right_val:
        return False
    if left_val == right_val:
        return True
    # Bearer wrappers / JWT bodies.
    if left_val in right_val or right_val in left_val:
        return True
    return False


def _pair_raw(left: SensitiveCandidate, right: SensitiveCandidate) -> str:
    return f"{left.analysis_value or ''}\n{right.analysis_value or ''}"


def _build_correlation(
    *,
    correlation_type: CorrelationType,
    members: list[SensitiveCandidate],
    subtype: str,
    relationship: str,
    severity_hint: SeverityLevel,
    base_confidence: float,
    description: str,
    recommendation: str,
    confirmed: bool,
    confidence_contribution: float,
    rejection_reason: str | None = None,
    raw_value: str | None = None,
) -> SensitiveCorrelation:
    snippets = [item.evidence for item in members if item.evidence]
    lines = [item.line_number for item in members if item.line_number]
    anchor = members[0]
    return SensitiveCorrelation(
        correlation_id=str(uuid4()),
        correlation_type=correlation_type,
        candidate_ids=[item.candidate_id for item in members],
        evidence_snippets=[item[:200] for item in snippets],
        confidence_contribution=confidence_contribution,
        relationship=relationship,
        source_url=anchor.source_url,
        source_file=anchor.source_file,
        asset_id=anchor.asset_id,
        validation_state=ValidationState.CONFIRMED if confirmed else ValidationState.REJECTED,
        rejection_reason=rejection_reason,
        line_number=min(lines) if lines else anchor.line_number,
        subtype=subtype,
        description=description,
        recommendation=recommendation,
        raw_value=raw_value,
        severity_hint=severity_hint,
        base_confidence=base_confidence,
    )


def _correlation_to_candidate(
    correlation: SensitiveCorrelation,
    anchor: SensitiveCandidate,
) -> SensitiveCandidate:
    """Materialize a confirmed correlation as a SensitiveCandidate for FindingTracker."""
    evidence = "\n".join(correlation.evidence_snippets)[:200] or anchor.evidence
    match = DetectorMatch(
        finding_type=FindingType.CREDENTIAL,
        subtype=correlation.subtype,
        matched_value=f"{correlation.subtype} [redacted]",
        matched_pattern=correlation.relationship,
        confidence=correlation.base_confidence,
        severity=correlation.severity_hint,
        evidence=evidence,
        line_number=correlation.line_number,
        byte_offset=0,
        column_number=1,
        category=FindingCategory.CREDENTIALS,
        rule_id=correlation.subtype,
        rule_name=correlation.correlation_type.value,
        description=correlation.description,
        recommendation=correlation.recommendation,
        raw_value=correlation.raw_value,
    )
    candidate = SensitiveCandidate(
        match=match,
        detector_id="candidate-correlator",
        source_url=correlation.source_url or anchor.source_url,
        source_file=correlation.source_file or anchor.source_file,
        relative_path=anchor.relative_path,
        asset_id=correlation.asset_id or anchor.asset_id,
        analysis_value=correlation.raw_value,
        credential_name=correlation.correlation_type.value,
        credential_category=FindingCategory.CREDENTIALS.value,
        value_strength=ValueStrength.REALISTIC,
        original_confidence=correlation.base_confidence,
        original_severity=correlation.severity_hint,
        adjusted_confidence=correlation.base_confidence,
        adjusted_severity=correlation.severity_hint,
        candidate_id=str(uuid4()),
        correlation_ids=[correlation.correlation_id],
        positive_evidence=[
            PositiveEvidence.CREDENTIAL_PAIR,
            PositiveEvidence.CORRELATION,
            PositiveEvidence.STATIC_LITERAL,
        ],
        validation_state=ValidationState.CONFIRMED,
    )
    return candidate
