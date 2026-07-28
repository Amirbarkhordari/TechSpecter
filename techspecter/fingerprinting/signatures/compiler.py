"""Compile typed indicators into detection rules."""

from __future__ import annotations

from techspecter.fingerprinting.signatures.models import (
    SignatureIndicators,
    SignatureRule,
    TechnologySignature,
)

_INDICATOR_TARGETS: tuple[tuple[str, str], ...] = (
    ("runtime", "runtime"),
    ("bundle", "bundle"),
    ("html", "html"),
    ("http", "http"),
    ("header", "header"),
    ("manifest", "manifest"),
    ("sourcemap", "sourcemap"),
    ("package", "package"),
    ("metadata", "metadata"),
    ("content", "content"),
)


def compile_signature(signature: TechnologySignature) -> TechnologySignature:
    """Merge indicator groups and legacy rules into a compiled signature."""
    required = _compile_indicators(signature.id, signature.required_evidence, role="required")
    positive = _compile_indicators(signature.id, signature.optional_evidence, role="positive")
    negative = _compile_indicators(signature.id, signature.negative_evidence, role="negative")

    merged_required = _dedupe_rules((*signature.required_rules, *required))
    merged_positive = _dedupe_rules((*signature.positive_rules, *positive))
    merged_optional = _dedupe_rules(signature.optional_rules)
    merged_negative = _dedupe_rules((*signature.negative_rules, *negative))

    return signature.model_copy(
        update={
            "required_rules": merged_required,
            "positive_rules": merged_positive,
            "optional_rules": merged_optional,
            "negative_rules": merged_negative,
        },
    )


def _compile_indicators(
    tech_id: str,
    indicators: SignatureIndicators,
    *,
    role: str,
) -> tuple[SignatureRule, ...]:
    """Convert indicator groups to signature rules."""
    rules: list[SignatureRule] = []
    for target_attr, target in _INDICATOR_TARGETS:
        group = getattr(indicators, target_attr)
        for indicator in group:
            rules.append(
                SignatureRule(
                    id=f"{tech_id}-{role}-{indicator.id}",
                    matcher=indicator.matcher,
                    pattern=indicator.pattern,
                    weight=_role_weight(indicator.weight, role),
                    target=target,
                    description=indicator.description,
                    metadata={"role": role, "indicator": indicator.id},
                ),
            )
    return tuple(rules)


def _role_weight(weight: float, role: str) -> float:
    """Adjust indicator weight by rule role."""
    if role == "required":
        return max(1.0, min(weight, 5.0))
    if role == "negative":
        return 1.0
    return weight


def _dedupe_rules(rules: tuple[SignatureRule, ...]) -> tuple[SignatureRule, ...]:
    """Remove duplicate rules by id."""
    seen: set[str] = set()
    deduped: list[SignatureRule] = []
    for rule in rules:
        if rule.id in seen:
            continue
        seen.add(rule.id)
        deduped.append(rule)
    return tuple(deduped)
