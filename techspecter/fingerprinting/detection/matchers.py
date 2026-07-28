"""Evidence rule matching."""

from __future__ import annotations

import re

from techspecter.fingerprinting.detection.models import NormalizedEvidence, RuleMatch
from techspecter.fingerprinting.signatures.models import SignatureRule

_REGEX_CACHE: dict[tuple[str, str], re.Pattern[str]] = {}


def match_rule(rule: SignatureRule, item: NormalizedEvidence) -> RuleMatch | None:
    """Match a signature rule against normalized evidence."""
    if not _target_matches(rule.target, item):
        return None

    haystack = _select_haystack(rule.target, item)
    if haystack is None:
        return None

    matched = _apply_matcher(rule.matcher, rule.pattern, haystack, item)
    if matched is None:
        return None

    weight = rule.weight * (item.base_weight / 100.0)
    return RuleMatch(
        rule=rule,
        evidence=item.evidence,
        matched_text=matched,
        weight=max(0.1, weight),
    )


def _target_matches(target: str, item: NormalizedEvidence) -> bool:
    """Return whether evidence target filter matches."""
    evidence_type = item.evidence.evidence_type.value
    mapping = {
        "content": True,
        "runtime": evidence_type == "runtime_pattern",
        "package": evidence_type in {"package_reference", "package_marker", "import_export"},
        "banner": evidence_type == "banner",
        "manifest": evidence_type == "manifest",
        "bundle": evidence_type in {"bundle_runtime", "bundle_marker"},
        "header": evidence_type in {"http_header", "http_metadata"},
        "html": evidence_type in {"html_element", "script_reference"},
        "metadata": evidence_type == "metadata",
        "filename": bool(item.evidence.file),
        "url": bool(item.evidence.url),
        "sourcemap": evidence_type in {"source_map", "source_map_metadata"},
        "version": evidence_type == "version_candidate",
    }
    if target in mapping:
        return mapping[target]
    if target.startswith("evidence:"):
        return evidence_type == target.split(":", 1)[1]
    return True


def _select_haystack(target: str, item: NormalizedEvidence) -> str | None:
    """Select the string field to match against."""
    evidence = item.evidence
    if target == "filename":
        return (evidence.file or "").lower()
    if target == "url":
        return (evidence.url or "").lower()
    if target == "metadata":
        return " ".join(str(value).lower() for value in evidence.metadata.values())
    return item.normalized_value


def _apply_matcher(
    matcher: str,
    pattern: str,
    haystack: str,
    item: NormalizedEvidence,
) -> str | None:
    """Apply matcher strategy to haystack."""
    if matcher in {"string", "contains"}:
        if pattern.lower() in haystack:
            return pattern
        return None
    if matcher == "equals":
        if haystack == pattern.lower():
            return pattern
        return None
    if matcher == "regex":
        compiled = _compile_regex(pattern)
        match = compiled.search(haystack)
        if match is None:
            return None
        return match.group(0)
    if matcher == "metadata_key":
        return pattern if pattern in item.evidence.metadata else None
    if matcher == "metadata_value":
        for value in item.evidence.metadata.values():
            if str(value).lower() == pattern.lower():
                return str(value)
        return None
    if matcher == "runtime_family":
        family = str(item.evidence.metadata.get("runtime_family", "")).lower()
        if family == pattern.lower():
            return family
        return None
    return None


def _compile_regex(pattern: str) -> re.Pattern[str]:
    """Compile and cache regex patterns."""
    key = ("i", pattern)
    compiled = _REGEX_CACHE.get(key)
    if compiled is None:
        compiled = re.compile(pattern, re.IGNORECASE)
        _REGEX_CACHE[key] = compiled
    return compiled
