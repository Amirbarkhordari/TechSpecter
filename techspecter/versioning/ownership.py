"""Technology-scoped version evidence ownership rules."""

from __future__ import annotations

from techspecter.fingerprinting.evidence.models import Evidence, EvidenceType


def evidence_owned_by_technology(technology_id: str, item: Evidence) -> bool:
    """Return True when evidence is explicitly attributable to a technology."""
    tech_id = technology_id.lower()
    if item.technology and item.technology.lower() == tech_id:
        return True

    metadata_tech = str(item.metadata.get("technology", "")).strip().lower()
    if metadata_tech:
        return metadata_tech == tech_id

    runtime_family = str(item.metadata.get("runtime_family", "")).strip().lower()
    if runtime_family:
        return runtime_family == tech_id

    package_hint = str(item.metadata.get("package", "")).strip().lower()
    if package_hint and any(token in package_hint for token in _package_tokens(tech_id)):
        return True

    value_hint = str(item.matched_value or "").strip().lower()
    if value_hint and any(token in value_hint for token in _package_tokens(tech_id)):
        return True

    return False


def version_evidence_relevant(
    technology_id: str,
    item: Evidence,
    *,
    matched_evidence_ids: frozenset[str],
) -> bool:
    """Return True when an evidence item may contribute a version for a technology."""
    if item.evidence_type == EvidenceType.VERSION_CANDIDATE:
        return evidence_owned_by_technology(technology_id, item)

    if evidence_owned_by_technology(technology_id, item):
        return True

    return item.id in matched_evidence_ids


def _package_tokens(technology_id: str) -> tuple[str, ...]:
    normalized = technology_id.lower().replace("_", "-")
    if normalized.startswith("package:"):
        normalized = normalized.removeprefix("package:")
    tokens = {normalized, normalized.replace("-", ""), normalized.replace("-", ".")}
    if normalized == "nextjs":
        tokens.add("next")
    if normalized == "react":
        tokens.update({"react-dom", "reactdom"})
    if normalized == "material-ui":
        tokens.update({"mui", "@mui"})
    return tuple(tokens)
