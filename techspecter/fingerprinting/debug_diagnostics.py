"""Fingerprint detection debug diagnostics for developers."""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from techspecter.fingerprinting.match_quality import MatchQualityGate, evidence_tier
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch


@dataclass(frozen=True, slots=True)
class MatchDecision:
    """Explainable confirmation or rejection decision for one match."""

    technology: str
    confirmed: bool
    source_file: str | None
    confidence: float
    version: str
    primary_evidence: str
    reason: str
    evidence_tiers: list[str]


def evidence_summary(match: TechnologyMatch) -> str:
    """Build a concise evidence label for reporting."""
    if match.matched_value and match.primary_matcher:
        return f"{match.primary_matcher}:{match.matched_value}"
    if match.detection_reason and " @ " in match.detection_reason:
        return match.detection_reason.split(" @ ", 1)[0]
    if match.evidence:
        primary = max(match.evidence, key=lambda item: item.weight)
        value = primary.matched_value or primary.pattern
        return f"{primary.matcher}:{value}"
    if match.matched_patterns:
        return match.matched_patterns[0]
    return "-"


def explain_match(match: TechnologyMatch, *, gate: MatchQualityGate | None = None) -> MatchDecision:
    """Explain why a match was confirmed or rejected."""
    quality_gate = gate or MatchQualityGate()
    patterns = quality_gate._collect_patterns(match)
    tiers = [evidence_tier(item) for item in patterns] if patterns else []
    confirmed = quality_gate.is_confirmed(match)
    if confirmed:
        reason = "confirmed: evidence-backed detection passed quality gate"
    else:
        reason = quality_gate.rejection_reason(match)

    return MatchDecision(
        technology=match.technology.name,
        confirmed=confirmed,
        source_file=match.source_file or match.filename or match.source_url,
        confidence=match.confidence,
        version=match.version,
        primary_evidence=evidence_summary(match),
        reason=reason,
        evidence_tiers=tiers,
    )


def render_debug_fingerprint_report(
    detection: DetectionResult,
    *,
    console: Console,
) -> None:
    """Render developer-oriented fingerprint diagnostics."""
    gate = MatchQualityGate()
    console.print("\n[bold cyan]Fingerprint Debug Diagnostics[/bold cyan]\n")
    console.print(
        f"[dim]Scripts analyzed:[/dim] {detection.scripts_analyzed}  "
        f"[dim]Pipeline time:[/dim] {detection.elapsed_ms:.0f} ms  "
        f"[dim]Confirmed:[/dim] {len(detection.matches)}  "
        f"[dim]Rejected:[/dim] {len(detection.ignored_matches)}"
    )
    console.print()

    if detection.matches:
        _render_decision_table(
            "Confirmed Detections",
            [explain_match(item, gate=gate) for item in detection.matches],
            console=console,
            style="green",
        )

    if detection.ignored_matches:
        _render_decision_table(
            "Rejected / Weak Detections",
            [explain_match(item, gate=gate) for item in detection.ignored_matches],
            console=console,
            style="yellow",
        )

    console.print("[dim]Tip: weak indicators alone never produce confirmed output.[/dim]\n")


def _render_decision_table(
    title: str,
    decisions: list[MatchDecision],
    *,
    console: Console,
    style: str,
) -> None:
    table = Table(title=title, show_header=True, header_style=f"bold {style}")
    table.add_column("Technology")
    table.add_column("Source", overflow="fold")
    table.add_column("Evidence", overflow="fold")
    table.add_column("Version")
    table.add_column("Confidence")
    table.add_column("Decision", overflow="fold")
    for item in decisions:
        table.add_row(
            item.technology,
            item.source_file or "-",
            item.primary_evidence,
            item.version,
            f"{item.confidence:.1f}",
            item.reason,
        )
    console.print(table)
    console.print()
