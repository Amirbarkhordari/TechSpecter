"""Unified fingerprint report rendering with integrated discovery sections."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.table import Table

from techspecter.fingerprinting.models import (
    DetectionResult,
    FingerprintAnalysisResult,
    SecurityFinding,
)
from techspecter.reporting.cli_display import count_fingerprint_security_findings
from techspecter.reporting.models import Report
from techspecter.reporting.renderer import render_report
from techspecter.sensitive_intelligence.cli_display import (
    filter_fingerprint_cli_findings,
    render_security_summary_lines,
)

logger = logging.getLogger(__name__)

_SECTION_WIDTH = 50


def render_fingerprint_report(
    result: FingerprintAnalysisResult,
    report: Report,
    *,
    console: Console,
    compact: bool = False,
    group_by_category: bool = False,
    verbose: bool = False,
    show_assets: bool = False,
) -> None:
    """Render the complete fingerprint report in the required section order."""
    if compact:
        render_report(report, console=console, compact=True)
        return

    _render_target_summary(result, report, console=console)

    if result.asset_inventory is not None:
        from techspecter.asset_discovery.report import render_fingerprint_asset_inventory

        render_fingerprint_asset_inventory(
            result.asset_inventory,
            console=console,
            show_assets=show_assets or verbose,
        )

    _render_technology_detection(
        report, console=console, group_by_category=group_by_category, verbose=verbose
    )

    if result.technology_intelligence is not None:
        from techspecter.technology_intelligence.report import (
            render_fingerprint_technology_evidence,
            render_fingerprint_technology_intelligence,
        )

        render_fingerprint_technology_intelligence(
            result.technology_intelligence,
            console=console,
        )
        render_fingerprint_technology_evidence(result.technology_intelligence, console=console)

    if result.sensitive_intelligence is not None:
        from techspecter.sensitive_intelligence.cli_display import (
            render_fingerprint_sensitive_intelligence,
        )

        render_fingerprint_sensitive_intelligence(result.sensitive_intelligence, console=console)

    _render_security_summary(
        result.detection,
        sensitive=result.sensitive_intelligence,
        console=console,
    )


def _render_target_summary(
    result: FingerprintAnalysisResult,
    report: Report,
    *,
    console: Console,
) -> None:
    """Render target summary as the first report section."""
    console.print("\n" + "=" * _SECTION_WIDTH)
    console.print("[bold]Target Summary[/bold]")
    console.print("=" * _SECTION_WIDTH + "\n")
    console.print(f"[bold]Target:[/bold] {report.target.url}")
    console.print(f"[bold]Elapsed:[/bold] {result.elapsed_ms:.0f} ms")
    console.print(f"[bold]Discovery:[/bold] {result.discovery_elapsed_ms:.0f} ms")
    console.print(f"[bold]Scripts analyzed:[/bold] {report.statistics.scripts_analyzed}")
    console.print(f"[bold]Summary:[/bold] {report.summary.headline}")

    merge_summary = result.provider_diagnostics.get("merge_summary")
    if isinstance(merge_summary, dict) and merge_summary.get("providers_succeeded"):
        providers = merge_summary.get("providers_succeeded", [])
        if isinstance(providers, list):
            console.print(f"[bold]Providers:[/bold] {', '.join(str(item) for item in providers)}")

    inventory = result.asset_inventory
    if inventory is not None:
        console.print(f"[bold]Assets discovered:[/bold] {inventory.summary.total_assets}")

    sensitive = result.sensitive_intelligence
    if sensitive is not None:
        security_count = count_fingerprint_security_findings(sensitive)
        if security_count:
            console.print(f"[bold]Security findings:[/bold] {security_count}")
    console.print()


def _render_technology_detection(
    report: Report,
    *,
    console: Console,
    group_by_category: bool,
    verbose: bool,
) -> None:
    """Render technology detection section."""
    console.print("=" * _SECTION_WIDTH)
    console.print("[bold]Technology Detection[/bold]")
    console.print("=" * _SECTION_WIDTH + "\n")

    if not report.technologies:
        console.print("[yellow]No JavaScript technologies detected.[/yellow]\n")
        return

    render_report(
        report,
        console=console,
        compact=False,
        group_by_category=group_by_category,
        verbose=verbose,
        skip_header=True,
        cli_mode=True,
    )
    console.print()


def _render_security_summary(
    detection: DetectionResult,
    *,
    sensitive: object | None,
    console: Console,
) -> None:
    """Render passive security findings from detection providers and sensitive intelligence."""
    cve_findings = _collect_security_findings(detection)
    sensitive_findings = []
    if sensitive is not None:
        from techspecter.sensitive_intelligence.models import SensitiveIntelligenceReport

        if isinstance(sensitive, SensitiveIntelligenceReport):
            sensitive_findings = filter_fingerprint_cli_findings(sensitive.findings)

    console.print("=" * _SECTION_WIDTH)
    console.print("[bold]Security Summary[/bold]")
    console.print("=" * _SECTION_WIDTH + "\n")

    if not cve_findings and not sensitive_findings:
        console.print("[dim]No passive security findings reported.[/dim]\n")
        return

    if sensitive_findings:
        console.print("[bold]Sensitive Intelligence[/bold]\n")
        for line in render_security_summary_lines(sensitive_findings):
            console.print(line)
        console.print("")

    if cve_findings:
        console.print("[bold]Known Vulnerabilities[/bold]\n")
        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Library", overflow="fold")
        table.add_column("Version", overflow="fold")
        table.add_column("Severity", no_wrap=True)
        table.add_column("CVEs", overflow="fold")
        table.add_column("Source File", overflow="fold")

        for item in cve_findings:
            table.add_row(
                item.library,
                item.installed_version,
                item.severity or "unknown",
                ", ".join(item.cve_ids) if item.cve_ids else "-",
                item.source_file or "-",
            )
        console.print(table)
        console.print("")


def _collect_security_findings(detection: DetectionResult) -> list[SecurityFinding]:
    """Collect unique security findings across all technology matches."""
    seen: set[tuple[str, str, str]] = set()
    findings: list[SecurityFinding] = []
    for match in detection.matches:
        for item in match.security_findings:
            key = (item.library, item.installed_version, item.source_file or "")
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
    return findings
