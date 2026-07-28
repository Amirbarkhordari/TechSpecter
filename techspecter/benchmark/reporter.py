"""Benchmark report rendering."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from techspecter.benchmark.models import ComparisonReport, VersionComparison


def render_console(report: ComparisonReport, *, console: Console | None = None) -> None:
    """Render a benchmark comparison report to the terminal."""
    out = console or Console()
    stats = report.statistics

    out.print(f"\n[bold]Benchmark Report[/bold] — {report.target_url}")
    out.print(f"[bold]Wappalyzer source:[/bold] {report.wappalyzer_execution}")
    out.print(f"[bold]Elapsed:[/bold] {report.elapsed_ms:.0f} ms\n")

    out.print("[bold cyan]Summary[/bold cyan]")
    out.print(
        f"  Matched: {stats.matched_technologies} | "
        f"Missing: {stats.missing_detections} | "
        f"Extra: {stats.extra_detections}"
    )
    out.print(
        f"  Precision: {stats.technology_precision:.1%} | "
        f"Recall: {stats.technology_recall:.1%} | "
        f"Coverage: {stats.coverage_percent:.1f}%"
    )
    out.print(
        f"  Version match rate: {stats.version_match_rate:.1%} | "
        f"Version accuracy: {stats.version_accuracy:.1%}\n"
    )

    if report.matched:
        out.print("[bold green]Matched Technologies[/bold green]")
        _render_matched_table(report, console=out)

    if report.wappalyzer_only:
        out.print("\n[bold yellow]Missing Technologies (Wappalyzer only)[/bold yellow]")
        for item in report.wappalyzer_only:
            wap = item.wappalyzer
            version = wap.version if wap is not None else "-"
            out.print(f"  • {item.technology_name} ({version}) [{item.category}]")

    if report.techspecter_only:
        out.print("\n[bold magenta]Extra Technologies (TechSpecter only)[/bold magenta]")
        for item in report.techspecter_only:
            ts = item.techspecter
            conf = f"{ts.confidence:.0f}%" if ts and ts.confidence is not None else "-"
            out.print(f"  • {item.technology_name} ({conf}) [{item.category}]")

    if report.version_comparisons:
        out.print("\n[bold]Version Comparison[/bold]")
        _render_version_table(report.version_comparisons, console=out)

    if report.gap_analysis:
        out.print("\n[bold]Gap Analysis & Recommended Improvements[/bold]")
        for gap in report.gap_analysis[:15]:
            out.print(
                f"  [{gap.severity}] {gap.technology_name}: {gap.reason}\n"
                f"    → {gap.suggested_improvement}",
            )
        if len(report.gap_analysis) > 15:
            out.print(f"  … and {len(report.gap_analysis) - 15} more recommendations")


def render_markdown(report: ComparisonReport) -> str:
    """Render benchmark report as Markdown."""
    stats = report.statistics
    lines = [
        f"# Benchmark Report — {report.target_url}",
        "",
        "## Summary",
        "",
        f"- **Wappalyzer source:** {report.wappalyzer_execution}",
        f"- **Elapsed:** {report.elapsed_ms:.0f} ms",
        f"- **Matched technologies:** {stats.matched_technologies}",
        f"- **Missing detections:** {stats.missing_detections}",
        f"- **Extra detections:** {stats.extra_detections}",
        f"- **Technology precision:** {stats.technology_precision:.2%}",
        f"- **Technology recall:** {stats.technology_recall:.2%}",
        f"- **Coverage:** {stats.coverage_percent:.1f}%",
        f"- **Version match rate:** {stats.version_match_rate:.2%}",
        f"- **Version accuracy:** {stats.version_accuracy:.2%}",
        "",
        "## Matched Technologies",
        "",
    ]

    if report.matched:
        lines.append("| Technology | Category | TechSpecter | Wappalyzer | Version Status |")
        lines.append("|---|---|---|---|---|")
        for item in report.matched:
            ts = item.techspecter
            wap = item.wappalyzer
            ts_ver = ts.version if ts else "-"
            wap_ver = wap.version if wap else "-"
            status = item.version_comparison.status if item.version_comparison else "-"
            lines.append(
                f"| {item.technology_name} | {item.category} | {ts_ver} | {wap_ver} | {status} |",
            )
    else:
        lines.append("_No matched technologies._")

    lines.extend(["", "## Missing Technologies (Wappalyzer only)", ""])
    if report.wappalyzer_only:
        for item in report.wappalyzer_only:
            wap = item.wappalyzer
            version = wap.version if wap else "-"
            lines.append(f"- **{item.technology_name}** ({version}) — {item.category}")
    else:
        lines.append("_None._")

    lines.extend(["", "## Extra Technologies (TechSpecter only)", ""])
    if report.techspecter_only:
        for item in report.techspecter_only:
            ts = item.techspecter
            conf = f"{ts.confidence:.0f}%" if ts and ts.confidence is not None else "-"
            lines.append(f"- **{item.technology_name}** ({conf}) — {item.category}")
    else:
        lines.append("_None._")

    lines.extend(["", "## Version Comparison", ""])
    if report.version_comparisons:
        lines.append("| Technology | TechSpecter | Wappalyzer | Status | Reason |")
        lines.append("|---|---|---|---|---|")
        for version_item in report.version_comparisons:
            reason = version_item.reason or "-"
            lines.append(
                f"| {version_item.technology_name} | {version_item.techspecter_version} | "
                f"{version_item.wappalyzer_version} | {version_item.status} | {reason} |",
            )
    else:
        lines.append("_No shared technologies for version comparison._")

    lines.extend(["", "## Gap Analysis", ""])
    if report.gap_analysis:
        for gap in report.gap_analysis:
            lines.append(
                f"- **[{gap.severity}] {gap.technology_name}** ({gap.gap_type}): "
                f"{gap.reason}. _Suggestion:_ {gap.suggested_improvement}",
            )
    else:
        lines.append("_No gaps identified._")

    lines.append("")
    return "\n".join(lines)


def render_json(report: ComparisonReport) -> str:
    """Render benchmark report as JSON."""
    return json.dumps(report.model_dump(mode="json"), indent=2)


def _render_matched_table(report: ComparisonReport, *, console: Console) -> None:
    """Render matched technologies table."""
    table = Table()
    table.add_column("Technology")
    table.add_column("Category")
    table.add_column("TechSpecter")
    table.add_column("Wappalyzer")
    table.add_column("Version")

    for item in report.matched:
        ts = item.techspecter
        wap = item.wappalyzer
        ts_label = ts.version if ts else "-"
        wap_label = wap.version if wap else "-"
        version_status = item.version_comparison.status if item.version_comparison else "-"
        table.add_row(
            item.technology_name,
            item.category,
            ts_label,
            wap_label,
            version_status,
        )
    console.print(table)


def _render_version_table(comparisons: list[VersionComparison], *, console: Console) -> None:
    """Render version comparison table."""
    table = Table()
    table.add_column("Technology")
    table.add_column("TechSpecter")
    table.add_column("Wappalyzer")
    table.add_column("Status")
    table.add_column("Reason")

    for item in comparisons:
        table.add_row(
            item.technology_name,
            item.techspecter_version,
            item.wappalyzer_version,
            item.status,
            item.reason or "-",
        )
    console.print(table)
