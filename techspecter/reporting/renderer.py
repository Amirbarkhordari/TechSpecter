"""Console report renderer."""

from __future__ import annotations

from collections import defaultdict

from rich.console import Console
from rich.table import Table

from techspecter.reporting.models import Report, ReportTechnology


def render_report(
    report: Report,
    *,
    console: Console,
    compact: bool = False,
    group_by_category: bool = False,
    verbose: bool = False,
    skip_header: bool = False,
    cli_mode: bool = False,
) -> None:
    """Render a scan report to the terminal."""
    if compact:
        _render_compact(report, console=console)
        return

    if not skip_header:
        console.print(f"\n[bold]Target:[/bold] {report.target.url}")
        console.print(f"[bold]Elapsed:[/bold] {report.metadata.scan_duration_ms:.0f} ms")
        console.print(f"[bold]Scripts analyzed:[/bold] {report.statistics.scripts_analyzed}")
        console.print(f"[bold]Summary:[/bold] {report.summary.headline}\n")

    if not cli_mode:
        _render_statistics(report, console=console)

    if not report.technologies:
        console.print("[yellow]No JavaScript technologies detected.[/yellow]")
        return

    matches = list(report.technologies)
    if group_by_category:
        _render_grouped(matches, console=console, verbose=verbose, cli_mode=cli_mode)
        return

    _render_table(matches, console=console, verbose=verbose, cli_mode=cli_mode)


def _render_statistics(report: Report, *, console: Console) -> None:
    """Render summary statistics."""
    stats = report.statistics
    console.print(
        "[bold]Statistics:[/bold] "
        f"{stats.total_technologies} technologies, "
        f"{stats.category_count} categories, "
        f"avg confidence {stats.average_confidence:.1f}%, "
        f"highest {stats.highest_confidence:.1f}%"
    )
    console.print(
        f"[bold]Versions:[/bold] {stats.known_versions} known, "
        f"{stats.unknown_versions} unknown\n"
    )


def _render_compact(report: Report, *, console: Console) -> None:
    """Render compact one-line output."""
    if not report.technologies:
        console.print(f"{report.target.url}: none")
        return
    for technology in report.technologies:
        console.print(
            f"{technology.name} {technology.version} "
            f"({technology.confidence:.0f}%) [{technology.category}]"
        )


def _render_grouped(
    technologies: list[ReportTechnology],
    *,
    console: Console,
    verbose: bool,
    cli_mode: bool = False,
) -> None:
    """Render technologies grouped by category."""
    grouped: dict[str, list[ReportTechnology]] = defaultdict(list)
    for technology in technologies:
        grouped[technology.category].append(technology)

    for category in sorted(grouped):
        console.print(f"[bold cyan]{category}[/bold cyan]")
        _render_table(
            grouped[category],
            console=console,
            verbose=verbose,
            title=None,
            cli_mode=cli_mode,
        )


def _render_table(
    technologies: list[ReportTechnology],
    *,
    console: Console,
    verbose: bool,
    title: str | None = "Confirmed Technologies",
    cli_mode: bool = False,
) -> None:
    """Render a Rich table of technologies."""
    table = Table(title=title)
    table.add_column("Technology")
    if cli_mode:
        table.add_column("Version")
        table.add_column("Source", overflow="fold")
        table.add_column("Evidence", overflow="fold")
        table.add_column("Confidence")
    else:
        table.add_column("Category")
        table.add_column("Version")
        table.add_column("Confidence")
    if not cli_mode:
        table.add_column("Detected By")
        table.add_column("Evidence")
    if verbose and not cli_mode:
        table.add_column("Details")

    for technology in technologies:
        source = technology.source_file or "-"
        if cli_mode:
            row = [
                technology.name,
                technology.version,
                source,
                technology.evidence_summary or technology.detection_reason or "-",
                f"{technology.confidence:.1f}",
            ]
        else:
            row = [
                technology.name,
                technology.category,
                technology.version,
                f"{technology.confidence:.1f}",
            ]
        if not cli_mode:
            detected_by = ", ".join(technology.detected_by) if technology.detected_by else "-"
            row.extend(
                [
                    detected_by,
                    str(technology.evidence_count or len(technology.evidence)),
                ],
            )
        if verbose and not cli_mode:
            details = technology.detection_reason or "-"
            if technology.detection_methods:
                details = f"{details} | methods: {', '.join(technology.detection_methods)}"
            if technology.version_source:
                version_conf = (
                    f"{technology.version_confidence:.0f}%"
                    if technology.version_confidence is not None
                    else "?"
                )
                details = f"{details} | version from {technology.version_source} ({version_conf})"
            row.append(details)
        table.add_row(*row)
    console.print(table)
