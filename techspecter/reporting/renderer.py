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
) -> None:
    """Render a scan report to the terminal."""
    if compact:
        _render_compact(report, console=console)
        return

    console.print(f"\n[bold]Target:[/bold] {report.target.url}")
    console.print(f"[bold]Elapsed:[/bold] {report.metadata.scan_duration_ms:.0f} ms")
    console.print(f"[bold]Scripts analyzed:[/bold] {report.statistics.scripts_analyzed}")
    console.print(f"[bold]Summary:[/bold] {report.summary.headline}\n")

    _render_statistics(report, console=console)

    if not report.technologies:
        console.print("[yellow]No JavaScript technologies detected.[/yellow]")
        return

    matches = list(report.technologies)
    if group_by_category:
        _render_grouped(matches, console=console, verbose=verbose)
        return

    _render_table(matches, console=console, verbose=verbose)


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
) -> None:
    """Render technologies grouped by category."""
    grouped: dict[str, list[ReportTechnology]] = defaultdict(list)
    for technology in technologies:
        grouped[technology.category].append(technology)

    for category in sorted(grouped):
        console.print(f"[bold cyan]{category}[/bold cyan]")
        _render_table(grouped[category], console=console, verbose=verbose, title=None)


def _render_table(
    technologies: list[ReportTechnology],
    *,
    console: Console,
    verbose: bool,
    title: str | None = "Detected Technologies",
) -> None:
    """Render a Rich table of technologies."""
    table = Table(title=title)
    table.add_column("Technology")
    table.add_column("Category")
    table.add_column("Version")
    table.add_column("Confidence")
    table.add_column("Evidence")
    table.add_column("Source")
    if verbose:
        table.add_column("Details")

    for technology in technologies:
        source = technology.source_file or "-"
        row = [
            technology.name,
            technology.category,
            technology.version,
            f"{technology.confidence:.1f}",
            str(technology.evidence_count or len(technology.evidence)),
            source,
        ]
        if verbose:
            details = technology.detection_reason or "-"
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
