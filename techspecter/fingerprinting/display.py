"""Fingerprint command rendering helpers."""

from __future__ import annotations

from collections import defaultdict

from rich.console import Console
from rich.table import Table

from techspecter.fingerprinting.models import FingerprintAnalysisResult, TechnologyMatch


def render_fingerprint_result(
    result: FingerprintAnalysisResult,
    *,
    console: Console,
    compact: bool = False,
    group_by_category: bool = False,
    verbose: bool = False,
) -> None:
    """Render fingerprint analysis output."""
    if compact:
        _render_compact(result, console=console)
        return

    console.print(f"\n[bold]Target:[/bold] {result.target_url}")
    console.print(f"[bold]Elapsed:[/bold] {result.elapsed_ms:.0f} ms")
    console.print(f"[bold]Scripts analyzed:[/bold] {result.detection.scripts_analyzed}\n")

    matches = sorted(
        result.detection.matches,
        key=lambda item: (-item.confidence, item.technology.name.lower()),
    )
    if not matches:
        console.print("[yellow]No JavaScript technologies detected.[/yellow]")
        return

    if group_by_category:
        _render_grouped(matches, console=console, verbose=verbose)
        return

    _render_table(matches, console=console, verbose=verbose)


def _render_compact(result: FingerprintAnalysisResult, *, console: Console) -> None:
    """Render a compact one-line-per-match summary."""
    if not result.detection.matches:
        console.print(f"{result.target_url}: none")
        return
    for match in sorted(result.detection.matches, key=lambda item: -item.confidence):
        console.print(
            f"{match.technology.name} {match.version} "
            f"({match.confidence:.0f}%) [{match.technology.category}]"
        )


def _render_grouped(
    matches: list[TechnologyMatch],
    *,
    console: Console,
    verbose: bool,
) -> None:
    """Render matches grouped by category."""
    grouped: dict[str, list[TechnologyMatch]] = defaultdict(list)
    for match in matches:
        grouped[match.technology.category].append(match)

    for category in sorted(grouped):
        console.print(f"[bold cyan]{category}[/bold cyan]")
        _render_table(grouped[category], console=console, verbose=verbose, title=None)


def _render_table(
    matches: list[TechnologyMatch],
    *,
    console: Console,
    verbose: bool,
    title: str | None = "Detected Technologies",
) -> None:
    """Render a Rich table of technology matches."""
    table = Table(title=title)
    table.add_column("Technology")
    table.add_column("Category")
    table.add_column("Version")
    table.add_column("Confidence")
    table.add_column("Source")
    if verbose:
        table.add_column("Evidence")

    for match in matches:
        source = match.filename or match.source_url or "-"
        row = [
            match.technology.name,
            match.technology.category,
            match.version,
            f"{match.confidence:.1f}",
            source,
        ]
        if verbose:
            evidence = ", ".join(match.matched_patterns[:5])
            if len(match.matched_patterns) > 5:
                evidence += "..."
            row.append(evidence)
        table.add_row(*row)
    console.print(table)
