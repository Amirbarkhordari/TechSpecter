"""Benchmark CLI helpers."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from techspecter.benchmark.models import ComparisonReport
from techspecter.benchmark.reporter import render_console, render_json, render_markdown
from techspecter.benchmark.runner import BenchmarkRunner
from techspecter.exceptions import TechSpecterError
from techspecter.utils.errors import format_user_error


def run_benchmark(
    url: str,
    *,
    wappalyzer_result: Path | str | None = None,
    json_output: bool = False,
    report_format: str | None = None,
    output: str | None = None,
    console: Console,
    debug: bool = False,
) -> ComparisonReport:
    """Execute benchmark comparison and render output."""
    try:
        report = BenchmarkRunner().run(url, wappalyzer_result=wappalyzer_result)
    except (RuntimeError, FileNotFoundError, ValueError, TechSpecterError) as exc:
        console.print(f"[red]Benchmark failed:[/red] {format_user_error(exc, debug=debug)}")
        raise typer.Exit(code=1) from exc

    if json_output or report_format == "json":
        content = render_json(report)
        if output:
            Path(output).write_text(content, encoding="utf-8")
            console.print(f"[green]Benchmark report written to[/green] {output}")
        else:
            console.print(content)
        return report

    if report_format == "markdown":
        content = render_markdown(report)
        if output:
            Path(output).write_text(content, encoding="utf-8")
            console.print(f"[green]Benchmark report written to[/green] {output}")
        else:
            console.print(content)
        return report

    render_console(report, console=console)
    if output:
        content = render_markdown(report)
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"[green]Benchmark report written to[/green] {output}")
    return report
