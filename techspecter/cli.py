"""Command-line interface for TechSpecter."""

from __future__ import annotations

import asyncio
import logging
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import orjson
import typer
from rich.console import Console
from rich.table import Table

from techspecter import __version__
from techspecter.analysis.http.analyzer_ids import CLI_FLAG_ANALYZER_MAP, HTTP_ANALYZER_IDS
from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.analysis.service import AnalysisService
from techspecter.configuration.manager import (
    ConfigurationManager,
    get_configuration_manager,
    set_configuration_manager,
)
from techspecter.crawler.discovery import DiscoveryPipeline
from techspecter.exceptions import ReportError, TechSpecterError, ValidationError
from techspecter.fingerprinting.models import FingerprintAnalysisResult
from techspecter.fingerprinting.service import FingerprintService
from techspecter.models.discovery import DiscoveryResult
from techspecter.plugins.cli import plugins_app
from techspecter.reporting.renderer import render_report
from techspecter.reporting.service import ReportService
from techspecter.utils.logging import configure_logging

console = Console()
logger = logging.getLogger(__name__)

app = typer.Typer(
    name="techspecter",
    help="TechSpecter — Passive Web Application Analysis Framework.",
    no_args_is_help=True,
    add_completion=False,
)


class OutputFormat(StrEnum):
    """Supported fingerprint report export formats."""

    json = "json"
    markdown = "markdown"
    html = "html"
    csv = "csv"
    sarif = "sarif"


app.add_typer(plugins_app, name="plugins")


def version_callback(value: bool) -> None:
    """Print the application version and exit."""
    if value:
        console.print(f"TechSpecter {__version__}")
        raise typer.Exit()


def _build_cli_overrides(
    *,
    debug: bool,
    verbose: bool,
    min_confidence: float | None,
    disable_analyzer: list[str] | None,
    enable_analyzer: list[str] | None,
    output: str | None,
    report_format: OutputFormat | None,
    http_analysis: bool | None = None,
    headers: bool = False,
    cookies: bool = False,
    security_headers: bool = False,
    redirects: bool = False,
) -> dict[str, Any]:
    """Build CLI override mapping for the configuration manager."""
    overrides: dict[str, Any] = {}

    logging_override: dict[str, Any] = {}
    if debug or verbose:
        logging_override["debug"] = True
        logging_override["level"] = "DEBUG"
    if logging_override:
        overrides["logging"] = logging_override

    analysis_override: dict[str, Any] = {}
    if min_confidence is not None:
        analysis_override["min_confidence"] = min_confidence
    if disable_analyzer:
        analysis_override["disabled_analyzers"] = disable_analyzer
    if enable_analyzer:
        analysis_override["enabled_analyzers"] = enable_analyzer
    if analysis_override:
        overrides["analysis"] = analysis_override

    http_override: dict[str, Any] = {}
    if http_analysis is not None:
        http_override["http_analysis"] = http_analysis
    if headers:
        http_override["headers"] = True
    if cookies:
        http_override["cookies"] = True
    if security_headers:
        http_override["security_headers"] = True
    if redirects:
        http_override["redirects"] = True

    specific_flags = headers or cookies or security_headers or redirects
    if specific_flags:
        enabled_ids: list[str] = []
        if headers:
            enabled_ids.extend(CLI_FLAG_ANALYZER_MAP["headers"])
        if cookies:
            enabled_ids.extend(CLI_FLAG_ANALYZER_MAP["cookies"])
        if security_headers:
            enabled_ids.extend(CLI_FLAG_ANALYZER_MAP["security_headers"])
        if redirects:
            enabled_ids.extend(CLI_FLAG_ANALYZER_MAP["redirects"])
        analysis_override = overrides.setdefault("analysis", {})
        existing_enabled = analysis_override.get("enabled_analyzers", [])
        if existing_enabled:
            enabled_ids = list(dict.fromkeys([*existing_enabled, *enabled_ids]))
        analysis_override["enabled_analyzers"] = enabled_ids

    if http_override:
        overrides["http_analysis"] = http_override

    reporting_override: dict[str, Any] = {}
    if output is not None:
        output_path = Path(output)
        reporting_override["output_directory"] = str(output_path.parent or ".")
        reporting_override["filename"] = output_path.name
    if report_format is not None:
        reporting_override["default_format"] = report_format.value
    if reporting_override:
        overrides["reporting"] = reporting_override

    return overrides


@app.callback()
def cli_callback(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            help="Show the application version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to a YAML or JSON configuration file."),
    ] = None,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Enable debug logging."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Enable verbose (DEBUG) logging."),
    ] = False,
) -> None:
    """TechSpecter — passive web application analysis framework."""
    manager = ConfigurationManager.load(
        config_path=config,
        cli_overrides=_build_cli_overrides(
            debug=debug,
            verbose=verbose,
            min_confidence=None,
            disable_analyzer=[],
            enable_analyzer=[],
            output=None,
            report_format=None,
            http_analysis=None,
        ),
    )
    set_configuration_manager(manager)
    configure_logging(config=manager.config.logging)
    logger.debug("TechSpecter CLI initialized (v%s)", __version__)


def _serialize_discovery_result(result: DiscoveryResult) -> dict[str, Any]:
    """Convert a discovery result to a JSON-serializable dictionary."""
    return result.model_dump(mode="json")


def _render_discovery_result(result: DiscoveryResult) -> None:
    """Render a human-readable discovery summary."""
    console.print(f"\n[bold]Target:[/bold] {result.target.url}")
    console.print(f"[bold]Elapsed:[/bold] {result.elapsed_ms:.0f} ms\n")

    console.print(
        f"[bold]Discovered:[/bold] {len(result.external_scripts)} external, "
        f"{len(result.inline_scripts)} inline"
    )
    console.print(
        f"[bold]Downloads:[/bold] {result.downloaded_count} succeeded, "
        f"{result.failed_count} failed\n"
    )

    if result.external_scripts:
        external_table = Table(title="External Scripts")
        external_table.add_column("URL", overflow="fold")
        external_table.add_column("Original", overflow="fold")
        for script in result.external_scripts:
            external_table.add_row(str(script.url), script.original_url)
        console.print(external_table)

    if result.downloads:
        download_table = Table(title="Download Results")
        download_table.add_column("Filename")
        download_table.add_column("Status")
        download_table.add_column("Size")
        download_table.add_column("Duration")
        download_table.add_column("Source Map")
        for item in result.downloads:
            status = str(item.status_code) if item.status_code is not None else "N/A"
            if not item.download_success:
                status = f"[red]{status}[/red]"
            size = str(item.content_length) if item.content_length is not None else "N/A"
            duration = (
                f"{item.download_duration_ms:.0f} ms"
                if item.download_duration_ms is not None
                else "N/A"
            )
            source_map = item.source_map_url or "-"
            download_table.add_row(item.filename, status, size, duration, source_map)
        console.print(download_table)

    if result.inline_scripts:
        console.print(f"\n[bold]Inline Scripts:[/bold] {len(result.inline_scripts)} found")


@app.command("discover")
def discover_command(
    url: Annotated[str, typer.Argument(help="Target website URL to scan.")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Discover and download JavaScript resources from a target website."""
    try:
        pipeline = DiscoveryPipeline()
        result = asyncio.run(pipeline.run(url))
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except TechSpecterError as exc:
        console.print(f"[red]Discovery failed:[/red] {exc}")
        logger.exception("Discovery failed for %s", url)
        raise typer.Exit(code=1) from exc

    if json_output:
        payload = _serialize_discovery_result(result)
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    _render_discovery_result(result)


def _serialize_fingerprint_result(result: FingerprintAnalysisResult) -> dict[str, Any]:
    """Convert a fingerprint analysis result to JSON."""
    return result.model_dump(mode="json")


@app.command("fingerprint")
def fingerprint_command(
    url: Annotated[str, typer.Argument(help="Target website URL to fingerprint.")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw analysis results as JSON."),
    ] = False,
    report_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", help="Export report format."),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", help="Write exported report to this file."),
    ] = None,
    compact: Annotated[
        bool,
        typer.Option("--compact", help="Output compact one-line results."),
    ] = False,
    group_by_category: Annotated[
        bool,
        typer.Option("--group-by-category", help="Group results by technology category."),
    ] = False,
    verbose_output: Annotated[
        bool,
        typer.Option("--verbose-output", help="Include matched pattern evidence in output."),
    ] = False,
    min_confidence: Annotated[
        float | None,
        typer.Option(
            "--min-confidence", help="Minimum confidence threshold (divided by 100 if > 1)."
        ),
    ] = None,
    disable_analyzer: Annotated[
        list[str] | None,
        typer.Option("--disable-analyzer", help="Disable an analyzer by ID."),
    ] = None,
    enable_analyzer: Annotated[
        list[str] | None,
        typer.Option("--enable-analyzer", help="Enable only listed analyzers when set globally."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to a YAML or JSON configuration file."),
    ] = None,
) -> None:
    """Discover JavaScript resources and identify technologies."""
    if enable_analyzer is None:
        enable_analyzer = []
    if disable_analyzer is None:
        disable_analyzer = []
    manager = get_configuration_manager()
    normalized_confidence = min_confidence

    command_overrides = _build_cli_overrides(
        debug=False,
        verbose=False,
        min_confidence=normalized_confidence,
        disable_analyzer=disable_analyzer,
        enable_analyzer=enable_analyzer,
        output=output,
        report_format=report_format,
        http_analysis=None,
    )
    if config is not None:
        manager = ConfigurationManager.load(config_path=config, cli_overrides=command_overrides)
        set_configuration_manager(manager)
    elif command_overrides:
        manager.apply_cli_overrides(command_overrides)

    active_config = manager.config
    if not active_config.analysis.is_analyzer_enabled("technology-fingerprint"):
        console.print(
            "[yellow]Technology fingerprint analyzer is disabled by configuration.[/yellow]"
        )
        raise typer.Exit(code=1)

    try:
        service = FingerprintService()
        result = asyncio.run(service.analyze_url(url))
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except TechSpecterError as exc:
        console.print(f"[red]Fingerprint analysis failed:[/red] {exc}")
        logger.exception("Fingerprint analysis failed for %s", url)
        raise typer.Exit(code=1) from exc

    if json_output:
        payload = _serialize_fingerprint_result(result)
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    report_service = ReportService()
    selected_format = (
        report_format.value if report_format is not None else active_config.reporting.default_format
    )
    export_path = output
    if export_path is None and active_config.reporting.filename:
        export_path = str(
            Path(active_config.reporting.output_directory) / active_config.reporting.filename
        )

    try:
        if selected_format is not None:
            if not active_config.reporting.is_format_enabled(selected_format):
                console.print(
                    f"[red]Report format '{selected_format}' is disabled by configuration.[/red]"
                )
                raise typer.Exit(code=1)
            export_result = report_service.generate_and_export(
                result.detection,
                selected_format,  # type: ignore[arg-type]
                output_path=export_path,
                scan_duration_ms=result.elapsed_ms,
            )
            if export_path is None:
                console.print(export_result.content)
            else:
                console.print(f"[green]Report written to[/green] {export_result.output_path}")
            return

        report = report_service.generate_report(
            result.detection,
            scan_duration_ms=result.elapsed_ms,
        )
    except ReportError as exc:
        console.print(f"[red]Report generation failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    render_report(
        report,
        console=console,
        compact=compact,
        group_by_category=group_by_category,
        verbose=verbose_output,
    )


def _render_analysis_summary(result: AnalysisResult) -> None:
    """Render a human-readable HTTP analysis summary."""
    console.print(f"\n[bold]Target:[/bold] {result.target_url}")
    console.print(f"[bold]Elapsed:[/bold] {result.elapsed_ms:.0f} ms")
    console.print(f"[bold]Findings:[/bold] {result.statistics.total_findings}")
    console.print(f"[bold]Analyzers:[/bold] {', '.join(result.metadata.analyzers)}\n")

    if not result.findings:
        console.print("[yellow]No findings detected.[/yellow]")
        return

    table = Table(title="HTTP Analysis Findings")
    table.add_column("Analyzer")
    table.add_column("Severity")
    table.add_column("Title", overflow="fold")
    for finding in result.findings[:50]:
        table.add_row(finding.analyzer, finding.severity.value, finding.title)
    console.print(table)
    if len(result.findings) > 50:
        console.print(f"[dim]... and {len(result.findings) - 50} more findings[/dim]")


@app.command("analyze")
def analyze_command(
    url: Annotated[str, typer.Argument(help="Target website URL to analyze passively.")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw analysis results as JSON."),
    ] = False,
    report_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", help="Export report format."),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", help="Write exported report to this file."),
    ] = None,
    http_analysis: Annotated[
        bool,
        typer.Option("--http-analysis", help="Enable passive HTTP analysis analyzers."),
    ] = True,
    headers: Annotated[
        bool,
        typer.Option("--headers", help="Enable HTTP header analyzer."),
    ] = False,
    cookies: Annotated[
        bool,
        typer.Option("--cookies", help="Enable cookie analyzer."),
    ] = False,
    security_headers: Annotated[
        bool,
        typer.Option("--security-headers", help="Enable security header analyzers."),
    ] = False,
    redirects: Annotated[
        bool,
        typer.Option("--redirects", help="Enable redirect analyzer."),
    ] = False,
    disable_analyzer: Annotated[
        list[str] | None,
        typer.Option("--disable-analyzer", help="Disable an analyzer by ID."),
    ] = None,
    enable_analyzer: Annotated[
        list[str] | None,
        typer.Option("--enable-analyzer", help="Enable only listed analyzers when set."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to a YAML or JSON configuration file."),
    ] = None,
) -> None:
    """Run passive HTTP analysis against a target website."""
    if enable_analyzer is None:
        enable_analyzer = []
    if disable_analyzer is None:
        disable_analyzer = []

    manager = get_configuration_manager()
    command_overrides = _build_cli_overrides(
        debug=False,
        verbose=False,
        min_confidence=None,
        disable_analyzer=disable_analyzer,
        enable_analyzer=enable_analyzer or list(HTTP_ANALYZER_IDS),
        output=output,
        report_format=report_format,
        http_analysis=http_analysis,
        headers=headers,
        cookies=cookies,
        security_headers=security_headers,
        redirects=redirects,
    )
    if config is not None:
        manager = ConfigurationManager.load(config_path=config, cli_overrides=command_overrides)
        set_configuration_manager(manager)
    elif command_overrides:
        manager.apply_cli_overrides(command_overrides)

    active_config = manager.config
    if headers and not active_config.http_analysis.is_analyzer_enabled("http-header-analyzer"):
        console.print("[yellow]HTTP header analyzer is disabled by configuration.[/yellow]")
        raise typer.Exit(code=1)

    try:
        service = AnalysisService()
        result = asyncio.run(service.analyze_url(url))
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except TechSpecterError as exc:
        console.print(f"[red]HTTP analysis failed:[/red] {exc}")
        logger.exception("HTTP analysis failed for %s", url)
        raise typer.Exit(code=1) from exc

    if json_output:
        payload = result.model_dump(mode="json")
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    report_service = ReportService()
    selected_format = (
        report_format.value if report_format is not None else active_config.reporting.default_format
    )
    export_path = output
    if export_path is None and active_config.reporting.filename:
        export_path = str(
            Path(active_config.reporting.output_directory) / active_config.reporting.filename
        )

    try:
        if selected_format is not None:
            if not active_config.reporting.is_format_enabled(selected_format):
                console.print(
                    f"[red]Report format '{selected_format}' is disabled by configuration.[/red]"
                )
                raise typer.Exit(code=1)
            export_result = report_service.generate_and_export_from_analysis(
                result,
                selected_format,  # type: ignore[arg-type]
                output_path=export_path,
                scan_duration_ms=result.elapsed_ms,
            )
            if export_path is None:
                console.print(export_result.content)
            else:
                console.print(f"[green]Report written to[/green] {export_result.output_path}")
            return

        _render_analysis_summary(result)
    except ReportError as exc:
        console.print(f"[red]Report generation failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def main() -> None:
    """Console script entry point for the ``techspecter`` command."""
    app()


if __name__ == "__main__":
    main()
