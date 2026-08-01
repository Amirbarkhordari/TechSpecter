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
from techspecter._version import version_display
from techspecter.analysis.artifact.analyzer_ids import (
    ARTIFACT_ANALYZER_IDS,
    CLI_FLAG_ARTIFACT_MAP,
    SENSITIVE_ARTIFACT_ANALYZER_IDS,
)
from techspecter.analysis.http.analyzer_ids import CLI_FLAG_ANALYZER_MAP, HTTP_ANALYZER_IDS
from techspecter.analysis.metadata.analyzer_ids import CLI_FLAG_METADATA_MAP, METADATA_ANALYZER_IDS
from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.analysis.service import AnalysisService
from techspecter.benchmark.cli_handlers import run_benchmark
from techspecter.configuration.manager import (
    ConfigurationManager,
    get_configuration_manager,
    set_configuration_manager,
)
from techspecter.crawler.discovery import DiscoveryPipeline, DiscoveryPipelineConfig
from techspecter.exceptions import ReportError, TechSpecterError, ValidationError
from techspecter.fingerprinting.models import FingerprintAnalysisResult
from techspecter.models.discovery import DiscoveryResult
from techspecter.plugins.cli import plugins_app
from techspecter.providers.service import UnifiedDetectionService
from techspecter.reporting.service import ReportService
from techspecter.utils.errors import format_user_error
from techspecter.utils.logging import configure_logging

console = Console()
logger = logging.getLogger(__name__)
_cli_quiet = False

app = typer.Typer(
    name="techspecter",
    help=(
        "TechSpecter — passive web application analysis framework.\n\n"
        "Discover JavaScript, fingerprint technologies, analyze HTTP/metadata/artifacts, "
        "and export structured reports. Passive only — no exploitation or active scanning."
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="markdown",
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
        console.print(f"TechSpecter {version_display()}")
        raise typer.Exit()


def _build_cli_overrides(
    *,
    debug: bool,
    verbose: bool,
    quiet: bool = False,
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
    metadata_analysis: bool | None = None,
    well_known: bool = False,
    manifest: bool = False,
    robots: bool = False,
    sitemap: bool = False,
    security_txt: bool = False,
    html_meta: bool = False,
    framework_meta: bool = False,
    sourcemaps: bool = False,
    service_workers: bool = False,
    artifact_analysis: bool | None = None,
    cloud_analysis: bool = False,
    identity_analysis: bool = False,
    graphql: bool = False,
    openapi: bool = False,
    firebase: bool = False,
    oauth: bool = False,
    third_party: bool = False,
    analytics: bool = False,
    monitoring: bool = False,
    secret_analysis: bool = False,
    config_analysis: bool = False,
    build_analysis: bool = False,
    debug_analysis: bool = False,
    backup_analysis: bool = False,
    classification: bool = False,
    risk_summary: bool = False,
) -> dict[str, Any]:
    """Build CLI override mapping for the configuration manager."""
    overrides: dict[str, Any] = {}

    logging_override: dict[str, Any] = {}
    if quiet:
        logging_override["quiet"] = True
        logging_override["console"] = False
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

    metadata_override: dict[str, Any] = {}
    if metadata_analysis is not None:
        metadata_override["metadata_analysis"] = metadata_analysis
    if well_known:
        metadata_override["well_known"] = True
    if manifest:
        metadata_override["manifest"] = True
    if robots:
        metadata_override["robots"] = True
    if sitemap:
        metadata_override["sitemap"] = True
    if security_txt:
        metadata_override["security_txt"] = True
    if html_meta:
        metadata_override["html_meta"] = True
    if framework_meta:
        metadata_override["framework_meta"] = True
    if sourcemaps:
        metadata_override["sourcemaps"] = True
    if service_workers:
        metadata_override["service_workers"] = True

    metadata_specific = (
        well_known
        or manifest
        or robots
        or sitemap
        or security_txt
        or html_meta
        or framework_meta
        or sourcemaps
        or service_workers
    )
    if metadata_specific:
        metadata_enabled_ids: list[str] = []
        flag_map = {
            "well_known": well_known,
            "manifest": manifest,
            "robots": robots,
            "sitemap": sitemap,
            "security_txt": security_txt,
            "html_meta": html_meta,
            "framework_meta": framework_meta,
            "sourcemaps": sourcemaps,
            "service_workers": service_workers,
        }
        for flag_name, enabled in flag_map.items():
            if enabled:
                metadata_enabled_ids.extend(CLI_FLAG_METADATA_MAP[flag_name])
        analysis_override = overrides.setdefault("analysis", {})
        existing_enabled = analysis_override.get("enabled_analyzers", [])
        if existing_enabled:
            metadata_enabled_ids = list(dict.fromkeys([*existing_enabled, *metadata_enabled_ids]))
        analysis_override["enabled_analyzers"] = metadata_enabled_ids

    if metadata_override:
        overrides["metadata_analysis"] = metadata_override

    artifact_override: dict[str, Any] = {}
    if artifact_analysis is not None:
        artifact_override["artifact_analysis"] = artifact_analysis
    if cloud_analysis:
        artifact_override["cloud_analysis"] = True
    if identity_analysis:
        artifact_override["identity_analysis"] = True
    if graphql:
        artifact_override["graphql"] = True
    if openapi:
        artifact_override["openapi"] = True
    if firebase:
        artifact_override["firebase"] = True
    if oauth:
        artifact_override["oauth"] = True
    if third_party:
        artifact_override["third_party"] = True
    if analytics:
        artifact_override["analytics"] = True
    if monitoring:
        artifact_override["monitoring"] = True
    if secret_analysis:
        artifact_override["secret_analysis"] = True
    if config_analysis:
        artifact_override["config_analysis"] = True
    if build_analysis:
        artifact_override["build_analysis"] = True
    if debug_analysis:
        artifact_override["debug_analysis"] = True
    if backup_analysis:
        artifact_override["backup_analysis"] = True
    if classification:
        artifact_override["classification"] = True
    if risk_summary:
        artifact_override["risk_summary"] = True

    artifact_specific = (
        cloud_analysis
        or identity_analysis
        or graphql
        or openapi
        or firebase
        or oauth
        or third_party
        or analytics
        or monitoring
        or secret_analysis
        or config_analysis
        or build_analysis
        or debug_analysis
        or backup_analysis
        or classification
        or risk_summary
    )
    if artifact_specific:
        artifact_enabled_ids: list[str] = []
        flag_map = {
            "cloud_analysis": cloud_analysis,
            "identity_analysis": identity_analysis,
            "graphql": graphql,
            "openapi": openapi,
            "firebase": firebase,
            "oauth": oauth,
            "third_party": third_party,
            "analytics": analytics,
            "monitoring": monitoring,
            "secret_analysis": secret_analysis,
            "config_analysis": config_analysis,
            "build_analysis": build_analysis,
            "debug_analysis": debug_analysis,
            "backup_analysis": backup_analysis,
            "classification": classification,
            "risk_summary": risk_summary,
        }
        for flag_name, enabled in flag_map.items():
            if enabled:
                artifact_enabled_ids.extend(CLI_FLAG_ARTIFACT_MAP[flag_name])
        analysis_override = overrides.setdefault("analysis", {})
        existing_enabled = analysis_override.get("enabled_analyzers", [])
        if existing_enabled:
            artifact_enabled_ids = list(dict.fromkeys([*existing_enabled, *artifact_enabled_ids]))
        analysis_override["enabled_analyzers"] = artifact_enabled_ids

    if artifact_override:
        overrides["artifact_analysis"] = artifact_override

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
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress non-essential console output."),
    ] = False,
) -> None:
    """TechSpecter — passive web application analysis framework."""
    global _cli_quiet
    _cli_quiet = quiet
    manager = ConfigurationManager.load(
        config_path=config,
        cli_overrides=_build_cli_overrides(
            debug=debug,
            verbose=verbose,
            quiet=quiet,
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

    if result.asset_inventory is not None:
        from techspecter.asset_discovery.report import render_asset_inventory

        render_asset_inventory(result.asset_inventory, console=console)

    if result.sensitive_intelligence is not None:
        from techspecter.sensitive_intelligence.report import render_sensitive_intelligence

        render_sensitive_intelligence(result.sensitive_intelligence, console=console)


@app.command("sensitive-intelligence")
def sensitive_intelligence_command(
    url: Annotated[str, typer.Argument(help="Target website URL to analyze.")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output sensitive intelligence as JSON."),
    ] = False,
) -> None:
    """Analyze discovered assets for sensitive data and secrets."""
    try:
        pipeline = DiscoveryPipeline(
            DiscoveryPipelineConfig(
                collect_metadata=True,
                collect_asset_inventory=True,
                collect_sensitive_intelligence=True,
            ),
        )
        result = asyncio.run(pipeline.run(url))
    except ValidationError as exc:
        _handle_analysis_error(exc, label="Validation error", url=url)
    except TechSpecterError as exc:
        _handle_analysis_error(exc, label="Sensitive intelligence failed", url=url)

    report = result.sensitive_intelligence
    if report is None:
        console.print("[yellow]No sensitive intelligence report was produced.[/yellow]")
        raise typer.Exit(code=1)

    if json_output:
        payload = report.model_dump(mode="json")
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    console.print(f"\n[bold]Target:[/bold] {result.target.url}")
    console.print(f"[bold]Elapsed:[/bold] {result.elapsed_ms:.0f} ms")
    from techspecter.sensitive_intelligence.report import render_sensitive_intelligence

    render_sensitive_intelligence(report, console=console)


def inventory_command(
    url: Annotated[str, typer.Argument(help="Target website URL to inventory.")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output asset inventory as JSON."),
    ] = False,
    no_download: Annotated[
        bool,
        typer.Option("--no-download", help="Discover assets without downloading bodies."),
    ] = False,
) -> None:
    """Discover and inventory all publicly referenced website assets."""
    from techspecter.asset_discovery.pipeline import (
        AssetDiscoveryPipeline,
        AssetDiscoveryPipelineConfig,
    )
    from techspecter.asset_discovery.report import render_asset_inventory

    try:
        asset_pipeline = AssetDiscoveryPipeline(
            config=AssetDiscoveryPipelineConfig(download_assets=not no_download),
        )
        pipeline = DiscoveryPipeline(
            DiscoveryPipelineConfig(
                collect_metadata=True,
                collect_asset_inventory=True,
            ),
            asset_pipeline=asset_pipeline,
        )
        result = asyncio.run(pipeline.run(url))
    except ValidationError as exc:
        _handle_analysis_error(exc, label="Validation error", url=url)
    except TechSpecterError as exc:
        _handle_analysis_error(exc, label="Inventory failed", url=url)

    inventory = result.asset_inventory
    if inventory is None:
        console.print("[yellow]No asset inventory was produced.[/yellow]")
        raise typer.Exit(code=1)

    if json_output:
        payload = inventory.model_dump(mode="json")
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    console.print(f"\n[bold]Target:[/bold] {result.target.url}")
    console.print(f"[bold]Elapsed:[/bold] {result.elapsed_ms:.0f} ms")
    render_asset_inventory(inventory, console=console)


@app.command("doctor")
def doctor_command(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output diagnostics as JSON."),
    ] = False,
) -> None:
    """Run installation and environment diagnostics."""
    import platform
    import sys

    from techspecter.plugins.developer.diagnostics import environment_diagnostics
    from techspecter.plugins.manager import PluginManager

    if json_output:
        logging.disable(logging.INFO)

    manager = get_configuration_manager()
    env = environment_diagnostics()
    plugin_manager = PluginManager()
    plugin_manager.load_plugins(load_builtins=True)
    plugin_summary = plugin_manager.load_summary()
    plugin_manager.shutdown()

    if json_output:
        logging.disable(logging.NOTSET)

    payload: dict[str, object] = {
        "status": "ok",
        "version": __version__,
        "version_display": version_display(),
        "python_version": env.python_version,
        "platform": env.platform,
        "implementation": env.implementation,
        "configuration_loaded": True,
        "logging_level": manager.config.logging.level,
        "plugins_enabled": manager.config.plugins.enabled,
        "parallel_analyzers": manager.config.performance.parallel_analyzers,
        "cache_enabled": manager.config.performance.cache_enabled,
        "plugin_summary": plugin_summary,
        "executable": sys.executable,
        "platform_release": platform.release(),
    }

    if json_output:
        typer.echo(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    console.print("\n[bold]TechSpecter Doctor[/bold]\n")
    console.print(f"[bold]Version:[/bold] {version_display()} ({__version__})")
    console.print(f"[bold]Python:[/bold] {env.python_version}")
    console.print(f"[bold]Platform:[/bold] {env.platform} ({platform.release()})")
    console.print(f"[bold]Logging:[/bold] {manager.config.logging.level}")
    cache_state = "on" if manager.config.performance.cache_enabled else "off"
    parallel_state = "on" if manager.config.performance.parallel_analyzers else "off"
    console.print(f"[bold]Performance:[/bold] cache={cache_state}, parallel={parallel_state}")
    console.print(
        f"[bold]Plugins:[/bold] {plugin_summary.get('loaded_count', 0)} built-in plugins loaded"
    )
    console.print("\n[green]Diagnostics completed successfully.[/green]")


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
        _handle_analysis_error(exc, label="Validation error", url=url)
    except TechSpecterError as exc:
        _handle_analysis_error(exc, label="Discovery failed", url=url)

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
    debug_fingerprint: Annotated[
        bool,
        typer.Option(
            "--debug-fingerprint",
            help="Show fingerprint detection diagnostics (confirmed/rejected decisions).",
        ),
    ] = False,
    show_assets: Annotated[
        bool,
        typer.Option("--show-assets", help="Display the full asset inventory table."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            help="Enable verbose output (includes full asset inventory table).",
        ),
    ] = False,
    compare_wappalyzer: Annotated[
        bool,
        typer.Option(
            "--compare-wappalyzer",
            help="After fingerprinting, compare results against Wappalyzer (optional benchmark).",
        ),
    ] = False,
    wappalyzer_result: Annotated[
        Path | None,
        typer.Option(
            "--wappalyzer-result",
            help="Import an existing Wappalyzer JSON report for comparison.",
        ),
    ] = None,
    provider: Annotated[
        list[str] | None,
        typer.Option(
            "--provider",
            help="Enable specific detection providers (techspecter, wappalyzer, retirejs, all).",
        ),
    ] = None,
    disable_provider: Annotated[
        list[str] | None,
        typer.Option(
            "--disable-provider",
            help="Disable specific detection providers.",
        ),
    ] = None,
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
    if provider is None:
        provider = []
    if disable_provider is None:
        disable_provider = []
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
        unified_service = UnifiedDetectionService(providers_config=active_config.providers)
        result = asyncio.run(
            unified_service.analyze_url(
                url,
                selected_providers=provider or None,
                disabled_providers=disable_provider or None,
            ),
        )
    except ValidationError as exc:
        _handle_analysis_error(exc, label="Validation error", url=url)
    except TechSpecterError as exc:
        _handle_analysis_error(exc, label="Fingerprint analysis failed", url=url)

    if json_output:
        payload = _serialize_fingerprint_result(result)
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        if compare_wappalyzer:
            console.print("\n[bold]Running Wappalyzer comparison benchmark…[/bold]")
            run_benchmark(
                url,
                wappalyzer_result=wappalyzer_result,
                console=console,
                debug=active_config.logging.debug,
            )
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
            if compare_wappalyzer:
                console.print("\n[bold]Running Wappalyzer comparison benchmark…[/bold]")
                run_benchmark(
                    url,
                    wappalyzer_result=wappalyzer_result,
                    console=console,
                    debug=active_config.logging.debug,
                )
            return

        report = report_service.generate_report(
            result.detection,
            scan_duration_ms=result.elapsed_ms,
        )
    except ReportError as exc:
        console.print(f"[red]Report generation failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    from techspecter.reporting.fingerprint_report import render_fingerprint_report

    render_fingerprint_report(
        result,
        report,
        console=console,
        compact=compact,
        group_by_category=group_by_category,
        verbose=verbose_output or verbose,
        show_assets=show_assets or verbose,
        debug_fingerprint=debug_fingerprint,
    )

    if compare_wappalyzer:
        console.print("\n[bold]Running Wappalyzer comparison benchmark…[/bold]")
        run_benchmark(
            url,
            wappalyzer_result=wappalyzer_result,
            console=console,
            debug=active_config.logging.debug,
        )


@app.command("benchmark")
def benchmark_command(
    url: Annotated[str, typer.Argument(help="Target website URL to benchmark.")],
    wappalyzer_result: Annotated[
        Path | None,
        typer.Option(
            "--wappalyzer-result",
            help="Import an existing Wappalyzer JSON report instead of running CLI.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output benchmark report as JSON."),
    ] = False,
    report_format: Annotated[
        str | None,
        typer.Option("--format", help="Report format: json or markdown."),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", help="Write benchmark report to this file."),
    ] = None,
) -> None:
    """Compare TechSpecter fingerprint results against Wappalyzer."""
    manager = get_configuration_manager()
    run_benchmark(
        url,
        wappalyzer_result=wappalyzer_result,
        json_output=json_output,
        report_format=report_format,
        output=output,
        console=console,
        debug=manager.config.logging.debug,
    )


def _handle_analysis_error(exc: Exception, *, label: str, url: str) -> None:
    """Print a user-facing analysis error and exit."""
    debug_enabled = get_configuration_manager().config.logging.debug
    console.print(f"[red]{label}:[/red] {format_user_error(exc, debug=debug_enabled)}")
    if debug_enabled:
        logger.exception("%s failed for %s", label, url)
    raise typer.Exit(code=1) from exc


def _render_analysis_summary(
    result: AnalysisResult, *, title: str = "HTTP Analysis Findings"
) -> None:
    """Render a human-readable analysis summary."""
    if _cli_quiet:
        console.print(
            f"{result.target_url}: {result.statistics.total_findings} findings "
            f"({result.elapsed_ms:.0f} ms)"
        )
        return

    console.print(f"\n[bold]Target:[/bold] {result.target_url}")
    console.print(f"[bold]Elapsed:[/bold] {result.elapsed_ms:.0f} ms")
    if result.metadata.discovery_elapsed_ms:
        console.print(f"[bold]Discovery:[/bold] {result.metadata.discovery_elapsed_ms:.0f} ms")
    if result.metadata.analysis_elapsed_ms:
        console.print(f"[bold]Analysis:[/bold] {result.metadata.analysis_elapsed_ms:.0f} ms")
    timing = result.metadata.extra.get("timing", {})
    if isinstance(timing, dict):
        analyzer_timings = timing.get("analyzer_timings", {})
        if isinstance(analyzer_timings, dict) and analyzer_timings:
            slowest = max(analyzer_timings.items(), key=lambda item: float(item[1]))
            console.print(
                f"[bold]Slowest analyzer:[/bold] {slowest[0]} ({float(slowest[1]):.0f} ms)"
            )
    console.print(f"[bold]Findings:[/bold] {result.statistics.total_findings}")
    console.print(f"[bold]Analyzers:[/bold] {', '.join(result.metadata.analyzers)}\n")

    if not result.findings:
        console.print("[yellow]No findings detected.[/yellow]")
        return

    table = Table(title=title)
    table.add_column("Analyzer")
    table.add_column("Severity")
    table.add_column("Title", overflow="fold")
    for finding in result.findings[:50]:
        table.add_row(finding.analyzer, finding.severity.value, finding.title)
    console.print(table)
    if len(result.findings) > 50:
        console.print(f"[dim]... and {len(result.findings) - 50} more findings[/dim]")


def _export_or_display_analysis_report(
    result: AnalysisResult,
    *,
    report_format: OutputFormat | None,
    output: str | None,
    title: str = "HTTP Analysis Findings",
) -> None:
    """Export an analysis result to a file or render a console summary.

    Shared by analyze, metadata, and artifacts commands to avoid
    duplicating the report format / export path / error handling logic.
    """
    from techspecter.configuration.manager import get_configuration_manager

    active_config = get_configuration_manager().config
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

        _render_analysis_summary(result, title=title)
    except ReportError as exc:
        console.print(f"[red]Report generation failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc


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
        _handle_analysis_error(exc, label="Validation error", url=url)
    except TechSpecterError as exc:
        _handle_analysis_error(exc, label="HTTP analysis failed", url=url)

    if json_output:
        payload = result.model_dump(mode="json")
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    _export_or_display_analysis_report(
        result,
        report_format=report_format,
        output=output,
    )


def _run_metadata_analysis(
    url: str,
    *,
    json_output: bool,
    report_format: OutputFormat | None,
    output: str | None,
    metadata_analysis: bool,
    well_known: bool,
    manifest: bool,
    robots: bool,
    sitemap: bool,
    security_txt: bool,
    html_meta: bool,
    framework_meta: bool,
    sourcemaps: bool,
    service_workers: bool,
    disable_analyzer: list[str],
    enable_analyzer: list[str],
    config: Path | None,
) -> None:
    """Shared metadata analysis command implementation."""
    manager = get_configuration_manager()
    specific = (
        well_known
        or manifest
        or robots
        or sitemap
        or security_txt
        or html_meta
        or framework_meta
        or sourcemaps
        or service_workers
    )
    resolved_enable = enable_analyzer or ([] if specific else list(METADATA_ANALYZER_IDS))
    command_overrides = _build_cli_overrides(
        debug=False,
        verbose=False,
        min_confidence=None,
        disable_analyzer=disable_analyzer,
        enable_analyzer=resolved_enable,
        output=output,
        report_format=report_format,
        metadata_analysis=metadata_analysis,
        well_known=well_known,
        manifest=manifest,
        robots=robots,
        sitemap=sitemap,
        security_txt=security_txt,
        html_meta=html_meta,
        framework_meta=framework_meta,
        sourcemaps=sourcemaps,
        service_workers=service_workers,
    )
    if config is not None:
        manager = ConfigurationManager.load(config_path=config, cli_overrides=command_overrides)
        set_configuration_manager(manager)
    elif command_overrides:
        manager.apply_cli_overrides(command_overrides)

    active_config = manager.config
    if robots and not active_config.metadata_analysis.is_analyzer_enabled("robots-analyzer"):
        console.print("[yellow]Robots analyzer is disabled by configuration.[/yellow]")
        raise typer.Exit(code=1)

    try:
        service = AnalysisService()
        result = asyncio.run(service.analyze_url(url))
    except ValidationError as exc:
        _handle_analysis_error(exc, label="Validation error", url=url)
    except TechSpecterError as exc:
        _handle_analysis_error(exc, label="Metadata analysis failed", url=url)

    if json_output:
        payload = result.model_dump(mode="json")
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    _export_or_display_analysis_report(
        result,
        report_format=report_format,
        output=output,
        title="Metadata Analysis Findings",
    )


@app.command("metadata")
def metadata_command(
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
    metadata_analysis: Annotated[
        bool,
        typer.Option("--metadata-analysis", help="Enable metadata analysis analyzers."),
    ] = True,
    well_known: Annotated[
        bool,
        typer.Option("--well-known", help="Enable well-known resource analyzers."),
    ] = False,
    manifest: Annotated[
        bool,
        typer.Option("--manifest", help="Enable manifest analyzers."),
    ] = False,
    robots: Annotated[
        bool,
        typer.Option("--robots", help="Enable robots.txt analyzer."),
    ] = False,
    sitemap: Annotated[
        bool,
        typer.Option("--sitemap", help="Enable sitemap analyzer."),
    ] = False,
    security_txt: Annotated[
        bool,
        typer.Option("--security-txt", help="Enable security.txt analyzer."),
    ] = False,
    html_meta: Annotated[
        bool,
        typer.Option("--html-meta", help="Enable HTML metadata analyzers."),
    ] = False,
    framework_meta: Annotated[
        bool,
        typer.Option("--framework-meta", help="Enable framework metadata analyzer."),
    ] = False,
    sourcemaps: Annotated[
        bool,
        typer.Option("--sourcemaps", help="Enable SourceMap analyzer."),
    ] = False,
    service_workers: Annotated[
        bool,
        typer.Option("--service-workers", help="Enable service worker analyzer."),
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
    """Run passive metadata and well-known resource analysis."""
    _run_metadata_analysis(
        url,
        json_output=json_output,
        report_format=report_format,
        output=output,
        metadata_analysis=metadata_analysis,
        well_known=well_known,
        manifest=manifest,
        robots=robots,
        sitemap=sitemap,
        security_txt=security_txt,
        html_meta=html_meta,
        framework_meta=framework_meta,
        sourcemaps=sourcemaps,
        service_workers=service_workers,
        disable_analyzer=disable_analyzer or [],
        enable_analyzer=enable_analyzer or [],
        config=config,
    )


def _run_artifact_analysis(
    url: str,
    *,
    json_output: bool,
    report_format: OutputFormat | None,
    output: str | None,
    artifact_analysis: bool,
    cloud_analysis: bool,
    identity_analysis: bool,
    graphql: bool,
    openapi: bool,
    firebase: bool,
    oauth: bool,
    third_party: bool,
    analytics: bool,
    monitoring: bool,
    secret_analysis: bool,
    config_analysis: bool,
    build_analysis: bool,
    debug_analysis: bool,
    backup_analysis: bool,
    classification: bool,
    risk_summary: bool,
    disable_analyzer: list[str],
    enable_analyzer: list[str],
    config: Path | None,
    default_analyzer_ids: tuple[str, ...] | None = None,
) -> None:
    """Shared artifact analysis command implementation."""
    manager = get_configuration_manager()
    specific = (
        cloud_analysis
        or identity_analysis
        or graphql
        or openapi
        or firebase
        or oauth
        or third_party
        or analytics
        or monitoring
        or secret_analysis
        or config_analysis
        or build_analysis
        or debug_analysis
        or backup_analysis
        or classification
        or risk_summary
    )
    fallback_ids = default_analyzer_ids or ARTIFACT_ANALYZER_IDS
    resolved_enable = enable_analyzer or ([] if specific else list(fallback_ids))
    command_overrides = _build_cli_overrides(
        debug=False,
        verbose=False,
        min_confidence=None,
        disable_analyzer=disable_analyzer,
        enable_analyzer=resolved_enable,
        output=output,
        report_format=report_format,
        artifact_analysis=artifact_analysis,
        cloud_analysis=cloud_analysis,
        identity_analysis=identity_analysis,
        graphql=graphql,
        openapi=openapi,
        firebase=firebase,
        oauth=oauth,
        third_party=third_party,
        analytics=analytics,
        monitoring=monitoring,
        secret_analysis=secret_analysis,
        config_analysis=config_analysis,
        build_analysis=build_analysis,
        debug_analysis=debug_analysis,
        backup_analysis=backup_analysis,
        classification=classification,
        risk_summary=risk_summary,
    )
    if config is not None:
        manager = ConfigurationManager.load(config_path=config, cli_overrides=command_overrides)
        set_configuration_manager(manager)
    elif command_overrides:
        manager.apply_cli_overrides(command_overrides)

    active_config = manager.config
    if graphql and not active_config.artifact_analysis.is_analyzer_enabled(
        "graphql-metadata-analyzer"
    ):
        console.print("[yellow]GraphQL analyzer is disabled by configuration.[/yellow]")
        raise typer.Exit(code=1)

    try:
        service = AnalysisService()
        result = asyncio.run(service.analyze_url(url))
    except ValidationError as exc:
        _handle_analysis_error(exc, label="Validation error", url=url)
    except TechSpecterError as exc:
        _handle_analysis_error(exc, label="Artifact analysis failed", url=url)

    if json_output:
        payload = result.model_dump(mode="json")
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    _export_or_display_analysis_report(
        result,
        report_format=report_format,
        output=output,
        title="Artifact Analysis Findings",
    )


@app.command("artifacts")
def artifacts_command(
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
    artifact_analysis: Annotated[
        bool,
        typer.Option("--artifact-analysis", help="Enable artifact analysis analyzers."),
    ] = True,
    cloud_analysis: Annotated[
        bool,
        typer.Option("--cloud-analysis", help="Enable cloud service analyzers."),
    ] = False,
    identity_analysis: Annotated[
        bool,
        typer.Option("--identity-analysis", help="Enable identity analyzers."),
    ] = False,
    graphql: Annotated[
        bool,
        typer.Option("--graphql", help="Enable GraphQL metadata analyzer."),
    ] = False,
    openapi: Annotated[
        bool,
        typer.Option("--openapi", help="Enable OpenAPI analyzer."),
    ] = False,
    firebase: Annotated[
        bool,
        typer.Option("--firebase", help="Enable Firebase analyzer."),
    ] = False,
    oauth: Annotated[
        bool,
        typer.Option("--oauth", help="Enable OAuth/OIDC analyzers."),
    ] = False,
    third_party: Annotated[
        bool,
        typer.Option("--third-party", help="Enable third-party service analyzer."),
    ] = False,
    analytics: Annotated[
        bool,
        typer.Option("--analytics", help="Enable analytics service analyzer."),
    ] = False,
    monitoring: Annotated[
        bool,
        typer.Option("--monitoring", help="Enable monitoring service analyzer."),
    ] = False,
    secret_analysis: Annotated[
        bool,
        typer.Option("--secret-analysis", help="Enable secret pattern analyzer."),
    ] = False,
    config_analysis: Annotated[
        bool,
        typer.Option("--config-analysis", help="Enable configuration artifact analyzers."),
    ] = False,
    build_analysis: Annotated[
        bool,
        typer.Option("--build-analysis", help="Enable build artifact analyzer."),
    ] = False,
    debug_analysis: Annotated[
        bool,
        typer.Option("--debug-analysis", help="Enable debug artifact analyzer."),
    ] = False,
    backup_analysis: Annotated[
        bool,
        typer.Option("--backup-analysis", help="Enable backup artifact analyzer."),
    ] = False,
    classification: Annotated[
        bool,
        typer.Option("--classification", help="Enable exposure classification analyzer."),
    ] = False,
    risk_summary: Annotated[
        bool,
        typer.Option("--risk-summary", help="Enable risk classification analyzer."),
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
    """Run passive cloud, identity, and API artifact analysis."""
    _run_artifact_analysis(
        url,
        json_output=json_output,
        report_format=report_format,
        output=output,
        artifact_analysis=artifact_analysis,
        cloud_analysis=cloud_analysis,
        identity_analysis=identity_analysis,
        graphql=graphql,
        openapi=openapi,
        firebase=firebase,
        oauth=oauth,
        third_party=third_party,
        analytics=analytics,
        monitoring=monitoring,
        secret_analysis=secret_analysis,
        config_analysis=config_analysis,
        build_analysis=build_analysis,
        debug_analysis=debug_analysis,
        backup_analysis=backup_analysis,
        classification=classification,
        risk_summary=risk_summary,
        disable_analyzer=disable_analyzer or [],
        enable_analyzer=enable_analyzer or [],
        config=config,
    )


@app.command("sensitive")
def sensitive_command(
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
    secret_analysis: Annotated[
        bool,
        typer.Option("--secret-analysis", help="Enable secret pattern analyzer."),
    ] = True,
    config_analysis: Annotated[
        bool,
        typer.Option("--config-analysis", help="Enable configuration artifact analyzers."),
    ] = False,
    build_analysis: Annotated[
        bool,
        typer.Option("--build-analysis", help="Enable build artifact analyzer."),
    ] = False,
    debug_analysis: Annotated[
        bool,
        typer.Option("--debug-analysis", help="Enable debug artifact analyzer."),
    ] = False,
    backup_analysis: Annotated[
        bool,
        typer.Option("--backup-analysis", help="Enable backup artifact analyzer."),
    ] = False,
    classification: Annotated[
        bool,
        typer.Option("--classification", help="Enable exposure classification analyzer."),
    ] = False,
    risk_summary: Annotated[
        bool,
        typer.Option("--risk-summary", help="Enable risk classification analyzer."),
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
    """Run passive secret, configuration, and build artifact analysis."""
    _run_artifact_analysis(
        url,
        json_output=json_output,
        report_format=report_format,
        output=output,
        artifact_analysis=True,
        cloud_analysis=False,
        identity_analysis=False,
        graphql=False,
        openapi=False,
        firebase=False,
        oauth=False,
        third_party=False,
        analytics=False,
        monitoring=False,
        secret_analysis=secret_analysis,
        config_analysis=config_analysis,
        build_analysis=build_analysis,
        debug_analysis=debug_analysis,
        backup_analysis=backup_analysis,
        classification=classification,
        risk_summary=risk_summary,
        disable_analyzer=disable_analyzer or [],
        enable_analyzer=enable_analyzer or [],
        config=config,
        default_analyzer_ids=SENSITIVE_ARTIFACT_ANALYZER_IDS,
    )


def main() -> None:
    """Console script entry point for the ``techspecter`` command."""
    app()


if __name__ == "__main__":
    main()
