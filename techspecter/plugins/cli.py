"""Plugin CLI commands."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from techspecter import __version__
from techspecter.configuration.manager import get_configuration_manager
from techspecter.plugins.config import PluginConfiguration
from techspecter.plugins.developer.diagnostics import diagnose_plugins, environment_diagnostics
from techspecter.plugins.loader import PluginLoader
from techspecter.plugins.manager import PluginManager
from techspecter.plugins.metadata import PluginMetadata
from techspecter.plugins.registry import plugin_id
from techspecter.plugins.validator import PluginValidator

console = Console()
logger = logging.getLogger(__name__)

plugins_app = typer.Typer(
    name="plugins",
    help="Inspect and validate TechSpecter plugins.",
    no_args_is_help=True,
)


def _build_manager(*, load: bool = False) -> PluginManager:
    """Build a plugin manager from active configuration."""
    config = get_configuration_manager().config
    plugin_config = PluginConfiguration.from_plugins_config(config.plugins)
    manager = PluginManager(configuration=plugin_config)
    if load:
        manager.load_plugins(load_builtins=False)
    return manager


@plugins_app.command("list")
def list_plugins(
    load: Annotated[
        bool,
        typer.Option("--load", help="Load plugins before listing."),
    ] = False,
) -> None:
    """List registered or loadable plugins."""
    manager = _build_manager(load=load)
    if load:
        loaded = manager.load_plugins(load_builtins=False)
        console.print(f"[green]Loaded {len(loaded)} plugin(s).[/green]")

    identifiers = manager.registry.list()
    if not identifiers:
        console.print("[yellow]No plugins registered.[/yellow]")
        if not load:
            console.print("Use [bold]--load[/bold] to discover plugins from configured sources.")
        return

    table = Table(title="TechSpecter Plugins")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Type")
    for identifier in identifiers:
        metadata = manager.registry.metadata_view()[identifier]
        if isinstance(metadata, PluginMetadata):
            table.add_row(
                identifier,
                metadata.name,
                metadata.version,
                metadata.plugin_type.value,
            )
        else:
            table.add_row(identifier, metadata.name, metadata.version, "legacy")
    console.print(table)


@plugins_app.command("show")
def show_plugin(
    plugin_name: Annotated[str, typer.Argument(help="Plugin identifier.")],
    load: Annotated[
        bool,
        typer.Option("--load", help="Load plugins before showing details."),
    ] = False,
) -> None:
    """Show metadata for a plugin."""
    manager = _build_manager(load=load)
    if load:
        manager.load_plugins(load_builtins=False)

    plugin = manager.registry.find(plugin_name)
    if plugin is None:
        console.print(f"[red]Plugin '{plugin_name}' not found.[/red]")
        raise typer.Exit(code=1)

    metadata = manager.registry.metadata_view()[plugin_name]
    console.print(f"[bold]ID:[/bold] {plugin_name}")
    if isinstance(metadata, PluginMetadata):
        console.print(f"[bold]Name:[/bold] {metadata.name}")
        console.print(f"[bold]Version:[/bold] {metadata.version}")
        console.print(f"[bold]Description:[/bold] {metadata.description}")
        console.print(f"[bold]Type:[/bold] {metadata.plugin_type.value}")
        console.print(f"[bold]Author:[/bold] {metadata.author or '-'}")
        console.print(f"[bold]Homepage:[/bold] {metadata.homepage or '-'}")
        console.print(f"[bold]License:[/bold] {metadata.license or '-'}")
        console.print(f"[bold]Minimum core:[/bold] {metadata.minimum_core_version}")
        console.print(f"[bold]Minimum Python:[/bold] {metadata.minimum_python_version}")
        if metadata.dependencies:
            console.print(f"[bold]Dependencies:[/bold] {', '.join(metadata.dependencies)}")
        if metadata.tags:
            console.print(f"[bold]Tags:[/bold] {', '.join(metadata.tags)}")
    else:
        console.print(f"[bold]Name:[/bold] {metadata.name}")
        console.print(f"[bold]Version:[/bold] {metadata.version}")
        console.print(f"[bold]Description:[/bold] {metadata.description}")
        console.print(f"[bold]Author:[/bold] {metadata.author or '-'}")
        console.print("[bold]Type:[/bold] legacy")


@plugins_app.command("validate")
def validate_plugins(
    directory: (
        Annotated[
            list[Path],
            typer.Option("--directory", "-d", help="Additional plugin directory to validate."),
        ]
        | None
    ) = None,
) -> None:
    """Validate plugins from configured sources."""
    config = get_configuration_manager().config
    plugin_config = PluginConfiguration.from_plugins_config(config.plugins)
    directories = list(plugin_config.plugin_directories)
    if directory:
        directories.extend(str(path) for path in directory)

    loader = PluginLoader(
        plugin_directories=directories,
        load_entry_points=plugin_config.load_entry_points,
        load_builtins=False,
    )
    candidates = loader.load_all()
    validator = PluginValidator()
    available_ids = {plugin_id(item) for item in candidates}

    if not candidates:
        console.print("[yellow]No plugins discovered for validation.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title="Plugin Validation")
    table.add_column("ID")
    table.add_column("Status")
    table.add_column("Details")

    invalid_count = 0
    for candidate in candidates:
        identifier = plugin_id(candidate)
        report = validator.validate(
            candidate,
            available_ids=available_ids - {identifier},
        )
        if report.is_valid:
            status = "[green]valid[/green]"
            details = "; ".join(report.warnings) if report.warnings else "-"
        else:
            status = "[red]invalid[/red]"
            details = "; ".join(report.errors)
            invalid_count += 1
        table.add_row(identifier, status, details)

    console.print(table)
    if invalid_count:
        raise typer.Exit(code=1)


@plugins_app.command("doctor")
def doctor_plugins(
    load: Annotated[
        bool,
        typer.Option("--load", help="Load plugins before running diagnostics."),
    ] = False,
) -> None:
    """Run plugin environment and registry diagnostics."""
    config = get_configuration_manager().config
    plugin_config = PluginConfiguration.from_plugins_config(config.plugins)
    manager = PluginManager(configuration=plugin_config)
    if load:
        manager.load_plugins(load_builtins=False)

    report = diagnose_plugins(manager=manager, configuration=plugin_config)
    env = report.environment
    console.print("[bold]TechSpecter Plugin Doctor[/bold]")
    console.print(f"TechSpecter: {env.techspecter_version}")
    console.print(f"Python: {env.python_version} ({env.implementation})")
    console.print(f"Platform: {env.platform}")
    console.print(f"Registered plugins: {len(report.registry.registered_plugins)}")

    if report.warnings:
        console.print("\n[yellow]Warnings[/yellow]")
        for warning in report.warnings:
            console.print(f"- {warning}")

    if report.issues:
        console.print("\n[red]Issues[/red]")
        for issue in report.issues:
            console.print(f"- {issue}")
        raise typer.Exit(code=1)

    console.print("\n[green]No plugin issues detected.[/green]")


@plugins_app.command("info")
def plugin_info() -> None:
    """Show plugin SDK and runtime information."""
    env = environment_diagnostics()
    config = get_configuration_manager().config.plugins
    console.print("[bold]TechSpecter Plugin SDK[/bold]")
    console.print(f"TechSpecter version: {__version__}")
    console.print(f"Python version: {env.python_version}")
    console.print(f"Platform: {env.platform}")
    console.print(f"Plugin system enabled: {config.enabled}")
    console.print(f"Plugin directories: {', '.join(config.directories) or '-'}")
    console.print(f"Entry points enabled: {config.load_entry_points}")
    console.print("SDK import path: techspecter.plugins.developer")
    console.print("Entry point group: techspecter.plugins")
