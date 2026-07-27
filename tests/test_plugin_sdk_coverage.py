"""Additional tests for plugin SDK coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from techspecter.cli import app
from techspecter.core.context import ScanContext
from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.core.interfaces import PluginMetadata as CorePluginMetadata
from techspecter.core.interfaces import ScanResult
from techspecter.plugins.config import PluginConfiguration
from techspecter.plugins.discovery import discover_package_modules, extract_plugin_from_module
from techspecter.plugins.exceptions import PluginValidationError
from techspecter.plugins.interfaces import AnalyzerPlugin, ExporterPlugin
from techspecter.plugins.lifecycle import PluginLifecycle
from techspecter.plugins.loader import PluginLoader, _iter_entry_points
from techspecter.plugins.manager import PluginManager
from techspecter.plugins.metadata import PluginMetadata, PluginType
from techspecter.plugins.registry import PluginRegistry
from techspecter.plugins.validator import PluginValidator
from tests.plugin_fixtures import RecordingLifecyclePlugin, sample_metadata, write_directory_plugin


class _LegacyStub(LegacyPlugin):
    @property
    def metadata(self) -> CorePluginMetadata:
        return CorePluginMetadata(
            name="legacy",
            version="1.0.0",
            description="Legacy plugin",
        )

    def execute(self, context: ScanContext) -> ScanResult:
        return ScanResult(plugin_name="legacy", findings={})


def test_registry_rejects_invalid_plugin() -> None:
    """Verify registry rejects plugins that fail validation."""
    reg = PluginRegistry()
    plugin = RecordingLifecyclePlugin(sample_metadata(minimum_core_version="99.0.0"))
    with pytest.raises(ValueError, match="core version"):
        reg.register(plugin)


def test_validator_validate_or_raise() -> None:
    """Verify validate_or_raise raises PluginValidationError."""
    plugin = RecordingLifecyclePlugin(sample_metadata(minimum_core_version="99.0.0"))
    with pytest.raises(PluginValidationError):
        PluginValidator(core_version="0.5.0").validate_or_raise(plugin)


def test_validator_legacy_empty_name() -> None:
    """Verify legacy plugins with empty names fail validation."""

    class BrokenLegacy(_LegacyStub):
        @property
        def metadata(self) -> CorePluginMetadata:
            return CorePluginMetadata(name="", version="1.0.0", description="x")

    report = PluginValidator().validate(BrokenLegacy())
    assert not report.is_valid


def test_loader_load_all_and_builtins() -> None:
    """Verify load_all aggregates sources and builtins can be requested."""
    loader = PluginLoader(plugin_directories=[], load_entry_points=False, load_builtins=True)
    loaded = loader.load_all()
    assert len(loaded) == 61
    assert len(loader.load_builtin_plugins()) == 61


def test_loader_package_with_plugin_attribute() -> None:
    """Verify package-level plugin exports are loaded."""
    plugin = RecordingLifecyclePlugin()
    package = MagicMock()
    package.__path__ = None
    package.plugin = plugin
    loader = PluginLoader(plugin_directories=[], load_entry_points=False)
    with patch("techspecter.plugins.loader.importlib.import_module", return_value=package):
        loaded = loader._load_plugins_from_package("fake.package")
    assert loaded == [plugin]


def test_iter_entry_points_legacy_api() -> None:
    """Verify legacy entry_points API is supported."""
    entry = MagicMock()
    legacy = MagicMock()
    legacy.get.return_value = [entry]

    def entry_points_side_effect(*args: object, **kwargs: object) -> object:
        if kwargs or args:
            raise TypeError("new API unavailable")
        return legacy

    with patch("techspecter.plugins.loader.entry_points", side_effect=entry_points_side_effect):
        result = _iter_entry_points("techspecter.plugins")
    assert result == [entry]


def test_extract_plugin_from_create_plugin_factory() -> None:
    """Verify create_plugin() factories are supported."""
    plugin = RecordingLifecyclePlugin()

    class Module:
        @staticmethod
        def create_plugin() -> RecordingLifecyclePlugin:
            return plugin

    assert extract_plugin_from_module(Module()) is plugin


def test_discover_package_modules_missing_package() -> None:
    """Verify missing packages return an empty module list."""
    assert discover_package_modules("techspecter.plugins.does_not_exist") == []


def test_manager_collect_contributions() -> None:
    """Verify manager collects analyzers, exporters, reporters, and rule dirs."""
    from techspecter.analysis.analyzers.base import Analyzer, AnalyzerMetadata
    from techspecter.analysis.results.analysis_result import AnalyzerResult
    from techspecter.models.discovery import DiscoveryResult
    from techspecter.plugins.interfaces import ReporterPlugin, RulePackPlugin
    from techspecter.reporting.engine import ReportEngine
    from techspecter.reporting.exporters.base import BaseExporter
    from techspecter.reporting.models import Report, ReportFormat

    class _Analyzer(Analyzer):
        @property
        def metadata(self) -> AnalyzerMetadata:
            return AnalyzerMetadata(
                id="a1",
                name="A1",
                version="1.0.0",
                description="d",
                category="information",
            )

        def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
            return AnalyzerResult(analyzer_id="a1", findings=[])

    class _Exporter(BaseExporter):
        format: ReportFormat = "json"

        def export(self, report: Report) -> str:
            return "{}"

    class _Bundle(AnalyzerPlugin, ReporterPlugin, ExporterPlugin, RulePackPlugin):
        @property
        def plugin_metadata(self) -> PluginMetadata:
            return sample_metadata(id="bundle", plugin_type=PluginType.ANALYZER)

        def analyzers(self):
            return [_Analyzer()]

        def report_engines(self):
            return {"r1": ReportEngine(tool_name="R1")}

        def exporters(self):
            return {"json": _Exporter()}

        def rule_directories(self):
            return [Path("/rules")]

    manager = PluginManager()
    manager.registry.register(_Bundle())
    assert len(manager.collect_analyzers()) == 1
    assert "r1" in manager.collect_report_engines()
    assert "json" in manager.collect_exporters()
    assert manager.collect_rule_directories() == [Path("/rules")]
    manager.shutdown()


def test_manager_shutdown_legacy_plugin() -> None:
    """Verify manager shutdown handles legacy plugins."""
    manager = PluginManager()
    manager.registry.register(_LegacyStub())
    manager._contexts["legacy"] = manager._build_context(_LegacyStub())
    manager.shutdown()


def test_lifecycle_enable_disable() -> None:
    """Verify enable and disable lifecycle hooks."""
    plugin = RecordingLifecyclePlugin()
    lifecycle = PluginLifecycle()
    context = manager_context(plugin)
    lifecycle.enable_plugin(plugin, context)
    assert plugin.is_enabled
    lifecycle.disable_plugin(plugin, context)
    assert not plugin.is_enabled


def manager_context(plugin: RecordingLifecyclePlugin):
    from techspecter.plugins.context import (
        PluginContext,
        PluginLogger,
        PluginResources,
        PluginSettings,
    )

    return PluginContext(
        metadata=plugin.plugin_metadata,
        settings=PluginSettings(),
        resources=PluginResources(),
        logger=PluginLogger(plugin.plugin_metadata.id),
    )


def test_plugins_show_loaded_plugin(tmp_path: Path) -> None:
    """Verify show displays metadata for a loaded plugin."""
    write_directory_plugin(tmp_path, plugin_id="show-plugin")
    config_yaml = tmp_path / "config.yaml"
    config_yaml.write_text(
        f"plugins:\n  directories:\n    - {tmp_path.as_posix()}\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--config", str(config_yaml), "plugins", "show", "show-plugin", "--load"],
    )
    assert result.exit_code == 0
    assert "show-plugin" in result.stdout
    assert "Directory Plugin" in result.stdout


def test_plugins_validate_no_candidates() -> None:
    """Verify validate exits cleanly when no plugins are discovered."""
    runner = CliRunner()
    result = runner.invoke(app, ["plugins", "validate", "--directory", "/nonexistent/path"])
    assert result.exit_code == 0
    assert "No plugins discovered" in result.stdout


def test_plugins_show_legacy_plugin() -> None:
    """Verify show displays legacy plugin metadata."""
    manager = PluginManager()
    manager.registry.register(_LegacyStub())
    runner = CliRunner()
    with patch("techspecter.plugins.cli._build_manager", return_value=manager):
        result = runner.invoke(app, ["plugins", "show", "legacy"])
    assert result.exit_code == 0
    assert "legacy" in result.stdout
    assert "Type: legacy" in result.stdout


def test_plugin_execute_methods() -> None:
    """Verify typed plugin execute methods return resource summaries."""
    from techspecter.core.context import ScanContext
    from techspecter.plugins.interfaces import ReporterPlugin, RulePackPlugin
    from techspecter.reporting.engine import ReportEngine

    class _Reporter(ReporterPlugin):
        @property
        def plugin_metadata(self) -> PluginMetadata:
            return sample_metadata(id="rep", plugin_type=PluginType.REPORTER)

        def report_engines(self):
            return {"engine": ReportEngine(tool_name="Engine")}

    class _Rules(RulePackPlugin):
        @property
        def plugin_metadata(self) -> PluginMetadata:
            return sample_metadata(id="rules", plugin_type=PluginType.RULE_PACK)

        def rule_directories(self):
            return [Path("/tmp")]

    context = ScanContext(target_url="https://example.com")
    assert "reporters" in _Reporter().execute(context).findings
    assert "rule_directories" in _Rules().execute(context).findings


def test_manager_skips_invalid_and_duplicate(tmp_path: Path) -> None:
    """Verify manager skips invalid plugins and duplicates."""
    write_directory_plugin(tmp_path, plugin_id="dup-plugin")
    invalid = RecordingLifecyclePlugin(sample_metadata(id="bad", minimum_core_version="99.0.0"))
    loader = MagicMock()
    loader.load_all.return_value = [
        invalid,
        RecordingLifecyclePlugin(sample_metadata(id="dup-plugin")),
        RecordingLifecyclePlugin(sample_metadata(id="dup-plugin")),
    ]
    manager = PluginManager(
        configuration=PluginConfiguration(plugin_directories=[str(tmp_path)]),
    )
    with patch("techspecter.plugins.manager.PluginLoader", return_value=loader):
        loaded = manager.load_plugins(load_entry_points=False)
    assert loaded == ["dup-plugin"]


def test_discovery_import_and_extract_edge_cases(tmp_path: Path) -> None:
    """Verify discovery handles missing files and invalid modules."""
    from techspecter.plugins.discovery import (
        discover_modules_in_directory,
        import_module_from_directory,
    )

    assert discover_modules_in_directory(tmp_path / "missing") == []
    assert import_module_from_directory(tmp_path, "missing") is None

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "_private.py").write_text("x = 1\n", encoding="utf-8")
    assert discover_modules_in_directory(plugin_dir) == []

    broken = plugin_dir / "broken.py"
    broken.write_text("raise RuntimeError('fail')\n", encoding="utf-8")
    assert import_module_from_directory(plugin_dir, "broken") is None


def test_registry_unregister_missing_raises() -> None:
    """Verify unregister raises for unknown plugins."""
    from techspecter.exceptions import PluginNotFoundError

    reg = PluginRegistry()
    with pytest.raises(PluginNotFoundError):
        reg.unregister("missing")


def test_plugin_configuration_enabled_plugins_whitelist() -> None:
    """Verify PluginConfiguration enabled_plugins whitelist."""
    from techspecter.plugins.config import PluginConfiguration

    config = PluginConfiguration(enabled_plugins=["allowed"])
    assert config.is_plugin_enabled("allowed")
    assert not config.is_plugin_enabled("blocked")


def test_loader_walk_packages(tmp_path: Path) -> None:
    """Verify loader imports submodules from namespace packages."""
    write_directory_plugin(tmp_path, plugin_id="walk-plugin")
    loader = PluginLoader(plugin_directories=[tmp_path], load_entry_points=False)
    loaded = loader.load_directory_plugins()
    assert len(loaded) == 1


def test_validator_warnings_and_plugin_type_checks() -> None:
    """Verify validator warnings and plugin type interface checks."""
    from techspecter.plugins.interfaces import ExporterPlugin
    from techspecter.reporting.exporters.base import BaseExporter
    from techspecter.reporting.models import Report, ReportFormat

    class _BadType(ExporterPlugin):
        @property
        def plugin_metadata(self) -> PluginMetadata:
            return sample_metadata(
                id="Bad ID",
                plugin_type=PluginType.EXPORTER,
                dependencies=["missing-dep"],
            )

        def exporters(self):
            return {}

    class _Exporter(BaseExporter):
        format: ReportFormat = "json"

        def export(self, report: Report) -> str:
            return "{}"

    report = PluginValidator().validate(
        _BadType(),
        available_ids={"Bad ID"},
    )
    assert not report.is_valid
    assert any("dependencies" in error for error in report.errors)

    valid = PluginValidator().validate(
        RecordingLifecyclePlugin(sample_metadata(id="Bad ID")),
    )
    assert valid.is_valid
    assert any("kebab-case" in warning for warning in valid.warnings)


def test_loader_import_submodule_failure() -> None:
    """Verify loader continues when submodule import fails."""
    loader = PluginLoader(plugin_directories=[], load_entry_points=False)
    module_info = MagicMock()
    module_info.ispkg = False
    module_info.name = "techspecter.plugins.builtin.broken"

    def import_side_effect(name: str) -> object:
        if name == "techspecter.plugins.builtin":
            package = MagicMock()
            package.__path__ = ["/fake"]
            return package
        raise ImportError("broken submodule")

    with (
        patch("pkgutil.walk_packages", return_value=[module_info]),
        patch(
            "techspecter.plugins.loader.importlib.import_module",
            side_effect=import_side_effect,
        ),
    ):
        loaded = loader._load_plugins_from_package("techspecter.plugins.builtin")
    assert loaded == []


def test_plugin_logger_methods() -> None:
    """Verify plugin logger methods delegate to logging."""
    from techspecter.plugins.context import PluginLogger

    logger = PluginLogger("test-plugin")
    logger.debug("debug %s", "msg")
    logger.info("info %s", "msg")
    logger.warning("warn %s", "msg")
    logger.error("error %s", "msg")
