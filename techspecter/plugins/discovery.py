"""Plugin discovery utilities."""

from __future__ import annotations

import importlib
import importlib.util
import logging
from pathlib import Path
from typing import cast

logger = logging.getLogger(__name__)


def discover_modules_in_directory(directory: Path) -> list[str]:
    """Discover importable plugin module names in a directory."""
    if not directory.is_dir():
        return []

    modules: list[str] = []
    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_"):
            continue
        modules.append(path.stem)
    return modules


def discover_package_modules(package_name: str) -> list[str]:
    """Discover importable submodules in a namespace package."""
    from pkgutil import walk_packages

    try:
        package = importlib.import_module(package_name)
    except ImportError:
        return []

    plugin_paths = getattr(package, "__path__", None)
    if plugin_paths is None:
        return []

    return [
        module_info.name
        for module_info in walk_packages(plugin_paths, prefix=f"{package_name}.")
        if not module_info.ispkg
    ]


def import_module_from_directory(directory: Path, module_name: str) -> object | None:
    """Import a module from a directory using a temporary path entry."""
    file_path = directory / f"{module_name}.py"
    if not file_path.is_file():
        return None

    spec_name = f"techspecter_external_plugins.{module_name}"
    spec = importlib.util.spec_from_file_location(spec_name, file_path)
    if spec is None or spec.loader is None:
        return None

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        logger.warning("Failed to import plugin module '%s': %s", module_name, exc)
        return None
    return module


def extract_plugin_from_module(module: object) -> object | None:
    """Return a plugin instance exported by a module."""
    plugin = getattr(module, "plugin", None)
    if plugin is not None:
        return cast(object | None, plugin)

    create_plugin = getattr(module, "create_plugin", None)
    if callable(create_plugin):
        return cast(object | None, create_plugin())
    return None
