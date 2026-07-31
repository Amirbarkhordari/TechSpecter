"""JavaScript resource classification."""

from __future__ import annotations

import re

from techspecter.javascript.classification.bundler import detect_bundler
from techspecter.javascript.models import (
    BundleClassification,
    BundlerType,
    DiscoverySource,
    JavaScriptResourceKind,
    ModuleType,
)

_VENDOR_PATTERN = re.compile(r"(?i)(?:vendor|vendors|lib(?:rary)?|node_modules|framework)")
_RUNTIME_PATTERN = re.compile(r"(?i)(?:runtime|webpack-runtime|vite/runtime|turbopack/runtime)")
_ENTRY_PATTERN = re.compile(r"(?i)(?:main|index|app|entry|bootstrap|start)")
_CHUNK_PATTERN = re.compile(r"(?i)(?:chunk|lazy|async|dynamic|split)")
_FRAMEWORK_PATTERN = re.compile(
    r"(?i)(?:react|vue|angular|svelte|next|nuxt|solid|ember|preact)",
)
_WORKER_PATTERN = re.compile(r"(?i)(?:worker|sw\.js|service-worker|serviceworker)")


def classify_resource(
    *,
    filename: str,
    content: str,
    module_type: ModuleType = ModuleType.UNKNOWN,
    discovery_sources: list[DiscoverySource] | None = None,
    is_entry: bool = False,
) -> tuple[JavaScriptResourceKind, BundleClassification, BundlerType]:
    """Classify a JavaScript resource by filename, content, and discovery context."""
    sources = discovery_sources or []
    bundler = detect_bundler(content=content, filename=filename)
    lowered = filename.lower()

    if module_type == ModuleType.SERVICE_WORKER or DiscoverySource.SERVICE_WORKER in sources:
        return JavaScriptResourceKind.SERVICE_WORKER, BundleClassification.WORKER, bundler
    if module_type == ModuleType.SHARED_WORKER or DiscoverySource.SHARED_WORKER in sources:
        return JavaScriptResourceKind.SHARED_WORKER, BundleClassification.WORKER, bundler
    if module_type == ModuleType.WORKER or DiscoverySource.WORKER in sources:
        return JavaScriptResourceKind.WORKER, BundleClassification.WORKER, bundler
    if _WORKER_PATTERN.search(lowered):
        return JavaScriptResourceKind.WORKER, BundleClassification.WORKER, bundler

    if module_type == ModuleType.MODULE:
        kind = JavaScriptResourceKind.MODULE
        bundle_class = BundleClassification.UNKNOWN
    elif is_entry or _ENTRY_PATTERN.search(lowered):
        kind = JavaScriptResourceKind.ENTRY_BUNDLE
        bundle_class = BundleClassification.ENTRY
    elif (
        _RUNTIME_PATTERN.search(lowered) or bundler != BundlerType.UNKNOWN and "runtime" in lowered
    ):
        kind = JavaScriptResourceKind.RUNTIME_BUNDLE
        bundle_class = BundleClassification.RUNTIME
    elif _VENDOR_PATTERN.search(lowered):
        kind = JavaScriptResourceKind.VENDOR_BUNDLE
        bundle_class = BundleClassification.VENDOR
    elif _FRAMEWORK_PATTERN.search(lowered):
        kind = JavaScriptResourceKind.FRAMEWORK_BUNDLE
        bundle_class = BundleClassification.FRAMEWORK
    elif _CHUNK_PATTERN.search(lowered) or DiscoverySource.DYNAMIC_IMPORT in sources:
        if DiscoverySource.DYNAMIC_IMPORT in sources or "lazy" in lowered:
            kind = JavaScriptResourceKind.LAZY_CHUNK
        else:
            kind = JavaScriptResourceKind.DYNAMIC_CHUNK
        bundle_class = BundleClassification.CHUNK
    elif DiscoverySource.HTML_SCRIPT in sources or DiscoverySource.HTML_MODULE in sources:
        kind = JavaScriptResourceKind.ENTRY_BUNDLE
        bundle_class = BundleClassification.ENTRY
    else:
        kind = JavaScriptResourceKind.APPLICATION_BUNDLE
        bundle_class = BundleClassification.APPLICATION

    return kind, bundle_class, bundler


def extract_chunk_name(filename: str) -> str | None:
    """Extract chunk name from filename when present."""
    match = re.search(r"(?i)(?:chunk[-.]?([\w-]+)|([\w-]+)\.chunk)", filename)
    if match is None:
        return None
    return match.group(1) or match.group(2)
