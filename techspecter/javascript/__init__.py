"""JavaScript discovery and preprocessing foundation (Phase 5.7)."""

from techspecter.javascript.index.javascript_index import JavaScriptIndex
from techspecter.javascript.models import (
    BundleClassification,
    BundlerType,
    DiscoverySource,
    IndexedJavaScriptResource,
    JavaScriptResourceKind,
    ModuleType,
)
from techspecter.javascript.pipeline.config import JavaScriptPipelineConfig
from techspecter.javascript.pipeline.pipeline import JavaScriptPipeline

__all__ = [
    "BundleClassification",
    "BundlerType",
    "DiscoverySource",
    "IndexedJavaScriptResource",
    "JavaScriptIndex",
    "JavaScriptPipeline",
    "JavaScriptPipelineConfig",
    "JavaScriptResourceKind",
    "ModuleType",
]
