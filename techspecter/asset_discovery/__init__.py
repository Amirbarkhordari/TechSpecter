"""Passive asset discovery and inventory engine (Phase 7.1)."""

from techspecter.asset_discovery.classifier import AssetClassifier
from techspecter.asset_discovery.collector import AssetCollector, AssetCollectorConfig
from techspecter.asset_discovery.discovery import AssetDiscoveryEngine
from techspecter.asset_discovery.inventory import AssetInventoryBuilder, inventory_key
from techspecter.asset_discovery.models import (
    AssetCategory,
    AssetDiscoverySource,
    AssetInventory,
    AssetInventorySummary,
    AssetRecord,
    AssetReference,
    AssetRelationship,
)
from techspecter.asset_discovery.pipeline import (
    AssetDiscoveryPipeline,
    AssetDiscoveryPipelineConfig,
)

__all__ = [
    "AssetCategory",
    "AssetClassifier",
    "AssetCollector",
    "AssetCollectorConfig",
    "AssetDiscoveryEngine",
    "AssetDiscoveryPipeline",
    "AssetDiscoveryPipelineConfig",
    "AssetDiscoverySource",
    "AssetInventory",
    "AssetInventoryBuilder",
    "AssetInventorySummary",
    "AssetRecord",
    "AssetReference",
    "AssetRelationship",
    "inventory_key",
]
