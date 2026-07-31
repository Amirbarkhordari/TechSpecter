"""Technology intelligence and evidence engine (Phase 7.2)."""

from techspecter.technology_intelligence.attribution import AssetAttributor
from techspecter.technology_intelligence.correlation import EvidenceCorrelationEngine
from techspecter.technology_intelligence.engine import TechnologyIntelligenceEngine
from techspecter.technology_intelligence.models import (
    DiscoveryMethod,
    IntelligenceEvidenceType,
    RelationshipKind,
    TechnologyDetectionMetadata,
    TechnologyEvidenceRecord,
    TechnologyIntelligenceEntry,
    TechnologyIntelligenceReport,
    TechnologyRelationshipRecord,
    VersionAttributionRecord,
)
from techspecter.technology_intelligence.tracker import EvidenceTracker

__all__ = [
    "AssetAttributor",
    "DiscoveryMethod",
    "EvidenceCorrelationEngine",
    "EvidenceTracker",
    "IntelligenceEvidenceType",
    "RelationshipKind",
    "TechnologyDetectionMetadata",
    "TechnologyEvidenceRecord",
    "TechnologyIntelligenceEngine",
    "TechnologyIntelligenceEntry",
    "TechnologyIntelligenceReport",
    "TechnologyRelationshipRecord",
    "VersionAttributionRecord",
]
