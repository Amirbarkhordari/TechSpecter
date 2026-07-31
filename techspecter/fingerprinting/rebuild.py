"""Rebuild forward references on fingerprint analysis models."""


def rebuild_fingerprint_analysis_models() -> None:
    """Resolve forward references on FingerprintAnalysisResult."""
    from techspecter.asset_discovery.models import AssetInventory
    from techspecter.fingerprinting.models import FingerprintAnalysisResult
    from techspecter.sensitive_intelligence.models import SensitiveIntelligenceReport
    from techspecter.technology_intelligence.models import TechnologyIntelligenceReport

    FingerprintAnalysisResult.model_rebuild(
        _types_namespace={
            "TechnologyIntelligenceReport": TechnologyIntelligenceReport,
            "AssetInventory": AssetInventory,
            "SensitiveIntelligenceReport": SensitiveIntelligenceReport,
        },
    )


rebuild_fingerprint_analysis_models()
