"""Rebuild forward references on fingerprint analysis models."""


def rebuild_fingerprint_analysis_models() -> None:
    """Resolve forward references on FingerprintAnalysisResult."""
    from techspecter.fingerprinting.models import FingerprintAnalysisResult
    from techspecter.technology_intelligence.models import TechnologyIntelligenceReport

    FingerprintAnalysisResult.model_rebuild(
        _types_namespace={"TechnologyIntelligenceReport": TechnologyIntelligenceReport},
    )


rebuild_fingerprint_analysis_models()
