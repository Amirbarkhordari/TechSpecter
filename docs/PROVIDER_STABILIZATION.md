# Phase 5.5 — External Provider Stabilization

Phase 5.5 hardens the unified provider framework before Phase 6 (Version Intelligence Engine). It does **not** add new detection capabilities. Instead, it makes external providers reliable, extensible, optional, well-tested, and ready for downstream enrichment.

## Provider Lifecycle

Every provider follows a consistent lifecycle:

```
Initialize → Availability Check → Execute → Validate Output → Normalize → Merge → Report
```

Implementation:

| Stage | Module |
|-------|--------|
| Health check | `providers/health.py`, `BaseDetectionProvider.check_health()` |
| Execute | `providers/lifecycle.py` (`ExternalProviderLifecycle`) |
| Validate | `providers/validation.py` |
| Normalize | `providers/normalizer.py`, `providers/naming.py` |
| Merge | `providers/merger.py`, `providers/evidence.py` |
| Report | `FingerprintAnalysisResult.provider_diagnostics` |

## Wappalyzer Compatibility Layer

Wappalyzer no longer assumes a single CLI command. The compatibility layer (`providers/backends/wappalyzer_compat.py`) tries multiple adapters in order:

1. Native `wappalyzer` CLI
2. `npx @wappalyzer/wappalyzer`
3. `npx wappalyzer`

Each skipped adapter is logged with a structured reason. New adapters implement `WappalyzerAdapter` and register with `WappalyzerCompatibilityLayer` — no changes to `WappalyzerProvider` required.

## Provider Health Checks

Before execution, `ProviderManager.check_health_all()` reports:

- availability state (`available`, `skipped`, `unavailable`, `failed`)
- selected backend id
- backend version (when known)
- skip/failure reason

Health is included in scan diagnostics via `FingerprintAnalysisResult.provider_diagnostics`.

## Output Validation

`ProviderOutputValidator` rejects malformed data before merge:

- missing technology id or name
- invalid confidence values
- malformed version strings
- duplicate technologies within a provider

Raw Wappalyzer and Retire.js payloads are also checked for structural issues.

## Technology Normalization

`providers/naming.py` canonicalizes display names across providers:

| Input | Output |
|-------|--------|
| ReactJS | React |
| AngularJS | Angular |
| Vue.js | Vue |

Technology IDs continue to use `normalize_technology_id()` for cross-provider deduplication.

## Evidence Aggregation

`ProviderEvidenceAggregator` merges evidence from all providers with source attribution. Each technology accumulates:

- string evidence (for reports)
- structured `PatternEvidence` (for explainability)
- provider-specific categories (runtime, javascript, wappalyzer, retirejs, etc.)

## Merge Engine

`ProviderMerger` improvements:

- deduplicates technologies by canonical id
- merges evidence and security findings
- resolves versions via provider priority
- recalculates confidence with explainable breakdown
- preserves provider attribution and per-provider version metadata

## Version Intelligence Foundation

`ProviderVersionMetadata` on each `ProviderMatch` captures:

- version, confidence, evidence
- provider and detection method
- location (when available)
- raw version and `is_known` flag

Merged results store `version_metadata_by_provider` in `provider_metadata` for Phase 6 enrichment without API changes.

## Architecture Decisions

1. **Optional dependencies** — Wappalyzer and Retire.js never block scanning.
2. **Backend injection** — providers depend on protocols, not CLI executors.
3. **Validation gate** — malformed provider output never reaches the merge engine.
4. **Backward compatibility** — existing CLI, models, and reports work unchanged; diagnostics are additive.
5. **Structured logging** — health, execution, validation, and merge summaries use structured log fields.

## Package Layout

```
techspecter/providers/
  lifecycle.py          # External provider execution flow
  health.py             # Health reporting
  validation.py         # Output validation
  naming.py             # Technology name normalization
  evidence.py           # Evidence aggregation
  version_metadata.py   # Phase 6 version foundation
  backends/
    wappalyzer_compat.py  # Multi-adapter Wappalyzer layer
```

See also: [UNIFIED_PROVIDERS.md](UNIFIED_PROVIDERS.md)
