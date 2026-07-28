# Unified Detection Providers

Phase 5 extends TechSpecter with a **provider-based unified detection system**. TechSpecter remains the primary engine; Wappalyzer and Retire.js run as additional passive providers after discovery.

## Architecture

```
UnifiedDetectionService
  → DiscoveryPipeline (once)
  → ProviderManager
       → TechSpecterProvider (primary)
       → WappalyzerProvider
       → RetireJsProvider
  → ProviderMerger
  → VersionResolver + ConfidenceEngine
  → Unified DetectionResult
```

Package layout:

```
techspecter/providers/
  base.py                 # DetectionProvider protocol
  techspecter_provider.py # Wraps FingerprintPipeline
  wappalyzer_provider.py  # Passive Wappalyzer provider (backend-injected)
  retirejs_provider.py    # Passive Retire.js provider (backend-injected)
  external.py             # Timeout, retry, structured logging for externals
  backends/
    wappalyzer.py         # WappalyzerBackend protocol + CLI implementation
    retirejs.py           # RetireJsBackend protocol + CLI implementation
  manager.py              # Executes enabled providers (failure-isolated)
  normalizer.py           # Common ProviderMatch schema
  merger.py               # Merge + deduplicate
  version_resolver.py     # TechSpecter > Wappalyzer > Retire.js
  confidence.py           # Multi-provider confidence
  service.py              # UnifiedDetectionService
  summaries.py            # Category summary groups
```

External providers (Wappalyzer, Retire.js) are **optional dependencies**. Each depends on a backend protocol so the underlying implementation can be replaced without changing the provider interface. If a backend is unavailable, times out, or fails unexpectedly, the error is logged and remaining providers continue.

Phase 5.5 stabilization details: [PROVIDER_STABILIZATION.md](PROVIDER_STABILIZATION.md)

## Configuration

```yaml
providers:
  techspecter:
    enabled: true
  wappalyzer:
    enabled: true
    timeout_seconds: 120
    retry_count: 0
    retry_delay_seconds: 1.0
  retirejs:
    enabled: true
    timeout_seconds: 120
    retry_count: 0
    retry_delay_seconds: 1.0
```

## CLI

```bash
# Default: all enabled providers
techspecter fingerprint https://example.com

# Select providers
techspecter fingerprint https://example.com --provider techspecter --provider wappalyzer

# Disable providers
techspecter fingerprint https://example.com --disable-provider retirejs

# All providers explicitly
techspecter fingerprint https://example.com --provider all
```

## Version Priority

1. TechSpecter
2. Wappalyzer
3. Retire.js

Unknown TechSpecter versions fall back to other providers. Conflicts are recorded in metadata.

## Confidence

| Providers agreeing | Target confidence |
|-------------------|-------------------|
| 1 | ~90% |
| 2 | ~97% |
| 3 | ~99% |

Evidence quality provides additional boost.

## Passive Security Intelligence

Retire.js findings appear in report sections as **Passive Security Intelligence** with library, version, CVE references, and severity. No exploitation is performed.

## Resilience and Optional Dependencies

- Wappalyzer and Retire.js are optional; the pipeline continues when they are missing or fail.
- `ProviderManager.run_all()` wraps every provider in exception handling and never stops early.
- External providers use `ExternalProviderRunner` for configurable timeout, retry count, and retry delay.
- Structured logging includes `provider_id`, `target_url`, attempt number, and error details.
- Replace CLI backends by implementing `WappalyzerBackend` or `RetireJsBackend` and injecting them into the provider.

## Extensibility

Add a new provider by:

1. Implementing `DetectionProvider` in a new module
2. Registering it in `ProviderManager`
3. Adding configuration entry in `ProvidersConfig`

For optional external tools, add a backend protocol under `techspecter/providers/backends/` and inject it into the provider. No changes to the core fingerprint engine are required.
