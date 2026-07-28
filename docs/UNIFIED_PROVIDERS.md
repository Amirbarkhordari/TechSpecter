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
  wappalyzer_provider.py  # Passive Wappalyzer CLI
  retirejs_provider.py    # Passive Retire.js scanning
  manager.py              # Executes enabled providers
  normalizer.py           # Common ProviderMatch schema
  merger.py               # Merge + deduplicate
  version_resolver.py     # TechSpecter > Wappalyzer > Retire.js
  confidence.py           # Multi-provider confidence
  service.py              # UnifiedDetectionService
  summaries.py            # Category summary groups
```

## Configuration

```yaml
providers:
  techspecter:
    enabled: true
  wappalyzer:
    enabled: true
  retirejs:
    enabled: true
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

## Extensibility

Add a new provider by:

1. Implementing `DetectionProvider` in a new module
2. Registering it in `ProviderManager`
3. Adding configuration entry in `ProvidersConfig`

No changes to the core fingerprint engine are required.
