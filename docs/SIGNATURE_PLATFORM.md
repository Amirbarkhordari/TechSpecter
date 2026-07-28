# Signature Intelligence Platform

Phase 4 transforms TechSpecter into a comprehensive passive technology fingerprinting engine through a production-grade Signature Platform built on Phases 1–3 infrastructure.

## Platform Overview

```
Signature Catalog / JSON Database
        ↓
TechnologySignature (strongly typed schema)
        ↓
SignatureCompiler (indicators → rules)
        ↓
SignatureValidator (quality gates)
        ↓
SignatureRegistry
        ↓
EvidenceDetectionPipeline (unchanged)
```

## Signature Schema

Each `TechnologySignature` supports:

| Field | Description |
|-------|-------------|
| `id`, `name`, `aliases` | Identity |
| `vendor`, `category`, `subcategory` | Taxonomy |
| `website`, `references`, `notes` | Documentation |
| `priority`, `minimum_score`, `confidence_modifier` | Detection tuning |
| `required_evidence`, `optional_evidence`, `negative_evidence` | Typed indicator groups |
| `required_rules`, `positive_rules`, `optional_rules`, `negative_rules` | Compiled rules |
| `version_extractors` | Technology-specific version patterns |
| `dependencies`, `conflicts_with` | Relationship metadata |
| `supported_versions`, `deprecated` | Lifecycle metadata |

### Indicator Groups

Indicators are grouped by evidence target:

- `runtime`, `bundle`, `html`, `http`, `header`
- `manifest`, `sourcemap`, `package`, `metadata`, `content`

The compiler converts indicators into `SignatureRule` objects consumed by the Phase 3 Rule Engine.

## Technology Categories

Signatures are organized using `TechnologyCategory` taxonomy including:

Frontend Frameworks, Backend Frameworks, CMS, Bundlers, CSS Frameworks, Component Libraries, Analytics, CDNs, Hosting Platforms, Web Servers, Authentication, Payment Providers, Monitoring, Search Engines, Databases, and more.

## Signature Catalog

The built-in catalog (`signatures/catalog/technologies.py`) defines 80+ technologies using the fluent `SignatureBuilder` API. This avoids duplicated regex definitions and ensures consistent quality.

## Version Extractors

Technology-specific `VersionExtractorSpec` entries support extraction from:

- Runtime markers and banners
- Package metadata
- HTTP headers
- Build manifests
- Source maps (via evidence pipeline)

## False Positive Reduction

Quality signatures combine:

- Required evidence (mandatory signals)
- Multiple optional indicators across evidence types
- Negative evidence (e.g. Angular vs zone.js-only)
- Cross-validation through required + positive scoring
- Minimum score thresholds per technology

## Benchmarking

The benchmark framework (`signatures/benchmark/`) provides:

- Precision, recall, F1, version accuracy
- False positive/negative counts
- Explainability scoring
- Competitor comparison baselines (Wappalyzer, BuiltWith, WhatRuns, FingerprintJS)

```python
from techspecter.fingerprinting.signatures.benchmark import BenchmarkRunner, render_benchmark_report

report = BenchmarkRunner().run()
print(render_benchmark_report(report))
```

## Regression Dataset

`signatures/regression/dataset.json` contains real-world stack samples with expected detections. Regression tests ensure future changes do not reduce accuracy.

## Authoring Guide

1. Use `SignatureBuilder` in the catalog or author JSON with indicator groups
2. Define at least one required signal and two optional indicators
3. Add technology-specific version extractors when possible
4. Include negative evidence for commonly confused technologies
5. Run `SignatureValidator` before submitting new signatures

## Contribution Guide

1. Add technology definition to `catalog/technologies.py`
2. Choose appropriate `TechnologyCategory`
3. Add regression sample if representative stack
4. Run `pytest tests/test_signature_platform.py`
5. Run benchmark and verify precision/recall

See also:

- [SIGNATURE_AUTHORING.md](SIGNATURE_AUTHORING.md)
- [VERSION_EXTRACTOR_GUIDE.md](VERSION_EXTRACTOR_GUIDE.md)
- [BENCHMARK_METHODOLOGY.md](BENCHMARK_METHODOLOGY.md)
