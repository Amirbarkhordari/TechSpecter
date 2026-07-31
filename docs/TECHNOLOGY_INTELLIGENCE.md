# Technology Intelligence (Phase 7.2)

Phase 7.2 extends TechSpecter fingerprinting and version detection with a **Technology Intelligence** engine that tracks complete evidence, attributes detections to assets, correlates multi-file evidence, and infers technology relationships.

This phase is passive only. It does not scan for vulnerabilities, secrets, or sensitive data.

## Architecture

```
UnifiedDetectionService.analyze_url()
  ├── DiscoveryPipeline → DiscoveryResult (+ asset_inventory)
  ├── ProviderManager → DetectionResult
  ├── EvidencePipeline → EvidenceCollection (optional)
  └── TechnologyIntelligenceEngine.build()
        ├── AssetAttributor        (URL → asset_id)
        ├── Evidence builders      (match + version + collection)
        ├── EvidenceTracker        (deduplication)
        ├── EvidenceCorrelationEngine (confidence + merge)
        └── Relationship resolver  (Next.js → React, etc.)
```

### Package layout

| Module | Responsibility |
|--------|----------------|
| `models.py` | Evidence, version attribution, relationships, intelligence report |
| `attribution.py` | Map evidence URLs to Phase 7.1 `AssetRecord` IDs |
| `evidence.py` | Build evidence from matches, collections, version results |
| `tracker.py` | Deduplicate and store evidence |
| `correlation.py` | Merge technologies, boost confidence, attach relationships |
| `relationships.py` | Known dependency registry |
| `engine.py` | End-to-end orchestration |
| `report.py` | Console output + export-ready report models |

## Detection flow

1. **Discovery** — JavaScript and asset inventory are collected (Phase 5.7 + 7.1).
2. **Detection** — Existing fingerprint providers produce `TechnologyMatch` entries.
3. **Evidence collection** — Optional `EvidencePipeline` gathers structured observations.
4. **Evidence building** — Each match produces `TechnologyEvidenceRecord` items with file/URL/asset attribution.
5. **Version attribution** — `VersionDetectionEngine` supplies version provenance and alternative candidates.
6. **Correlation** — Evidence across files is merged; confidence increases with independent sources.
7. **Relationships** — Known dependencies are inferred when both technologies are detected.
8. **Reporting** — Summary table + per-technology evidence blocks are rendered.

## Evidence model

Each `TechnologyEvidenceRecord` stores:

- Technology name, category, version, confidence
- Detector name and evidence type
- Matched pattern and matched text
- Source file, source URL, source asset ID
- Byte offset, line number (when available)
- Discovery method and detection timestamp

Evidence is never discarded after detection — it remains attached to the technology entry.

## Correlation

When a technology appears in multiple assets (e.g. React in `framework.js`, `vendor.js`, `runtime.js`):

- Evidence is deduplicated by pattern + source
- File and asset counts are aggregated
- Confidence receives a bounded boost for additional independent files and evidence items
- Duplicate technology entries are merged by technology ID

## Relationship model

`TechnologyRelationshipRecord` links detected technologies using a static registry, for example:

| Source | Target | Kind |
|--------|--------|------|
| Next.js | React | framework_dependency |
| Nuxt | Vue | framework_dependency |
| Material UI | React | ui_dependency |
| React Router | React | routing_dependency |

The registry is extensible in `relationships.py` and prepares for future graph visualization.

## Version attribution

`VersionAttributionRecord` captures:

- Detected version
- Source file and asset
- Matched pattern and text
- Confidence and extractor ID
- Alternative rejected candidates

When multiple version candidates exist, the highest-confidence result is selected; alternatives are stored internally.

## Reporting

### Console (`fingerprint` command)

After the standard technology report, TechSpecter prints:

```
==================================================
Technology Intelligence
==================================================

Technology | Version | Category | Confidence | Files | Evidence | Relationship | Detector
...
--------------------------------------------------
Technology: React
Found In:
  framework.js
  vendor.js
Evidence:
  React.version
Matched Pattern:
  React.version
Matched Text:
  19.3.0
Confidence:
  97%
```

### Export models (internal)

`ReportTechnologyIntelligence`, `ReportTechnologyIntelligenceEntry`, and `ReportTechnologyEvidence` on `Report.technology_intelligence` prepare JSON/HTML/SARIF export without implementing exporters in this phase.

## CLI

Technology intelligence runs automatically during:

```bash
techspecter fingerprint https://example.com
```

JSON output includes `technology_intelligence` on `FingerprintAnalysisResult`.

## Examples

### React in Next.js bundle

```
Technology: React
Found In: framework.js
Version Source: framework.js
Evidence: React.version
Matched Text: 19.3.0
```

### Next.js with relationship

When both Next.js and React are detected, a `framework_dependency` relationship is recorded from Next.js → React.

## Design decisions

1. **Layer on existing detection** — No duplicate fingerprint logic; intelligence is built from existing `TechnologyMatch` and version engines.
2. **Asset inventory join** — Phase 7.1 `AssetRecord.asset_id` is resolved by normalized URL.
3. **Passive evidence only** — No guessing; every record ties to a matched pattern or collected observation.
4. **Backward compatible** — `technology_intelligence` is optional on results; legacy detection output is unchanged.

## Extensibility

- Add relationships in `relationships.KNOWN_TECHNOLOGY_RELATIONSHIPS`
- Extend `evidence.py` mappers for new evidence sources
- Adjust confidence boosts in `correlation.py`
- Wire `Report.technology_intelligence` into exporters in a future phase

## Future roadmap

- Graph visualization of technology dependencies
- SARIF `physicalLocation` mapping via asset IDs
- Evidence pipeline as default for all providers
- Cross-provider evidence merge
- UI dependency tree export

## Related documentation

- [Asset Discovery](ASSET_DISCOVERY.md) — Phase 7.1 asset inventory
- [Fingerprinting Evidence](FINGERPRINTING_EVIDENCE.md) — Evidence collection pipeline
- [Version Detection](VERSION_DETECTION.md) — Phase 6 version engine
