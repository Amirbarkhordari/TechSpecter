# JavaScript Version Detection Engine (Phase 6)

Phase 6 adds a dedicated **JavaScript Version Detection Engine** that extracts real framework and library versions from downloaded JavaScript resources. It runs after fingerprint detection and before final reporting.

Everything remains **passive** — no CVE lookup, vulnerability scanning, or active probing.

## Conceptual separation (Phase 6 Step 1)

`
Technology Detection
        ≠
Version Evidence
        ≠
Version Candidate
        ≠
Version Confirmation
        ≠
Final Technology Version
`

Finding a version string inside an asset does **not** mean every technology detected in that asset owns that version.

| Concept | Meaning |
|---------|---------|
| Technology Detection | Evidence that a technology is present |
| Version Evidence | A version string observation with provenance |
| Version Candidate | Technology-scoped version observation pending ownership confirmation |
| Version Confirmation | Ownership-gated promotion of a candidate to a confirmed version |
| Final Technology Version | Confirmed version attached to a technology match (or Unknown) |

Independent confidence axes:

- **Technology confidence** — strength of technology detection
- **Version confidence** — strength of the version observation
- **Ownership confidence** — strength of technology-scoped attribution

A technology may be confirmed at confidence 100 with version Unknown. Weak/reference evidence may remain **candidate-only** without becoming a final version.

Ownership is always technology-scoped. Shared assets do **not** imply shared version ownership. Full multi-version conflict resolution is deferred to Phase 6 Step 2.


## Primary / Alternate Resolution (Phase 6 Step 2)

`
Version Candidate
        ↓
Ownership
        ↓
Ranking (evidence quality + independent corroboration)
        ↓
Conflict Classification
        ↓
Primary Version
        ↓
Alternate Versions
`

Rules:

- Primary Version is selected by ownership and evidence quality, **not** by numeric newest/first/last.
- Alternate versions may be retained when attributable and provenance-backed.
- Two strong conflicting versions without a clear margin may remain **Unknown/Ambiguous**.
- Independent assets corroborate a version; repeated matches in one source do not inflate independence.
- Technology, Version, and Ownership confidence remain independent.
- Ownership remains technology-scoped.
- Step 2 does not perform live-target validation and does not claim universal resolution.

Conflict classes: 
o_conflict, weak_alternate, strong_conflict, mbiguous, weak_only.

Canonical API: 	echspecter.versioning.resolve_primary_version.


## Canonical Resolution Across Paths (Phase 6 Step 3)

`
Extraction (JS extractors / evidence collectors)
        ↓
Version Evidence
        ↓
Version Candidate
        ↓
Ownership
        ↓
Canonical Resolution (resolve_primary_version)
        ↓
Primary Version + Alternate Versions
        ↓
TechnologyMatch
        ↓
Technology Intelligence / Reporting
`

- Extractors extract evidence; they do **not** own final version selection.
- Evidence-path and JS-extractor-path candidates share the same candidate model and resolver.
- Technology Intelligence consumes TechnologyMatch.version when already resolved and does not independently override it.
- Live-target validation is separate from this architecture step.

### Evidence quality vs ownership (post-validation hardening)

Extractors produce evidence. `VersionCandidate` retains technology identity, version value,
evidence type/source, ownership, and confidence axes through adaptation.

Confirmation requires **both**:

1. Technology-scoped ownership strong enough to attribute the observation
2. Evidence quality strong enough to confirm (weak `reference` / `generic_literal` methods
   and weak source labels cannot enter the strong-conflict path even if ownership was
   stamped high by a technology-scoped extractor)

Canonical resolution (`resolve_primary_version`) alone selects Primary / Alternate / Unknown.
Technology Intelligence consumes that canonical result.

## Pipeline

```
JavaScript Discovery (Phase 5.7)
        ↓
Fingerprint Detection
        ↓
Version Detection (Phase 6)   ← techspecter/versioning/
        ↓
Final Report
```

Integration point: `FingerprintPipeline.run()` calls `VersionDetectionEngine.enrich()` after technology matching.

## Architecture

```
techspecter/versioning/
├── engine.py          # VersionDetectionEngine
├── models.py          # Evidence types, results, ownership/state enums
├── ownership.py       # Technology-scoped ownership classification
├── attribution.py     # Candidate vs confirmed confirmation helpers
├── registry.py        # VersionExtractorRegistry
├── extractor.py       # TechnologyVersionExtractor protocol
├── validator.py       # Semver validation and normalization
├── confidence.py      # Method → confidence scoring
└── extractors/
    ├── base.py        # PatternVersionExtractor
    ├── react.py
    ├── nextjs.py
    ├── angular.py
    ├── vue.py
    ├── jquery.py
    ├── bootstrap.py
    ├── tailwind.py
    ├── materialui.py
    ├── leaflet.py
    ├── webpack.py
    ├── vite.py
    └── turbopack.py
```

## Version Extraction Flow

1. Collect JavaScript content from `DiscoveryResult.javascript_index` (preferred) or legacy downloads/inline scripts.
2. For each detected technology with `version == Unknown` (or low-confidence version):
3. Look up a technology-specific extractor in `VersionExtractorRegistry`.
4. Run all regex-based extraction strategies on all resource bodies.
5. Validate candidates with `validate_and_normalize()`.
6. Rank by method confidence (runtime constants > package paths > banners).
7. Update `TechnologyMatch.version`, `version_source`, `version_confidence`, `version_reason`, and `evidence_sources`.

## Extraction Methods

| Method | Evidence Type | Typical Confidence |
|--------|---------------|------------------|
| Runtime constant | `runtime_constant` | High (~95) |
| Framework object | `framework_object` | High (~92) |
| Package path | `package_identifier` | High (~90) |
| Build metadata | `build_metadata` | High (~88) |
| Manifest/metadata | `metadata` | Medium (~85) |
| Banner comment | `banner` | Medium (~80) |

## Supported Technologies

| Technology ID | Extractor |
|---------------|-----------|
| `react` | `ReactVersionExtractor` |
| `nextjs` | `NextJsVersionExtractor` |
| `angular` | `AngularVersionExtractor` |
| `vue` | `VueVersionExtractor` |
| `jquery` | `JQueryVersionExtractor` |
| `bootstrap` | `BootstrapVersionExtractor` |
| `tailwindcss` | `TailwindVersionExtractor` |
| `material-ui` | `MaterialUiVersionExtractor` |
| `leaflet` | `LeafletVersionExtractor` |
| `webpack` | `WebpackVersionExtractor` |
| `vite` | `ViteVersionExtractor` |
| `turbopack` | `TurbopackVersionExtractor` |

## Adding a New Extractor

1. Create `techspecter/versioning/extractors/mytech.py`:

```python
class MyTechVersionExtractor(PatternVersionExtractor):
    technology_id = "mytech"
    patterns = (
        ExtractionPattern(
            re.compile(r'MyTech\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "MyTech.version runtime constant",
        ),
    )
```

2. Register in `versioning/extractors/__init__.py` and `registry.py`.
3. Add tests in `tests/test_version_detection_engine.py`.

No changes to `FingerprintPipeline` are required when using the default registry.

## Semantic Version Validation

Supported formats:

- `x.y`, `x.y.z`
- Pre-release: `x.y.z-beta`, `x.y.z-alpha`, `x.y.z-rc`, `x.y.z-rc.1`

Invalid strings are rejected; versions are never invented.

## Reporting

`ReportEngine` maps `TechnologyMatch.version` to `ReportTechnology.version`. When Phase 6 resolves a version, reports and console output show the detected value instead of `Unknown`.

Version provenance appears in:

- `version_source`
- `version_confidence`
- Verbose console details

## Limitations

- Extraction is regex-based, not full AST analysis (by design for this phase).
- Versions embedded only in external source maps are not fetched unless content is already available.
- Generic semver literals without technology context are not used (avoids false positives).
- Technologies without a dedicated extractor still rely on legacy `VersionExtractor` / JSON patterns.
- Highly obfuscated bundles may hide runtime constants.
- Primary/alternate version ranking and full cross-asset conflict resolution are **not** complete (Phase 6 Step 2).
- This foundation does not claim universal version attribution.

## Developer API

```python
from techspecter.versioning import VersionDetectionEngine

engine = VersionDetectionEngine()
enriched = engine.enrich(detection_result, discovery_result)
```

See also: [JAVASCRIPT_DISCOVERY.md](JAVASCRIPT_DISCOVERY.md), [VERSION_EXTRACTOR_GUIDE.md](VERSION_EXTRACTOR_GUIDE.md).
