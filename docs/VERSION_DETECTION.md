# JavaScript Version Detection Engine (Phase 6)

Phase 6 adds a dedicated **JavaScript Version Detection Engine** that extracts real framework and library versions from downloaded JavaScript resources. It runs after fingerprint detection and before final reporting.

Everything remains **passive** — no CVE lookup, vulnerability scanning, or active probing.

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
├── models.py          # ExtractedVersion, VersionEvidence, TechnologyVersionResult
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

## Developer API

```python
from techspecter.versioning import VersionDetectionEngine

engine = VersionDetectionEngine()
enriched = engine.enrich(detection_result, discovery_result)
```

See also: [JAVASCRIPT_DISCOVERY.md](JAVASCRIPT_DISCOVERY.md), [VERSION_EXTRACTOR_GUIDE.md](VERSION_EXTRACTOR_GUIDE.md).
