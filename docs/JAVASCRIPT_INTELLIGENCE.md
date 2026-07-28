# JavaScript Intelligence Engine

Phase 2 of the TechSpecter Fingerprinting Engine introduces a production-grade,
passive Deep JavaScript Intelligence subsystem. Every downloaded or inline
JavaScript resource is normalized, parsed, inspected, and converted into strongly
typed `Evidence` objects. No JavaScript is executed and no browser runtime is used.

## Architecture

```
DiscoveryResult
       │
       ▼
JavaScriptAnalyzer (collector)
       │
       ▼
JavaScriptIntelligenceEngine
   ├── normalizer.py      UTF-8, line endings, minified detection, truncation
   ├── parser/            Pluggable parser interface (TokenJavaScriptParser)
   ├── cache.py           LRU parse cache (avoid duplicate parsing)
   ├── extractors/        Modular evidence extractors
   ├── sourcemap/         Passive download + JSON parse
   └── evidence_builder.py → Evidence objects
```

Supporting collectors reuse shared extractors:

- `BundleAnalyzer` → `extractors/bundle.py`
- `PackageAnalyzer` → `extractors/package.py`

The evidence pipeline deduplicates identical observations produced by overlapping
collectors.

## Parsing Pipeline

1. **Normalize** — decode bytes, normalize line endings, detect minification, truncate oversized files.
2. **Parse** — structured token extraction (imports, exports, strings, identifiers).
3. **Extract** — run modular extractors (banner, versions, runtime, bundle, package, metadata).
4. **Source maps** — optionally fetch and parse `sourceMappingURL` references.
5. **Evidence** — map findings to `Evidence` with `technology=None`.

## Evidence Types

New Phase 2 evidence types include:

| Type | Description |
|------|-------------|
| `string_literal` | Meaningful extracted string literals |
| `version_candidate` | Version strings (not resolved in Phase 2) |
| `runtime_pattern` | Framework runtime API observations |
| `package_reference` | npm/node_modules/import targets |
| `banner` | Header comments, licenses, generators |
| `manifest` | Framework manifest references |
| `bundle_runtime` | Webpack/Vite/Rollup/etc. runtime markers |
| `ast_extraction` | Structured parse observations |
| `source_map_metadata` | Original paths from source maps |
| `import_export` | Import/export module targets |

## Package Intelligence

The package extractor collects evidence only when supported by file content:

- `node_modules/` path references
- Embedded `package.json` fragments
- License and copyright headers
- Import targets from parsed modules
- NPM URL patterns

Package names are never guessed — only observed references become evidence.

## Bundle Intelligence

Bundle analysis covers:

- Filename conventions (`.min.js`, `.chunk.js`, etc.)
- Bundler runtime markers (webpack, vite, rollup, parcel, rspack, turbopack)
- Chunk identifiers and dynamic imports
- Manifest name references (Next.js, Vite, Nuxt)

## Runtime Extraction

Runtime patterns (e.g. `ReactDOM.createRoot`, `Vue.createApp`, `ɵɵdefineComponent`)
are recorded as `runtime_pattern` evidence with a `runtime_family` metadata hint.
Technologies are **not** detected in Phase 2.

## Version Candidate Extraction

All semver-like and calver-like strings are stored as `version_candidate` evidence.
Selecting the correct version is deferred to Phase 3 (Confidence Engine).

## Source Map Processing

When a `sourceMappingURL` is present:

1. The reference is recorded as `source_map` evidence.
2. The map is passively downloaded (HTTP/HTTPS or data URLs).
3. JSON is parsed to extract original file paths and embedded metadata.
4. `node_modules` paths produce `package_reference` evidence.

## Performance Optimizations

- **Parse cache** — SHA-256 keyed LRU cache shared across collectors.
- **Truncation** — files larger than 5 MB are truncated for analysis.
- **Minified detection** — very large minified files use regex fallback strategy.
- **Extractor limits** — caps on string literals, version candidates, metadata items.
- **Pipeline deduplication** — identical evidence from multiple collectors is merged.

## Error Handling

Malformed JavaScript, invalid encodings, and broken source maps never crash the
engine. Failures are logged and processing continues for remaining resources.

## Extension Points

- Replace `JavaScriptParser` with a future AST backend without changing extractors.
- Inject `JavaScriptIntelligenceEngine` into `JavaScriptAnalyzer` for testing.
- Add extractors under `extractors/` and register them in `engine.py`.

## Known Limitations

- Token parser is not a full ECMAScript AST (decorators/classes are partially covered).
- Source map fetching requires network access for remote maps.
- Commit hash detection uses contextual heuristics to reduce false positives.
- Manifest JSON extraction uses conservative fragment matching.

## Phase 3 Roadmap

- Confidence-weighted version selection
- Technology correlation from evidence graph
- Optional tree-sitter or WASM parser backend
- Cross-resource evidence linking
