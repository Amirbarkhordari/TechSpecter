# JavaScript Discovery Architecture (Phase 5.7)

Phase 5.7 introduces a production-grade JavaScript discovery and preprocessing foundation. The goal is **not** technology detection — it prepares clean, normalized, structured JavaScript data for the future Intelligence Engine (Phase 6).

Everything remains **passive**: no browser automation, JavaScript execution, active crawling, or endpoint guessing.

## Pipeline Stages

```
HTML / Seed References
        ↓
Discovery (v2 sources + recursive expansion)
        ↓
Download (bounded concurrency)
        ↓
Deduplication (URL + content hash)
        ↓
Classification (resource kind + bundle role)
        ↓
Normalization (minified/bundled content)
        ↓
Metadata Extraction (imports, bundler, source maps)
        ↓
AST Preparation (token parse + cache)
        ↓
Indexing (JavaScript Index)
        ↓
Ready for Intelligence Engine
```

## Package Layout

```
techspecter/javascript/
├── discovery/          # v2 reference discovery + recursion
├── classification/     # resource kind + bundler detection
├── normalization/      # content normalization pipeline
├── metadata/           # structured per-resource metadata
├── ast/                # AST preparation + parser abstraction
├── index/              # centralized JavaScript Index
├── cache/              # download/normalized/metadata/AST caches
├── pipeline/           # staged orchestrator
└── adapter.py          # DiscoveryResult backward compatibility
```

## Discovery Sources

The v2 engine discovers JavaScript from:

| Source | Module |
|--------|--------|
| HTML `<script>` tags (classic, module, async, defer) | `discovery/sources/html.py` |
| `<link rel="modulepreload">` | `discovery/sources/html.py` |
| `<link rel="preload" as="script">` | `discovery/sources/html.py` |
| `<link rel="prefetch">` | `discovery/sources/html.py` |
| Import maps (`type="importmap"`) | `discovery/sources/html.py` |
| Service / shared workers | `discovery/sources/html.py` |
| Dynamic `import()` | `discovery/references.py` |
| Webpack / Vite chunk references | `discovery/references.py` |
| Build/asset manifest JSON | `discovery/references.py` |
| Recursive script content | `discovery/engine.py` |

## Recursive Discovery

`JavaScriptDiscoveryEngine.discover_recursive()` follows passive references until no new URLs are found:

```
HTML → main.js → chunk-abc.js → lazy-module.js
```

Safety limits (configurable via `JavaScriptPipelineConfig`):

- `max_resources` — maximum URLs processed (default 200)
- `max_recursive_rounds` — maximum expansion rounds (default 20)
- URL normalization deduplication prevents infinite loops

## JavaScript Index

`JavaScriptIndex` stores each resource exactly once:

- `resources` — indexed by `resource_id`
- `url_to_id` — URL lookup
- `hash_to_id` — content-hash lookup for duplicate detection

Future analyzers should consume the index instead of reading raw files.

## Classification

`classify_resource()` assigns:

- **Resource kind**: Entry, Runtime, Vendor, Application, Framework, Lazy/Dynamic Chunk, Worker, Module
- **Bundle classification**: Entry, Runtime, Vendor, Application, Framework, Chunk, Worker
- **Bundler**: Webpack, Turbopack, Vite, Rollup, Parcel, Rspack, esbuild

## Normalization

`JavaScriptNormalizationPipeline` wraps the existing normalizer:

- UTF-8 / latin-1 recovery
- Line ending normalization
- Minified detection
- Size truncation (default 5 MB)
- **Never modifies program logic**

## Metadata

`JavaScriptResourceMetadata` includes:

- Filename, content hash, module type
- Bundle type, build tool, chunk name
- Source map and manifest references
- Import/export references and dependencies
- Known globals and discovery sources

## AST Preparation

`AstPreparationStage` provides:

- Pluggable `AstParser` interface
- Default `TokenAstParser` (token/regex backend)
- LRU cache keyed by URL + content hash
- `AstSnapshot` for downstream analyzers

## Caching

`JavaScriptResourceCache` caches:

- Normalized content
- Metadata
- AST snapshots
- Content hashes

Deterministic keys: `SHA-256(content)` and `{url}:{hash-prefix}`.

## Configuration

```yaml
# Future configuration section (via JavaScriptPipelineConfig)
javascript:
  max_concurrency: 10
  max_resources: 200
  max_recursive_rounds: 20
  enable_recursive_discovery: true
  enable_ast_preparation: true
  enable_content_hash_dedup: true
  cache_enabled: true
```

## Backward Compatibility

`DiscoveryPipeline.run()` uses the v2 pipeline internally and maps output to the existing `DiscoveryResult`:

- `external_scripts`, `inline_scripts`, `downloads` — unchanged
- `javascript_index` — new optional field with full index data

## Extension Points

1. **Discovery sources** — add extractors under `discovery/sources/`
2. **Reference patterns** — extend `discovery/references.py`
3. **Classification rules** — extend `classification/classifier.py`
4. **AST parsers** — implement `AstParser` and inject into `AstPreparationStage`
5. **Pipeline stages** — inject stages into `JavaScriptPipeline` constructor

## Developer Guide

```python
from techspecter.javascript import JavaScriptPipeline, JavaScriptPipelineConfig
from techspecter.downloader.http_client import AsyncHttpClient

config = JavaScriptPipelineConfig(max_resources=100)
pipeline = JavaScriptPipeline(config=config)

async with AsyncHttpClient() as client:
    result = await pipeline.process_html(
        html=html_content,
        base_url="https://example.com/",
        client=client,
    )

for resource in result.index.all_resources():
    print(resource.metadata.bundler, resource.metadata.resource_kind)
```

See also: [JAVASCRIPT_INTELLIGENCE.md](JAVASCRIPT_INTELLIGENCE.md) for the downstream analysis engine.
