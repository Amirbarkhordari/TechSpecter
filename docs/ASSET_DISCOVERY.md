# Asset Discovery & Inventory (Phase 7.1)

Phase 7.1 introduces a **passive Asset Discovery and Inventory engine** that discovers every publicly referenced asset belonging to a target website and builds a complete inventory.

This phase is **not** vulnerability scanning, technology detection, or secrets detection. It only inventories assets that are naturally discoverable from HTML, JavaScript, CSS, manifests, HTTP headers, and well-known public metadata.

## Architecture

```
techspecter/asset_discovery/
├── models.py          # AssetRecord, AssetInventory, categories, relationships
├── classifier.py      # Extension/MIME-based asset classification
├── hash.py            # SHA256 and stable asset IDs
├── discovery.py       # AssetDiscoveryEngine (reference collection)
├── collector.py       # AssetCollector (passive downloads)
├── inventory.py       # AssetInventoryBuilder (dedup + summary)
├── pipeline.py        # AssetDiscoveryPipeline orchestrator
├── report.py          # Console rendering + export models
└── sources/
    ├── html.py        # HTML script/link/img/manifest references
    ├── css.py         # CSS url() and @import references
    ├── javascript.py  # JS string literals, workers, source maps
    └── manifest.py    # Web manifest icon/start_url references
```

## Discovery Flow

```
DiscoveryPipeline.run()
        │
        ├── HtmlDownloader (target page)
        ├── JavaScriptPipeline (existing Phase 5.7)
        └── AssetDiscoveryPipeline (Phase 7.1)
                │
                ├── Collect references (HTML, CSS, JS, manifest, well-known)
                ├── Seed metadata from JavaScriptIndex
                ├── Download remaining assets (bounded concurrency)
                ├── Recursive CSS/manifest expansion (bounded rounds)
                └── Build AssetInventory
                        │
                        └── Attached to DiscoveryResult.asset_inventory
```

## Inventory Model

Each `AssetRecord` includes:

- Unique ID (stable hash of normalized URL)
- URL, relative path, filename, extension
- Category (JavaScript, CSS, JSON, Map, Manifest, Worker, WASM, Font, etc.)
- Content-Type, MIME, HTTP status, encoding, file size
- SHA256 digest (when downloaded)
- Discovery sources and relationship evidence
- Download status, timing, and errors

`AssetInventory.summary` provides per-category counts and total assets.

## Integration

| Component | Integration |
|-----------|-------------|
| `DiscoveryResult` | Optional `asset_inventory: AssetInventory \| None` |
| `DiscoveryPipeline` | `collect_asset_inventory=True` by default |
| CLI `discover` | Renders asset inventory when present |
| CLI `inventory` | Dedicated asset inventory command |
| `Report` | Optional `asset_inventory: ReportAssetInventory` for future exporters |
| `ReportSection` | `asset-inventory` section metadata for JSON/HTML/SARIF |

## CLI Usage

```bash
# Discover JavaScript and show asset inventory
python -m techspecter discover https://example.com

# Dedicated asset inventory scan
python -m techspecter inventory https://example.com

# JSON output
python -m techspecter inventory https://example.com --json

# Reference-only mode (no downloads)
python -m techspecter inventory https://example.com --no-download
```

## Asset Lifecycle

1. **Reference** — URL discovered from passive source with relationship evidence
2. **Register** — Added to inventory (deduplicated by normalized URL)
3. **Download** — Optional HTTP GET with size limits and timeout handling
4. **Classify** — Category assigned from extension, MIME, or source hint
5. **Expand** — CSS/manifest bodies parsed for additional references (bounded)
6. **Report** — Summary + table rendered to terminal; export models prepared

## Extensibility

### Adding a classifier rule

Extend `AssetClassifier._EXTENSION_MAP` or `_category_from_mime()`.

### Adding a discovery source

1. Create `sources/mysource.py` with an `extract_*_references()` function
2. Register references in `AssetDiscoveryEngine.collect_references()`

### Adding export support (future)

Use `build_report_asset_inventory()` and `Report.asset_inventory` — exporters can read structured data without redesign.

## Design Decisions

- **Passive only** — No wordlists, brute force, or directory enumeration
- **Compose with JS pipeline** — Reuses `JavaScriptIndex` instead of re-downloading scripts
- **Backward compatible** — `asset_inventory` is optional on `DiscoveryResult`
- **Dedup by normalized URL** — Fragments stripped; query strings preserved
- **Bounded recursion** — CSS/manifest expansion limited to configurable rounds

## Limitations

- Only assets **referenced** in discoverable content are inventoried
- Large files skipped when exceeding configured size limit
- Image discovery from JS uses string-literal heuristics (optional, conservative)
- Sitemap URL lists are not recursively crawled (only referenced sitemap URLs fetched)
- Full content bodies are not stored in inventory models (metadata only)

## Future Roadmap

- HTML/JSON/SARIF exporters for asset inventory sections
- Relationship graph visualization
- Integration with fingerprint `--inventory` flag
- Incremental inventory diff across scans
- Source map asset tree expansion (passive, when content available)

See also: [JAVASCRIPT_DISCOVERY.md](JAVASCRIPT_DISCOVERY.md), [VERSION_DETECTION.md](VERSION_DETECTION.md).
