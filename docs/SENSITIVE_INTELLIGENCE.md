# Sensitive Data Intelligence (Phase 7.3)

Phase 7.3 adds a **Sensitive Data & Secrets Intelligence** engine that passively analyzes downloaded textual assets from Phase 7.1 asset discovery and enriches the overall scan with traceable findings.

This phase does **not** perform vulnerability scanning, credential validation, exploitation, or additional HTTP requests.

## Architecture

```
DiscoveryPipeline.run()
  ├── AssetDiscoveryPipeline → AssetInventory (+ text_bodies)
  └── SensitiveIntelligenceEngine.build()
        ├── collect_text_assets()
        ├── DetectorRegistry → pluggable detectors
        ├── FindingTracker (deduplication + attribution)
        └── SensitiveIntelligenceReport
```

### Package layout

| Module | Responsibility |
|--------|----------------|
| `models.py` | Finding types, severity, confidence, report models |
| `sources.py` | Collect textual assets from discovery + inventory |
| `registry.py` | Pluggable detector registration |
| `detectors/` | Individual passive detectors (email, secrets, credentials, …) |
| `tracker.py` | Deduplication and multi-file merge |
| `evidence.py` | Evidence helpers (line numbers, offsets, counts) |
| `engine.py` | Orchestration |
| `report.py` | Full console output + export-ready models |
| `cli_display.py` | Fingerprint CLI filtering and concise rendering |

## Detector pipeline

1. **Collect assets** — JavaScript, JSON, CSS, manifests, maps, workers, XML, TXT, and other text bodies from downloads and `AssetInventory.text_bodies`. Binary assets (fonts, WASM, images) are skipped.
2. **Run detectors** — Each registered detector scans content independently.
3. **Attribute findings** — Every match records source file, URL, asset ID, line number, and byte offset.
4. **Deduplicate** — Identical values merge across files; occurrence count and confidence increase.
5. **Summarize** — Counts by category and severity feed the report.

## Supported detectors

| Detector | Finds |
|----------|-------|
| `EmailDetector` | Email addresses |
| `PhoneDetector` | Phone numbers |
| `UsernameDetector` | Usernames, application names, environment names |
| `UrlDetector` | External and internal URLs |
| `DomainDetector` | Domains, hostnames, subdomains |
| `IpDetector` | IPv4 and IPv6 |
| `UuidDetector` | UUID / GUID |
| `SecretDetector` | JWT, API keys, tokens, private keys, high-entropy secrets |
| `CredentialDetector` | Connection strings, DB URIs, passwords, env vars |
| `CommentDetector` | TODO, FIXME, HACK, BUG, NOTE, deprecated/debug markers |

## Confidence model

| Level | Score |
|-------|-------|
| Very High | ≥ 95 |
| High | ≥ 80 |
| Medium | ≥ 60 |
| Low | < 60 |

Multiple detections of the same value across files increase confidence slightly. High-entropy and base64 secret detection require elevated entropy thresholds to reduce false positives.

## Evidence model

Each `SensitiveFindingRecord` includes:

- Type, subtype, severity, confidence, confidence level
- Matched value (redacted for secrets) and matched pattern
- Detector name and evidence snippet
- Locations with file, URL, asset ID, line, offset
- Source files list and occurrence count

## Reporting

### Console

`discover` and `sensitive-intelligence` render the full finding set.

The `fingerprint` command uses a **filtered CLI view** that prioritizes security-relevant
findings only. Emails, phone numbers, domains, URLs, IPs, UUIDs, and usernames remain in
internal models and export payloads but are not printed to the terminal. Secrets,
credentials, and security markers (TODO/FIXME/HACK/debug) are shown.

```
==================================================
Sensitive Data Intelligence
==================================================

Summary
  Secrets: …
  Credentials: …
  Security Markers: …
  High Severity: …

Category | Value | Severity | Confidence | Source
...
```

Full console example (`discover` / `sensitive-intelligence`):

```
==================================================
Sensitive Data Intelligence
==================================================

Summary
  Emails: …
  Secrets: …
  High Severity: …

Type | Value | Severity | Confidence | Files | Occurrences | Detector
...
--------------------------------------------------
Type: secret / jwt-token
Matched Value: jwt-token [redacted]
Files:
  config.js
Line Numbers: 12
Evidence Count: 1
```

### Export models (internal)

`ReportSensitiveIntelligence`, `ReportSensitiveFinding`, and `Report.sensitive_intelligence` prepare JSON/HTML/SARIF/SBOM export without implementing exporters in this phase.

## CLI

```bash
techspecter sensitive-intelligence https://example.com
techspecter sensitive-intelligence https://example.com --json
techspecter discover https://example.com   # includes sensitive section when enabled
```

Configuration: `DiscoveryPipelineConfig.collect_sensitive_intelligence` (default: `true`).

## Examples

**Email in JavaScript bundle**

```
Type: email / email
Matched Value: admin@example.com
Files: app.js
```

**JWT in config**

```
Type: secret / jwt-token
Matched Value: jwt-token [redacted]
Severity: high
Confidence: 94%
```

## Extensibility

Register custom detectors without modifying the engine:

```python
from techspecter.sensitive_intelligence.registry import DetectorRegistry
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine

registry = DetectorRegistry()
registry.register(MyCustomDetector())
engine = SensitiveIntelligenceEngine(registry=registry)
```

## Known limitations

- Analysis uses already-downloaded content only; no re-fetching
- Binary assets are not scanned
- Company/developer name detection is limited to explicit key/value patterns
- Phone detection may produce low-confidence matches on numeric sequences
- Does not validate whether secrets are active or revoked

## Future improvements

- Integrate with artifact analyzers without duplicating patterns
- Entropy-based scoring calibration per asset type
- SARIF export with `physicalLocation` via asset IDs
- Configurable detector enable/disable per scan
- SBOM cross-reference for exposed package credentials

## Related documentation

- [Asset Discovery](ASSET_DISCOVERY.md) — Phase 7.1 inventory
- [Technology Intelligence](TECHNOLOGY_INTELLIGENCE.md) — Phase 7.2 evidence engine
