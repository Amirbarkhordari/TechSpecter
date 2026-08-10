# Secret & Sensitive Intelligence Engine (Phase 8)

Phase 8 delivers a production-grade **Secret & Sensitive Intelligence Engine** that passively analyzes assets already collected by TechSpecter. It does **not** perform vulnerability scanning, exploitation, active probing, or additional downloads.

## Architecture

```
DiscoveryPipeline.run()
  ├── AssetDiscoveryPipeline → AssetInventory (+ text_bodies)
  └── SensitiveIntelligenceEngine.build()
        ├── collect_text_assets()          # reuse downloaded assets only
        ├── extract_javascript_config_snippets()
        ├── DetectorRegistry → DetectorMatch (evidence only)
        ├── correlate_credential_pairs() → DetectorMatch (evidence only)
        ├── SensitiveCandidateValidator
        │     ├── build SensitiveCandidate
        │     ├── ContextAnalyzer / ValueAnalyzer
        │     ├── positive / negative evidence
        │     └── SensitiveMatchQualityGate
        ├── FindingTracker (confirmed candidates only; dedupe + attribution)
        └── SensitiveIntelligenceReport
```

`DetectorMatch` is **not** automatically a confirmed finding. Confirmation requires the
candidate validation spine (`candidates/`).

### Candidate validation spine

| Module | Responsibility |
|--------|----------------|
| `candidates/models.py` | `SensitiveCandidate`, evidence enums, `ValueStrength`, `ContextKind`, `SensitiveCorrelation` |
| `candidates/builder.py` | `DetectorMatch` → candidate (+ credential name for correlation) |
| `candidates/context.py` | Static / runtime / empty / placeholder / docs / fixture / form context |
| `candidates/value.py` | Empty / placeholder / weak / runtime / provider / realistic classification |
| `candidates/placeholders.py` | Centralized placeholder normalization + detection |
| `candidates/runtime.py` | Centralized runtime / self / empty / form / template detection |
| `candidates/policies.py` | Detector-specific confirmation requirements (consume evidence, no re-parsing) |
| `candidates/correlation.py` | Candidate-scoped correlation (username/password, client, AWS, token, DB) |
| `candidates/severity.py` | Central confidence/severity calibration after validation/correlation |
| `candidates/validator.py` | Confirmation policy + negative-evidence precedence |
| `candidates/quality_gate.py` | Final confirm / reject / candidate-only gate |

**Flow:** detectors emit `DetectorMatch` → candidates are validated → eligible candidates are
correlated within the same asset/source/proximity scope → severity is calibrated → only
confirmed candidates enter `FindingTracker`.

**Correlation** is evidence, not automatic confirmation. Weak/placeholder/runtime pairs cannot
escalate to Critical merely because related fields are nearby. Strong pairs add
`CORRELATION` / `CREDENTIAL_PAIR` evidence and may emit a single deduplicated pair finding.

**Detector policies** declare minimum value strength, disqualifying negatives, candidate-only
allowance, and severity floors/ceilings per rule family (generic password, JWT/PEM/AWS,
internal config, contact). Policies do not duplicate JWT/PEM/AWS/GitHub/entropy validators.

### Package layout

| Module | Responsibility |
|--------|----------------|
| `models.py` | Finding types, categories, severity, confidence, report models |
| `candidates/` | Candidate validation spine (see above) |
| `rules/` | Extensible rule engine (`DetectionRule`, validators, catalog, `RuleEngine`) |
| `javascript_intel.py` | Extract `window.__NEXT_DATA__`, `__INITIAL_STATE__`, `process.env`, etc. |
| `correlator.py` | Legacy regex helper + export of `CandidateCorrelator` |
| `registry.py` | Pluggable detector registration |
| `engine.py` | Orchestration |
| `tracker.py` | Deduplicate confirmed findings only |
| `report.py` | Full CLI section: **Secret & Sensitive Intelligence** |
| `cli_display.py` | Fingerprint CLI filtering and concise rendering |
| `display_utils.py` | Safe Rich markup escaping for evidence output |

## Rule engine

Rules are declarative and extensible. Each `DetectionRule` includes:

| Field | Purpose |
|-------|---------|
| `rule_id` | Stable identifier |
| `name` | Human-readable name |
| `category` | `secrets`, `credentials`, `sensitive_configuration`, `developer_artifacts` |
| `pattern` | Compiled regular expression |
| `severity` | `critical`, `high`, `medium`, `low`, `informational` |
| `confidence` | Base confidence score (0–100) |
| `description` | What was found |
| `recommendation` | Remediation guidance |
| `validator` | Optional callable to reduce false positives |

Add a rule without modifying the engine:

```python
from techspecter.sensitive_intelligence.rules.engine import RuleEngine
from techspecter.sensitive_intelligence.rules.models import DetectionRule, RuleCategory

engine = RuleEngine()
engine.register(my_rule)
```

Built-in catalog: `techspecter/sensitive_intelligence/rules/catalog.py` (40+ rules).

## Supported categories

### Secrets

AWS keys, Google/Firebase API keys, GitHub/GitLab tokens, Azure keys, Stripe/Twilio/Slack/Discord/OpenAI/Anthropic keys, JWT, bearer/basic/session tokens, PEM/RSA/SSH private keys, certificates, GCP service accounts, generic API keys, high-entropy secrets.

### Credentials

MongoDB/PostgreSQL/MySQL/Redis/LDAP/SMTP URIs, hardcoded usernames/passwords, connection strings, correlated username/password pairs.

### Sensitive configuration

Internal/admin/debug/staging/backup endpoints, internal IPs and hostnames, feature flags, environment configuration (`process.env`, `REACT_APP_*`).

### Developer artifacts

TODO, FIXME, BUG, HACK, NOTE, XXX, stack traces, debug markers, `console.debug` statements.

## JavaScript intelligence

The engine recursively inspects extracted configuration from:

- `window.__NEXT_DATA__`
- `window.__INITIAL_STATE__`
- `window.__ENV__`
- `window.config`
- `runtimeConfig`
- `process.env.*`

Extracted JSON values are scanned for sensitive keys and secret-like values.

## Evidence model

Every finding includes:

- Category, finding type, subtype, severity, confidence, confidence level
- Source file, relative path, asset ID, line number, column, byte offset
- Matched pattern, matched value (redacted for secrets), evidence snippet
- Rule metadata (`rule_id`, `rule_name`, description, recommendation)

## Validation

Optional validators in `rules/validators.py`:

- JWT structure and header decode
- PEM private key / certificate headers
- AWS access key format
- GitHub token format

Validated matches receive a small confidence boost; invalid matches are discarded.

## Reporting

### Default CLI output

The **Secret & Sensitive Intelligence** section uses dot-aligned summaries:

```
Secrets ..................... 0
Credentials ................. 0
Sensitive Configuration ..... 3
Developer Artifacts ......... 0
```

Findings are **grouped by category** with compact list entries, followed by **Detailed Findings** blocks containing severity, confidence, source file, asset ID, line number, matched value, context snippet, and recommendation.

Values are normalized (trimmed, control characters removed, max 100 characters with `...` truncation). Duplicate findings are merged with occurrence count and affected files.

### Asset Inventory CLI

Fingerprint scans show a concise asset summary by default. Use `--show-assets` or `--verbose` to print the full asset table. Failed downloads are grouped by reason (404, 403, Timeout, Connection Error, etc.).

### Security Summary

When sensitive findings exist, the Security Summary section reports them instead of printing "No passive security findings reported."

### Fingerprint CLI

The fingerprint command shows security-relevant findings only (secrets, credentials, sensitive configuration, security-related developer markers). Contact information (emails, phones, domains) is hidden from the fingerprint CLI but preserved in export models.

## Performance

- Reuses `AssetInventory.text_bodies` and existing downloads — no re-fetching
- Skips binary assets (images, fonts, WASM)
- Deduplicates identical values across files

## Testing

| Test file | Coverage |
|-----------|----------|
| `tests/test_sensitive_intelligence.py` | Core detectors, engine, export |
| `tests/test_sensitive_rule_engine.py` | Rule engine, validators, JS intel, correlation |
| `tests/test_fingerprint_cli_display.py` | Fingerprint CLI filters |
| `tests/test_cli_report_rendering.py` | CLI summaries, grouping, value trimming, security summary |

Run:

```bash
python -m pytest tests/test_sensitive_intelligence.py tests/test_sensitive_rule_engine.py -v
```

## Limitations

- No active secret validation (revocation checks) — passive pattern matching only
- Legacy `techspecter sensitive` artifact analyzers remain separate from this engine
- SARIF/HTML export wiring for sensitive findings is prepared but not fully integrated into `ReportEngine`
- Entropy-based detection may still produce low-confidence findings on minified bundles

## Related docs

- [Asset Discovery](ASSET_DISCOVERY.md) — upstream asset pipeline (Phase 7.1)
- [Technology Intelligence](TECHNOLOGY_INTELLIGENCE.md) — sibling Phase 7.2 module
