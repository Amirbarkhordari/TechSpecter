# Benchmark & Validation Subsystem

Phase 5 adds an **optional** Benchmark & Validation subsystem that compares TechSpecter against Wappalyzer to measure detection quality and guide improvements.

## Purpose

The benchmark subsystem:

- Runs TechSpecter and Wappalyzer **independently**
- Normalizes both outputs into a common structure
- Compares technologies, versions, categories, and confidence
- Produces actionable gap analysis and statistics
- **Never** modifies the production fingerprint pipeline

Normal fingerprinting remains unchanged:

```bash
techspecter fingerprint https://example.com
```

No Wappalyzer dependency is required for normal operation.

## Architecture

The benchmark package is completely independent from production detection code:

```
techspecter/benchmark/
├── models.py          # Normalized structures and comparison report models
├── normalizer.py      # TechSpecter + Wappalyzer → common format
├── wappalyzer.py      # Wappalyzer CLI execution and JSON import
├── comparator.py      # Side-by-side comparison engine
├── statistics.py      # Precision, recall, version metrics
├── gap_analysis.py    # Actionable improvement recommendations
├── runner.py          # Orchestrates independent scans
├── reporter.py        # Console, JSON, Markdown output
├── cli_handlers.py    # CLI integration helpers
└── utils.py           # Technology ID normalization
```

### Data Flow

```
URL
 ├─→ FingerprintService (TechSpecter) ─→ normalize ─┐
 └─→ Wappalyzer CLI or JSON import ───→ normalize ─┤
                                                     ├─→ compare → statistics → gap analysis → report
```

## CLI Usage

### Dedicated benchmark command

```bash
# Run both engines (Wappalyzer CLI if installed)
techspecter benchmark https://example.com

# Import existing Wappalyzer JSON report
techspecter benchmark https://example.com --wappalyzer-result report.json

# JSON output
techspecter benchmark https://example.com --wappalyzer-result report.json --json

# Markdown report to file
techspecter benchmark https://example.com --wappalyzer-result report.json --format markdown --output report.md
```

### Compare after fingerprint

```bash
techspecter fingerprint https://example.com --compare-wappalyzer

techspecter fingerprint https://example.com \
    --compare-wappalyzer \
    --wappalyzer-result report.json
```

## Wappalyzer Integration

Two supported methods:

### Method 1 — Automatic CLI execution

If `wappalyzer` or `npx @wappalyzer/wappalyzer` is available, the benchmark runner executes:

```bash
wappalyzer <url> --json
```

### Method 2 — JSON import

Provide a pre-generated Wappalyzer report:

```bash
techspecter benchmark https://example.com --wappalyzer-result report.json
```

Supported JSON formats:

- Wappalyzer CLI array output `[{ "url": "...", "technologies": [...] }]`
- Legacy `urls` object format
- Direct `technologies` / `applications` arrays

## Report Sections

| Section | Description |
|---------|-------------|
| Summary | Matched, missing, extra counts and key metrics |
| Matched Technologies | Detected by both engines |
| Missing Technologies | Wappalyzer only (false negatives) |
| Extra Technologies | TechSpecter only (potential false positives) |
| Version Comparison | Match, Unknown, different versions |
| Gap Analysis | Actionable improvement recommendations |

## Statistics

| Metric | Description |
|--------|-------------|
| Technology Precision | Matched / TechSpecter total |
| Technology Recall | Matched / Wappalyzer total |
| Version Match Rate | Exact version matches / shared technologies |
| Version Accuracy | Correct or unverifiable versions / resolved comparisons |
| Coverage % | Matched / Wappalyzer total |
| Extra Detections | TechSpecter-only technologies |
| Missing Detections | Wappalyzer-only technologies |

## Improving Detection Using Benchmark Reports

1. **Missing technologies** — Add runtime detectors, manifest rules, or HTTP header patterns
2. **Unknown versions** — Improve version extractors in the signature catalog
3. **Version mismatches** — Review version resolution priorities and candidate linking
4. **Extra detections** — Add negative evidence or raise minimum score thresholds
5. **Gap analysis suggestions** — Follow per-technology recommendations in the report

## Example Workflow

```bash
# 1. Run Wappalyzer separately (optional)
wappalyzer https://react.dev --json > wappalyzer-react.json

# 2. Benchmark against TechSpecter
techspecter benchmark https://react.dev --wappalyzer-result wappalyzer-react.json --format markdown --output benchmark.md

# 3. Review gap analysis section in benchmark.md
# 4. Improve signatures/extractors based on recommendations
# 5. Re-run benchmark to validate improvements
```

## Tests

See `tests/test_benchmark_validation.py` for coverage of:

- Normalization (TechSpecter + Wappalyzer formats)
- Comparison and version analysis
- Statistics calculation
- Gap analysis
- JSON import
- CLI integration

## Important Constraints

- Benchmark code does **not** import into production detection pipelines
- Wappalyzer is **never** part of normal fingerprint output
- The benchmark runner uses `FingerprintService` independently — production code is unchanged
