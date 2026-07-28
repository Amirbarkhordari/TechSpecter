# Phase 4.5 — Detection Quality Engine

Phase 4.5 improves detection accuracy without changing the overall architecture, CLI, or pipeline stages.

## Goals

- Accurate version detection from all available evidence
- Duplicate suppression (one detection per technology)
- Calibrated, stable confidence scoring
- Cross-resource and cross-file evidence correlation
- Explainable version resolution

## Version Candidate Engine

Every analyzer contributes version candidates. Candidates are **never discarded during extraction**.

Sources include:

| Source | Priority |
|--------|----------|
| Package metadata | 100 |
| Runtime API | 95 |
| Manifest | 90 |
| Build metadata | 85 |
| Source map | 80 |
| License banner | 75 |
| Comment | 65 |
| Filename | 40 |
| Regex | 20 |

Implementation: `techspecter/fingerprinting/detection/version/candidates.py`

## Version Resolution Engine

The resolver:

1. Collects all candidates for a technology
2. Normalizes and validates versions
3. Ranks by source priority and cross-source agreement
4. Resolves conflicts (never invents versions)
5. Returns version, confidence, source, reason, and rejected candidates

Implementation: `techspecter/fingerprinting/detection/version_resolver.py`

## Duplicate Suppression

`TechnologyMerger` merges detections sharing a technology ID:

- Combines evidence IDs and matched resources
- Preserves highest confidence with multi-resource bonus
- Ensures pipeline output contains exactly one row per technology

Implementation: `techspecter/fingerprinting/detection/merger.py`

## Confidence Calibration

`ConfidenceEngine.calibrate()` adjusts confidence based on:

- Independent evidence source agreement (+)
- Cross-resource correlation (+)
- Known version with high version confidence (+)
- Version conflicts (-)
- Negative evidence (-)

## Cross-File Correlation

Version candidates are pooled from all evidence items (HTML, JS, bundles, source maps, manifests, headers). Candidates link to technologies via:

- Explicit `technology` metadata
- Package/runtime family hints
- Matched resource overlap
- Signature version extractors

## Reporting

Reports include:

- Winning version and version source
- Version confidence
- Evidence count
- Detection reason

No duplicate technology rows are emitted.

## Tests

See `tests/test_detection_quality.py` for coverage of:

- Version resolution
- Duplicate suppression
- Cross-file correlation
- Manifest and source map resolution
- Runtime version extraction
- Conflict resolution
- Confidence calibration
