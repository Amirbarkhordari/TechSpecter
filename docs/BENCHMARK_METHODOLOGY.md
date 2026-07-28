# Benchmark Methodology

## Purpose

Measure TechSpecter signature intelligence quality against expected detections and estimated competitor baselines.

## Metrics

| Metric | Definition |
|--------|------------|
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 Score | Harmonic mean of precision and recall |
| Version Accuracy | Correct version / total version expectations |
| Explainability | Detections with reason + supporting evidence |

## Regression Dataset

Samples in `signatures/regression/dataset.json` define:

- Synthetic evidence representing real-world stacks
- Expected technology IDs
- Optional expected versions

## Competitor Baselines

Static estimated baselines for:

- Wappalyzer
- BuiltWith
- WhatRuns
- FingerprintJS (technology detection subset)

Baselines are comparative references, not live API integrations.

## Running Benchmarks

```bash
python -m pytest tests/test_signature_platform.py -v -k benchmark
```

Or programmatically:

```python
from techspecter.fingerprinting.signatures.benchmark import BenchmarkRunner, render_benchmark_report

print(render_benchmark_report(BenchmarkRunner().run()))
```

## Regression Testing

Regression tests fail when:

- Expected technologies are not detected (false negatives increase)
- False positives appear on negative samples (e.g. zone.js-only)
- Signature count drops below platform minimum
