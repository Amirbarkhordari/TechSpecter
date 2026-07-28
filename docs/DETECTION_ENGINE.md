# Detection Engine

Phase 3 transforms collected evidence into explainable technology detections using a multi-stage passive pipeline.

## Pipeline Stages

```
Evidence Collection (Phase 1+2)
        ↓
Evidence Normalization
        ↓
Evidence Correlation
        ↓
Rule Evaluation
        ↓
Confidence Calculation
        ↓
Version Resolution
        ↓
Technology Detection
        ↓
Explainable Detection Output
```

## Correlation Engine

The correlation engine groups evidence by resource and source, applying bonuses when multiple independent evidence types support the same technology:

- Same-resource correlation
- Cross-resource correlation on one target
- Cross-domain evidence support
- Duplicate elimination via pipeline aggregator and detection filters

## Rule Engine

Technology signatures define modular rules without hardcoded framework logic:

| Rule group | Behavior |
|------------|----------|
| `required_rules` | All must match or detection is rejected |
| `positive_rules` | Contribute to score |
| `optional_rules` | Additional score contributors |
| `negative_rules` | Reject when matched without required confirmation |

Each signature also defines `minimum_score`, `priority`, `dependencies`, `aliases`, and `conflicts_with`.

## Confidence Engine

Confidence is calculated from weighted evidence — never fixed per technology:

| Evidence type | Default weight |
|---------------|----------------|
| Package metadata | 100 |
| Manifest | 95 |
| Runtime object | 90 |
| Build/metadata | 85 |
| HTML marker | 80 |
| Bundle metadata | 70 |
| Filename | 50 |
| Regex/weak | 20 |

Components are exposed in `TechnologyMatch.confidence_breakdown`.

## Version Resolution

Version candidates from Phase 2 are ranked by source reliability. The resolver:

1. Collects candidates linked to matched technology evidence
2. Applies technology-specific extractors when configured
3. Rejects invalid semver fragments
4. Returns `Unknown` when evidence is insufficient — never invents versions

## False Positive Reduction

- Minimum score thresholds per signature
- Weak-only evidence filtering
- Negative rule evaluation (e.g. Angular vs zone.js-only)
- Confidence threshold filtering
- Duplicate technology suppression

## False Negative Reduction

- Cross-source correlation bonuses
- Optional rules supplement required signals
- Dependencies auto-included (e.g. React when Next.js detected)
- Multiple evidence types combined into one detection

## Explainable Detection

Each `TechnologyMatch` includes:

- `detection_reason`
- `supporting_evidence_ids`
- `evidence_count`
- `matched_resources`
- `version_source` / `version_reason`
- `rejected_version_candidates`
- `confidence_breakdown`

## Conflict Resolution

- Higher-confidence detections prioritized
- `conflicts_with` signature metadata respected
- Dependencies ensured when parent technology detected
- Version deduplication per technology ID

## Extension Points

Plugins can register via `detection/plugins.py`:

- `DetectionRulePlugin` — custom signatures/rules
- `DetectionConfidencePlugin` — confidence adjustments
- `DetectionVersionPlugin` — custom version resolvers
- `DetectionValidatorPlugin` — evidence validators

## Usage

```python
from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer

layer = FingerprintCompatibilityLayer()
explainable = layer.analyze_explainable(discovery)
for match in explainable.detection.matches:
    print(match.technology.name, match.confidence, match.version)
```

## Known Limitations

- Token-based evidence matching is substring/regex oriented, not full AST correlation
- Version linking uses contextual heuristics when extractors are disabled
- Focused signature set (~14 technologies) — extend via registry/plugins rather than bulk JSON
- Server-side detections depend on header/HTML evidence collectors

## Phase 4 Preparation

- Evidence graph storage and cross-scan correlation
- ML-assisted scoring hooks (`ScoringEngine` component model)
- Signature migration tooling from legacy `Fingerprint` JSON
- Unified pipeline replacing parallel legacy/evidence detection paths
