# Signature Authoring Guide

## Principles

1. **Never rely on a single regex** — combine runtime, package, header, and bundle indicators
2. **Require strong signals** — use `required_rule()` or `required_evidence`
3. **Add negative evidence** for commonly confused technologies
4. **Include version extractors** when technology exposes version strings
5. **Document references** via `website` and `refs()`

## Using SignatureBuilder

```python
from techspecter.fingerprinting.signatures.catalog.builder import SignatureBuilder
from techspecter.fingerprinting.signatures.catalog.patterns import ind, req_regex, ver

signature = (
    SignatureBuilder(id="demo", name="Demo", category="frontend-frameworks")
    .required_rule(req_regex("demo", r"demo-runtime|demo-package"))
    .optional(
        runtime=(ind("runtime", "demo-runtime", weight=90),),
        package=(ind("pkg", "demo-package", weight=85),),
    )
    .negative(runtime=(ind("weak", "demo-weak-only", weight=10),))
    .versions(ver("demo-ver", r"demo[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)"))
    .build()
)
```

## Indicator Targets

| Target | Evidence Source |
|--------|-----------------|
| `runtime` | JavaScript runtime API patterns |
| `bundle` | Bundler runtime markers |
| `package` | npm/node_modules references |
| `header` | HTTP response headers |
| `html` | HTML elements and script references |
| `manifest` | Framework build manifests |
| `metadata` | Generator and build metadata |

## Quality Checklist

- [ ] At least 2 optional indicators across different evidence types
- [ ] Required rule prevents weak-only detection
- [ ] Version extractor configured or documented as unavailable
- [ ] Negative evidence for known false positive patterns
- [ ] Dependencies declared for meta-frameworks
