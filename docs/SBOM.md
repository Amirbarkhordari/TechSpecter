# Software Bill of Materials (SBOM)

TechSpecter supports supply chain transparency through CycloneDX and SPDX SBOM generation.

## Formats

| Format | Output File | Standard |
|---|---|---|
| CycloneDX | `techspecter.cyclonedx.json` | CycloneDX 1.5 JSON |
| SPDX | `techspecter.spdx.json` | SPDX 2.3 JSON |

## Generate Locally

Install SBOM dependencies:

```bash
pip install -e ".[sbom]"
```

Generate SBOMs:

```bash
python tools/generate_sbom.py --output-dir dist/sbom
```

Output:

```
dist/sbom/techspecter.cyclonedx.json
dist/sbom/techspecter.spdx.json
```

## CI Generation

The [SBOM workflow](../.github/workflows/sbom.yml) generates artifacts on pushes to `main` and version tags. Download SBOM files from GitHub Actions artifacts.

## When to Generate

- Before publishing a release
- After dependency updates
- For compliance and security audit requests

## Supply Chain Recommendations

1. Pin dependencies in production (`pip freeze` or lock files)
2. Review Dependabot pull requests promptly
3. Enable GitHub secret scanning and push protection on the repository
4. Verify release artifacts against SBOM component lists
5. Install from tagged releases or PyPI — not unverified forks

## Limitations

Generated SBOMs reflect **runtime dependencies installed in the active environment** at generation time. For reproducible release SBOMs, generate from a clean virtual environment after `pip install .`.

## Related

- [SECURITY.md](../SECURITY.md)
- [Dependency Review workflow](../.github/workflows/dependency-review.yml)
