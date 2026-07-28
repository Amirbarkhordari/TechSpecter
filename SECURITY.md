# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Release candidates (`1.0.0rc*`) receive security fixes on a best-effort basis until stable `1.0.0` is published.

## Reporting a Vulnerability

TechSpecter takes security seriously. **Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's **Private vulnerability reporting** on the repository:

https://github.com/Amirbarkhordari/TechSpecter/security/advisories/new

If private reporting is unavailable, email the maintainers with:

- A clear description of the issue
- Steps to reproduce
- Impact assessment
- Suggested remediation (if available)

## Responsible Disclosure

We ask that you:

1. Give maintainers reasonable time to investigate and patch (typically 90 days)
2. Avoid accessing, modifying, or deleting data that is not yours
3. Do not perform denial-of-service, social engineering, or physical attacks
4. Do not publicly disclose the issue until a fix is available or coordinated disclosure ends

We will acknowledge receipt within **5 business days** and provide a status update within **14 business days**.

## Scope

In scope:

- TechSpecter core package (`techspecter/`)
- Official CLI commands and bundled plugins
- Supply chain artifacts published from this repository

Out of scope:

- Third-party websites analyzed by TechSpecter
- Misuse of passive analysis output
- Issues requiring physical access to maintainer systems

## Secure Development Practices

This repository uses:

- **Dependabot** for dependency updates
- **Dependency Review** on pull requests
- **CodeQL** static analysis
- **Secret scanning** (GitHub native — enable in repository settings)
- **SBOM generation** for supply chain transparency (see [docs/SBOM.md](docs/SBOM.md))

## Supply Chain Recommendations

When deploying TechSpecter:

- Install from verified PyPI releases or signed tags
- Pin dependencies in production environments
- Review SBOM artifacts attached to releases
- Run `techspecter doctor` after installation to verify the environment
- Do not commit credentials, API keys, or `.env` files

## Telemetry

TechSpecter does **not** include telemetry, analytics, or phone-home behavior.
