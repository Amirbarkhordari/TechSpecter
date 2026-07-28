# TechSpecter Roadmap

TechSpecter follows semantic versioning. The first stable release target is **v1.0.0**, preceded by release candidates.

## Current Release

**v1.0.0-rc1** — Release Candidate 1

Focus: production-ready passive analysis framework with fingerprinting, HTTP/metadata/artifact intelligence, plugin SDK, performance hardening, and open-source release engineering.

## Completed Phases

| Phase | Focus | Status |
|---|---|---|
| 1 | Project bootstrap, CLI, plugins, CI | ✅ |
| 2 | JavaScript discovery engine | ✅ |
| 3 | Fingerprinting core and database expansion | ✅ |
| 4 | Reporting engine (JSON, Markdown, HTML, CSV, SARIF) | ✅ |
| 4.5 | Generic analysis framework | ✅ |
| 5 | Plugin SDK and extended analyzers | ✅ |
| 6 | Passive HTTP and metadata intelligence | ✅ |
| 7 | Cloud, identity, API, and sensitive artifact intelligence | ✅ |
| 8 | Performance, scalability, production hardening | ✅ |
| 9 | Release engineering, CI/CD, open-source readiness | ✅ |

## Upcoming

### v1.0.0 Stable

- Final RC validation and community feedback
- PyPI publication
- Signed release artifacts and SBOM attachments
- Documentation polish from RC feedback

### Post-1.0 (Planned)

- Additional passive analyzers via plugin ecosystem
- Enhanced report templates and dashboards
- Optional rule pack marketplace patterns
- Improved large-target performance profiles

## Non-Goals

TechSpecter will **not** include:

- Active vulnerability scanning or exploitation
- Brute force, credential stuffing, or password attacks
- Port scanning or network enumeration beyond target HTTP(S) resources
- Telemetry or phone-home analytics

## Contributing to the Roadmap

Open a [GitHub Discussion](https://github.com/Amirbarkhordari/TechSpecter/discussions) to propose features. See [CONTRIBUTING.md](CONTRIBUTING.md) for implementation guidelines.
