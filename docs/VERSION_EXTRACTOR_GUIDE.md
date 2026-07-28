# Version Extractor Guide

Version extractors resolve Phase 2 `VERSION_CANDIDATE` evidence into technology versions during Phase 3 detection.

## VersionExtractorSpec Fields

| Field | Description |
|-------|-------------|
| `id` | Unique extractor identifier |
| `pattern` | Regex with capture group for version |
| `source` | Preferred evidence source (`banner`, `package`, `metadata`, `header`) |
| `weight` | Ranking weight (higher = preferred) |
| `enabled` | Whether extractor is active |

## Example

```json
{
  "id": "react-version",
  "pattern": "react[^0-9]*([0-9]+\\.[0-9]+\\.[0-9]+)",
  "source": "banner",
  "weight": 90.0,
  "enabled": true
}
```

## Source Priority

1. Package metadata (100)
2. Banner / license headers (90)
3. Manifest metadata (85)
4. Runtime markers (75)
5. Generic content (60)

## Rules

- Never invent versions — return `Unknown` when evidence is insufficient
- Use technology-specific patterns, not generic semver-only matching
- Reject invalid semver fragments
- Track rejected candidates in explainable output
