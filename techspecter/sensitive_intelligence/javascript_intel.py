"""JavaScript configuration object extraction for sensitive intelligence."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

_JS_ASSIGNMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"window\.__NEXT_DATA__\s*=\s*(\{.*?\})\s*;?", re.S),
    re.compile(r"window\.__INITIAL_STATE__\s*=\s*(\{.*?\})\s*;?", re.S),
    re.compile(r"window\.__ENV__\s*=\s*(\{.*?\})\s*;?", re.S),
    re.compile(r"window\.config\s*=\s*(\{.*?\})\s*;?", re.S),
    re.compile(r"runtimeConfig\s*=\s*(\{.*?\})\s*;?", re.S),
    re.compile(r"__NEXT_DATA__\s*=\s*(\{.*?\})\s*;?", re.S),
)

_SENSITIVE_KEY = re.compile(
    r"(?:token|secret|password|api[_-]?key|credential|auth|private[_-]?key)",
    re.I,
)


def extract_javascript_config_snippets(content: str) -> list[str]:
    """Extract serialized JavaScript configuration objects for analysis."""
    snippets: list[str] = []
    seen: set[str] = set()
    for pattern in _JS_ASSIGNMENT_PATTERNS:
        for match in pattern.finditer(content):
            raw = match.group(1).strip()
            if raw in seen:
                continue
            seen.add(raw)
            snippets.append(raw)
            snippets.extend(_flatten_json_values(raw))
    snippets.extend(_scan_process_env_assignments(content))
    return snippets


def _scan_process_env_assignments(content: str) -> list[str]:
    results: list[str] = []
    for match in re.finditer(r"process\.env\.([A-Z0-9_]+)", content):
        results.append(match.group(0))
    return results


def _flatten_json_values(raw: str) -> list[str]:
    """Recursively flatten JSON object values into inspectable strings."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return list(_walk_json(parsed))


def _walk_json(value: object, *, path: str = "") -> Iterator[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if isinstance(nested, (dict, list)):
                yield from _walk_json(nested, path=key_path)
            elif _SENSITIVE_KEY.search(str(key)):
                yield f"{key_path}={nested!r}"
            elif isinstance(nested, str) and len(nested) >= 8:
                yield str(nested)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _walk_json(nested, path=f"{path}[{index}]")
    elif isinstance(value, str) and _SENSITIVE_KEY.search(path):
        yield str(value)
