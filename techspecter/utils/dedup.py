"""Duplicate removal utilities for discovered resources."""

from __future__ import annotations

from techspecter.models.discovery import ScriptResource
from techspecter.utils.url import normalize_url


def deduplicate_scripts(scripts: list[ScriptResource]) -> list[ScriptResource]:
    """Remove duplicate external script resources by normalized URL.

    The first occurrence of each unique URL is preserved.

    Args:
        scripts: Discovered external script resources.

    Returns:
        Deduplicated list of script resources.
    """
    seen: set[str] = set()
    unique: list[ScriptResource] = []

    for script in scripts:
        key = normalize_url(str(script.url))
        if key in seen:
            continue
        seen.add(key)
        unique.append(script)

    return unique
