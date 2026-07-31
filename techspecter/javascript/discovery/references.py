"""Passive JavaScript URL reference extraction from content."""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import urljoin

from techspecter.javascript.models import DiscoveredReference, DiscoverySource, ModuleType
from techspecter.utils.url import normalize_url, resolve_url
from techspecter.utils.validation import build_script_resource

logger = logging.getLogger(__name__)

_JS_SUFFIX = re.compile(r"\.(?:mjs|cjs|js)(?:\?[^{'\"\\s]*)?$", re.IGNORECASE)
_DYNAMIC_IMPORT = re.compile(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)""")
_STATIC_IMPORT = re.compile(
    r"""^\s*import\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_EXPORT_FROM = re.compile(
    r"""^\s*export\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_SCRIPT_SRC_STRING = re.compile(r"""['"]([^'"]+\.(?:js|mjs|cjs)(?:\?[^{'\"\\s]*)?)['"]""")
_WEBPACK_CHUNK = re.compile(
    r"""['"]([^'"]*(?:\.chunk\.|/chunks/|chunk-)[^'"]*\.js(?:\?[^{'\"\\s]*)?)['"]""",
    re.IGNORECASE,
)
_WEBPACK_PUBLIC = re.compile(
    r"""__webpack_require__\.(?:p|u)\s*\+\s*['"]([^'"]+)['"]""",
)
_WEBPACK_ENSURE = re.compile(
    r"""__webpack_require__\.e\s*\(\s*['"]?([^'")\s]+)['"]?\s*\)""",
)
_VITE_DYNAMIC = re.compile(r"""import\s*\(\s*['"]\./([^'"]+)['"]\s*\)""")
_MANIFEST_JSON = re.compile(
    r"""['"]([^'"]*(?:manifest|chunks)[^'"]*\.json(?:\?[^{'\"\\s]*)?)['"]""",
    re.IGNORECASE,
)
_WORKER_REGISTER = re.compile(
    r"""new\s+(?:Shared)?Worker\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def extract_references_from_content(
    content: str,
    *,
    base_url: str,
    parent_url: str | None = None,
    source: DiscoverySource = DiscoverySource.SCRIPT_REFERENCE,
) -> list[DiscoveredReference]:
    """Extract passive JavaScript references from script content."""
    references: list[DiscoveredReference] = []
    seen: set[str] = set()

    def add(
        raw: str, ref_source: DiscoverySource, module_type: ModuleType = ModuleType.UNKNOWN
    ) -> None:
        candidate = raw.strip()
        if not candidate or candidate.startswith("data:"):
            return
        if not _looks_like_js(candidate) and ref_source not in {
            DiscoverySource.WEBPACK_CHUNK,
            DiscoverySource.DYNAMIC_IMPORT,
        }:
            return
        try:
            absolute = resolve_url(base_url, candidate)
            key = normalize_url(absolute)
        except Exception as exc:
            logger.debug("Skipping invalid JS reference %r: %s", candidate, exc)
            return
        if key in seen:
            return
        seen.add(key)
        resource = build_script_resource(url=absolute, original_url=candidate)
        references.append(
            DiscoveredReference(
                url=resource.url,
                original_reference=candidate,
                source=ref_source,
                module_type=module_type,
                parent_url=parent_url,
            ),
        )

    for pattern, ref_source in (
        (_DYNAMIC_IMPORT, DiscoverySource.DYNAMIC_IMPORT),
        (_STATIC_IMPORT, DiscoverySource.SCRIPT_REFERENCE),
        (_EXPORT_FROM, DiscoverySource.SCRIPT_REFERENCE),
        (_WEBPACK_CHUNK, DiscoverySource.WEBPACK_CHUNK),
        (_WEBPACK_PUBLIC, DiscoverySource.WEBPACK_CHUNK),
        (_SCRIPT_SRC_STRING, source),
        (_VITE_DYNAMIC, DiscoverySource.DYNAMIC_IMPORT),
        (_WORKER_REGISTER, DiscoverySource.WORKER),
    ):
        for match in pattern.finditer(content):
            add(match.group(1), ref_source)

    for match in _WEBPACK_ENSURE.finditer(content):
        chunk_id = match.group(1)
        add(f"{chunk_id}.js", DiscoverySource.WEBPACK_CHUNK)

    for match in _MANIFEST_JSON.finditer(content):
        manifest_ref = match.group(1)
        references.extend(
            extract_manifest_references(
                manifest_ref,
                base_url=base_url,
                parent_url=parent_url,
            ),
        )

    return references


def extract_manifest_references(
    manifest_path: str,
    *,
    base_url: str,
    parent_url: str | None = None,
) -> list[DiscoveredReference]:
    """Extract JS paths from a manifest path reference (when content unavailable)."""
    references: list[DiscoveredReference] = []
    try:
        absolute = resolve_url(base_url, manifest_path)
        key = normalize_url(absolute)
        resource = build_script_resource(url=absolute, original_url=manifest_path)
        references.append(
            DiscoveredReference(
                url=resource.url,
                original_reference=manifest_path,
                source=DiscoverySource.BUNDLE_MANIFEST,
                parent_url=parent_url,
            ),
        )
        _ = key
    except Exception:
        pass
    return references


def extract_references_from_manifest_json(
    manifest_json: str,
    *,
    base_url: str,
    parent_url: str | None = None,
) -> list[DiscoveredReference]:
    """Parse build/asset manifest JSON and extract JavaScript file paths."""
    references: list[DiscoveredReference] = []
    seen: set[str] = set()

    try:
        data = json.loads(manifest_json)
    except json.JSONDecodeError:
        return references

    paths = _collect_paths_from_json(data)
    for path in paths:
        if not _looks_like_js(path):
            continue
        try:
            absolute = resolve_url(base_url, path)
            key = normalize_url(absolute)
        except Exception:
            continue
        if key in seen:
            continue
        seen.add(key)
        resource = build_script_resource(url=absolute, original_url=path)
        references.append(
            DiscoveredReference(
                url=resource.url,
                original_reference=path,
                source=DiscoverySource.BUNDLE_MANIFEST,
                parent_url=parent_url,
            ),
        )
    return references


def _collect_paths_from_json(data: object) -> list[str]:
    """Recursively collect string paths from manifest JSON."""
    paths: list[str] = []
    if isinstance(data, str):
        paths.append(data)
    elif isinstance(data, dict):
        for key, value in data.items():
            if key in {"file", "src", "path", "js", "css"} and isinstance(value, str):
                paths.append(value)
            paths.extend(_collect_paths_from_json(value))
    elif isinstance(data, list):
        for item in data:
            paths.extend(_collect_paths_from_json(item))
    return paths


def _looks_like_js(reference: str) -> bool:
    """Return whether a reference likely points to JavaScript."""
    lowered = reference.lower()
    if lowered.endswith((".js", ".mjs", ".cjs")):
        return True
    if ".js?" in lowered or ".mjs?" in lowered:
        return True
    if "/chunks/" in lowered or ".chunk." in lowered:
        return True
    if _JS_SUFFIX.search(reference):
        return True
    return bool(re.search(r"chunk[-.]?\w+\.js", reference, re.IGNORECASE))


def resolve_manifest_base(base_url: str, manifest_url: str) -> str:
    """Resolve base URL for manifest-relative paths."""
    if manifest_url.endswith(".json"):
        return manifest_url.rsplit("/", 1)[0] + "/"
    return urljoin(base_url + "/", "")
