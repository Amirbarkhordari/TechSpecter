"""HTML-based JavaScript discovery sources."""

from __future__ import annotations

import json
import logging

from bs4 import BeautifulSoup
from bs4.element import Tag

from techspecter.javascript.models import DiscoveredReference, DiscoverySource, ModuleType
from techspecter.parser.html_parser import HtmlParseResult, HtmlScriptParser
from techspecter.utils.url import resolve_url
from techspecter.utils.validation import build_script_resource

logger = logging.getLogger(__name__)

_SCRIPT_MODULE = {"module"}
_LINK_SCRIPT_HINTS = {
    "modulepreload": (DiscoverySource.LINK_MODULEPRELOAD, ModuleType.MODULE),
    "preload": (DiscoverySource.LINK_PRELOAD, ModuleType.CLASSIC),
    "prefetch": (DiscoverySource.LINK_PREFETCH, ModuleType.UNKNOWN),
}


def discover_from_html(
    html: str,
    *,
    base_url: str,
    html_parser: HtmlScriptParser | None = None,
) -> tuple[HtmlParseResult, list[DiscoveredReference]]:
    """Discover JavaScript references from HTML using extended passive sources."""
    parser = html_parser or HtmlScriptParser()
    parse_result = parser.parse(html, base_url=base_url)
    references: list[DiscoveredReference] = []

    for script in parse_result.external_scripts:
        references.append(
            DiscoveredReference(
                url=script.url,
                original_reference=script.original_url,
                source=DiscoverySource.HTML_SCRIPT,
                module_type=ModuleType.CLASSIC,
            ),
        )

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception as exc:
        logger.warning("Extended HTML discovery failed: %s", exc)
        return parse_result, references

    references.extend(_discover_script_tags(soup, base_url=base_url))
    references.extend(_discover_link_hints(soup, base_url=base_url))
    references.extend(_discover_import_maps(soup, base_url=base_url))
    references.extend(_discover_workers(soup, base_url=base_url))

    return parse_result, references


def _discover_script_tags(soup: BeautifulSoup, *, base_url: str) -> list[DiscoveredReference]:
    """Discover module, async, and deferred script references."""
    references: list[DiscoveredReference] = []
    for script_tag in soup.find_all("script"):
        if not isinstance(script_tag, Tag):
            continue
        src = script_tag.get("src")
        if src is None:
            continue
        src_value = str(src).strip()
        if not src_value:
            continue

        script_type = str(script_tag.get("type", "")).strip().lower()
        module_type = ModuleType.MODULE if script_type in _SCRIPT_MODULE else ModuleType.CLASSIC
        source = DiscoverySource.HTML_SCRIPT
        if script_tag.has_attr("async"):
            source = DiscoverySource.HTML_ASYNC
        elif script_tag.has_attr("defer"):
            source = DiscoverySource.HTML_DEFERRED
        elif module_type == ModuleType.MODULE:
            source = DiscoverySource.HTML_MODULE

        try:
            absolute = resolve_url(base_url, src_value)
            resource = build_script_resource(url=absolute, original_url=src_value)
        except Exception as exc:
            logger.debug("Skipping script tag src %r: %s", src_value, exc)
            continue

        references.append(
            DiscoveredReference(
                url=resource.url,
                original_reference=src_value,
                source=source,
                module_type=module_type,
            ),
        )
    return references


def _discover_link_hints(soup: BeautifulSoup, *, base_url: str) -> list[DiscoveredReference]:
    """Discover modulepreload, preload, and prefetch script references."""
    references: list[DiscoveredReference] = []
    for link in soup.find_all("link"):
        if not isinstance(link, Tag):
            continue
        rel_values = _normalize_rel(link.get("rel"))
        href = link.get("href")
        if href is None:
            continue
        href_value = str(href).strip()
        if not href_value:
            continue

        as_attr = str(link.get("as", "")).strip().lower()
        for rel in rel_values:
            if rel not in _LINK_SCRIPT_HINTS:
                continue
            if (
                rel in {"preload", "prefetch"}
                and as_attr not in {"", "script", "module"}
                and not href_value.endswith((".js", ".mjs", ".cjs"))
            ):
                continue
            source, module_type = _LINK_SCRIPT_HINTS[rel]
            try:
                absolute = resolve_url(base_url, href_value)
                resource = build_script_resource(url=absolute, original_url=href_value)
            except Exception as exc:
                logger.debug("Skipping link hint %r: %s", href_value, exc)
                continue
            references.append(
                DiscoveredReference(
                    url=resource.url,
                    original_reference=href_value,
                    source=source,
                    module_type=module_type,
                ),
            )
    return references


def _discover_import_maps(soup: BeautifulSoup, *, base_url: str) -> list[DiscoveredReference]:
    """Discover JavaScript URLs from import maps."""
    references: list[DiscoveredReference] = []
    for script_tag in soup.find_all("script"):
        if not isinstance(script_tag, Tag):
            continue
        script_type = str(script_tag.get("type", "")).strip().lower()
        if script_type != "importmap":
            continue
        content = script_tag.string or script_tag.get_text()
        content = content.strip()
        if not content:
            continue
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            logger.debug("Invalid import map JSON: %s", exc)
            continue

        imports = data.get("imports", {})
        if isinstance(imports, dict):
            for target in imports.values():
                if not isinstance(target, str):
                    continue
                references.extend(
                    _reference_from_path(
                        target,
                        base_url=base_url,
                        source=DiscoverySource.IMPORT_MAP,
                        module_type=ModuleType.MODULE,
                    ),
                )

        scopes = data.get("scopes", {})
        if isinstance(scopes, dict):
            for scope_map in scopes.values():
                if not isinstance(scope_map, dict):
                    continue
                for target in scope_map.values():
                    if not isinstance(target, str):
                        continue
                    references.extend(
                        _reference_from_path(
                            target,
                            base_url=base_url,
                            source=DiscoverySource.IMPORT_MAP,
                            module_type=ModuleType.MODULE,
                        ),
                    )
    return references


def _discover_workers(soup: BeautifulSoup, *, base_url: str) -> list[DiscoveredReference]:
    """Discover worker and service worker script references."""
    references: list[DiscoveredReference] = []
    for link in soup.find_all("link"):
        if not isinstance(link, Tag):
            continue
        rel_values = _normalize_rel(link.get("rel"))
        href = link.get("href")
        if href is None:
            continue
        href_value = str(href).strip()
        if not href_value:
            continue
        if "serviceworker" in rel_values:
            source = DiscoverySource.SERVICE_WORKER
            module_type = ModuleType.SERVICE_WORKER
        elif "worker" in rel_values:
            source = DiscoverySource.WORKER
            module_type = ModuleType.WORKER
        else:
            continue
        references.extend(
            _reference_from_path(
                href_value,
                base_url=base_url,
                source=source,
                module_type=module_type,
            ),
        )
    return references


def _reference_from_path(
    path: str,
    *,
    base_url: str,
    source: DiscoverySource,
    module_type: ModuleType,
) -> list[DiscoveredReference]:
    """Build a discovered reference from a path."""
    try:
        absolute = resolve_url(base_url, path)
        resource = build_script_resource(url=absolute, original_url=path)
    except Exception:
        return []
    return [
        DiscoveredReference(
            url=resource.url,
            original_reference=path,
            source=source,
            module_type=module_type,
        ),
    ]


def _normalize_rel(rel: object) -> list[str]:
    """Normalize link rel attribute to lowercase tokens."""
    if rel is None:
        return []
    if isinstance(rel, list):
        return [str(item).strip().lower() for item in rel if str(item).strip()]
    return [part.strip().lower() for part in str(rel).split() if part.strip()]
