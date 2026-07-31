"""Recursive passive JavaScript discovery engine."""

from __future__ import annotations

import logging
from collections import deque

from techspecter.downloader.http_client import AsyncHttpClient
from techspecter.javascript.discovery.references import (
    extract_references_from_content,
    extract_references_from_manifest_json,
    resolve_manifest_base,
)
from techspecter.javascript.discovery.sources.html import discover_from_html
from techspecter.javascript.models import DiscoveredReference, DiscoverySource
from techspecter.javascript.pipeline.config import JavaScriptPipelineConfig
from techspecter.models.discovery import InlineScript
from techspecter.parser.html_parser import HtmlParseResult, HtmlScriptParser
from techspecter.utils.url import normalize_url

logger = logging.getLogger(__name__)


class JavaScriptDiscoveryEngine:
    """Passively discover JavaScript resources with recursive reference following."""

    def __init__(
        self,
        *,
        config: JavaScriptPipelineConfig | None = None,
        html_parser: HtmlScriptParser | None = None,
    ) -> None:
        """Initialize discovery engine."""
        self._config = config or JavaScriptPipelineConfig()
        self._html_parser = html_parser or HtmlScriptParser()

    def seed_from_html(
        self,
        html: str,
        *,
        base_url: str,
    ) -> tuple[HtmlParseResult, list[DiscoveredReference], list[InlineScript]]:
        """Seed discovery worklist from HTML content."""
        parse_result, references = discover_from_html(
            html,
            base_url=base_url,
            html_parser=self._html_parser,
        )
        deduped = self._dedupe_references(references)
        return parse_result, deduped, list(parse_result.inline_scripts)

    async def discover_recursive(
        self,
        client: AsyncHttpClient,
        seed_references: list[DiscoveredReference],
    ) -> tuple[list[DiscoveredReference], int]:
        """Recursively discover JavaScript URLs from seed references."""
        if not self._config.enable_recursive_discovery:
            return list(seed_references), 0

        worklist: deque[DiscoveredReference] = deque(seed_references)
        discovered: dict[str, DiscoveredReference] = {
            normalize_url(str(item.url)): item for item in seed_references
        }
        rounds = 0
        processed = 0

        while worklist and processed < self._config.max_resources:
            if rounds >= self._config.max_recursive_rounds:
                break
            batch_size = len(worklist)
            rounds += 1
            new_in_round = 0

            for _ in range(batch_size):
                if processed >= self._config.max_resources:
                    break
                reference = worklist.popleft()
                url_key = normalize_url(str(reference.url))
                processed += 1

                content = await self._fetch_content(client, url_key)
                if not content:
                    continue

                base_url = url_key.rsplit("/", 1)[0] + "/"
                new_refs = extract_references_from_content(
                    content,
                    base_url=base_url,
                    parent_url=url_key,
                    source=DiscoverySource.RECURSIVE,
                )

                if url_key.endswith(".json") or reference.source == DiscoverySource.BUNDLE_MANIFEST:
                    manifest_base = resolve_manifest_base(base_url, url_key)
                    new_refs.extend(
                        extract_references_from_manifest_json(
                            content,
                            base_url=manifest_base,
                            parent_url=url_key,
                        ),
                    )

                for item in new_refs:
                    item_key = normalize_url(str(item.url))
                    if item_key in discovered:
                        continue
                    discovered[item_key] = item
                    worklist.append(item)
                    new_in_round += 1

            if new_in_round == 0:
                break

            logger.debug(
                "Recursive discovery round %d discovered %d new references",
                rounds,
                new_in_round,
            )

        return list(discovered.values()), rounds

    async def _fetch_content(self, client: AsyncHttpClient, url: str) -> str | None:
        """Fetch resource content for recursive discovery."""
        try:
            response = await client.get(url)
            if response.status_code >= 400 or not response.content:
                return None
            encoding = response.encoding or "utf-8"
            try:
                return response.content.decode(encoding, errors="replace")
            except LookupError:
                return response.content.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.debug("Recursive fetch failed for %s: %s", url, exc)
            return None

    def _dedupe_references(
        self,
        references: list[DiscoveredReference],
    ) -> list[DiscoveredReference]:
        """Deduplicate references by normalized URL."""
        deduped: dict[str, DiscoveredReference] = {}
        for reference in references:
            key = normalize_url(str(reference.url))
            deduped[key] = reference
        return list(deduped.values())
