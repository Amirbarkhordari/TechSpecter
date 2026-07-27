"""HTML parsing utilities for JavaScript discovery."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from bs4 import BeautifulSoup
from bs4.element import Tag

from techspecter.exceptions import ParserError, ValidationError
from techspecter.models.discovery import InlineScript, ScriptResource
from techspecter.parser.sourcemap import detect_source_map_url
from techspecter.utils.url import resolve_url

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HtmlParseResult:
    """Result of parsing an HTML document for JavaScript resources.

    Attributes:
        external_scripts: Discovered external script resources.
        inline_scripts: Discovered inline script blocks.
    """

    external_scripts: list[ScriptResource]
    inline_scripts: list[InlineScript]


class HtmlScriptParser:
    """Parse HTML documents and discover JavaScript resources."""

    def parse(self, html: str, *, base_url: str) -> HtmlParseResult:
        """Discover external and inline JavaScript resources in HTML.

        Args:
            html: HTML document content.
            base_url: Base URL used to resolve relative script paths.

        Returns:
            Parsed script discovery result.

        Raises:
            ParserError: If the HTML document cannot be parsed.
        """
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception as exc:
            msg = f"Failed to parse HTML document: {exc}"
            raise ParserError(msg) from exc

        external_scripts: list[ScriptResource] = []
        inline_scripts: list[InlineScript] = []
        inline_index = 0

        for script_tag in soup.find_all("script"):
            if not isinstance(script_tag, Tag):
                continue
            inline_index = self._process_script_tag(
                script_tag,
                base_url=base_url,
                external_scripts=external_scripts,
                inline_scripts=inline_scripts,
                inline_index=inline_index,
            )

        logger.info(
            "Discovered %d external and %d inline scripts in %s",
            len(external_scripts),
            len(inline_scripts),
            base_url,
        )

        return HtmlParseResult(
            external_scripts=external_scripts,
            inline_scripts=inline_scripts,
        )

    def _process_script_tag(
        self,
        script_tag: Tag,
        *,
        base_url: str,
        external_scripts: list[ScriptResource],
        inline_scripts: list[InlineScript],
        inline_index: int,
    ) -> int:
        """Process a single ``script`` tag.

        Args:
            script_tag: BeautifulSoup ``script`` element.
            base_url: Base URL for resolving relative paths.
            external_scripts: Accumulator for external scripts.
            inline_scripts: Accumulator for inline scripts.
            inline_index: Current inline script index.

        Returns:
            Updated inline script index.
        """
        src = script_tag.get("src")
        if src is not None:
            src_value = str(src).strip()
            if not src_value:
                return inline_index
            try:
                absolute_url = resolve_url(base_url, src_value)
            except ValidationError as exc:
                logger.warning("Skipping invalid script src '%s': %s", src_value, exc)
                return inline_index

            external_scripts.append(
                ScriptResource(
                    url=absolute_url,  # type: ignore[arg-type]
                    original_url=src_value,
                )
            )
            return inline_index

        content = script_tag.string
        if content is None:
            content = script_tag.get_text()
        content = content.strip()
        if not content:
            return inline_index

        inline_scripts.append(
            InlineScript(
                index=inline_index,
                content=content,
                source_map_url=detect_source_map_url(content, base_url=base_url),
            )
        )
        return inline_index + 1
