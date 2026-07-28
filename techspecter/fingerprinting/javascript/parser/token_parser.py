"""Structured token-based JavaScript parser."""

from __future__ import annotations

import logging
import re

from techspecter.fingerprinting.javascript.models import (
    JavaScriptResource,
    ParsedExport,
    ParsedImport,
    ParsedScript,
    ParsedStringLiteral,
    ParseStrategy,
)
from techspecter.fingerprinting.javascript.parser.base import JavaScriptParser

logger = logging.getLogger(__name__)

_STRING_LITERAL = re.compile(
    r"""(['"`])((?:\\.|(?!\1)[^\\])*?)\1""",
)
_IMPORT = re.compile(
    r"""^\s*import\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_EXPORT_FROM = re.compile(
    r"""^\s*export\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_EXPORT_DECL = re.compile(
    r"""^\s*export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)""",
    re.MULTILINE,
)
_DYNAMIC_IMPORT = re.compile(
    r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)""",
)
_IDENTIFIER = re.compile(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\b")
_MAX_STRINGS = 500
_MAX_IDENTIFIERS = 300


class TokenJavaScriptParser(JavaScriptParser):
    """Token and pattern parser supporting modern ECMAScript syntax."""

    def parse(self, resource: JavaScriptResource) -> ParsedScript:
        """Parse imports, exports, strings, and identifiers from JavaScript."""
        content = resource.content
        strategy = (
            ParseStrategy.REGEX_FALLBACK
            if resource.is_minified and len(content) > 500_000
            else ParseStrategy.FULL
        )
        errors: list[str] = []
        try:
            imports = _extract_imports(content)
            exports = _extract_exports(content)
            strings = _extract_strings(content)
            identifiers = _extract_identifiers(content)
        except Exception as exc:
            logger.warning("JavaScript parse failed for %s: %s", resource.filename, exc)
            errors.append(str(exc))
            imports = ()
            exports = ()
            strings = ()
            identifiers = ()

        return ParsedScript(
            resource=resource,
            imports=imports,
            exports=exports,
            string_literals=strings,
            identifiers=identifiers,
            parse_errors=tuple(errors),
            parse_strategy=strategy,
        )


def _extract_imports(content: str) -> tuple[ParsedImport, ...]:
    """Extract static and dynamic import observations."""
    items: list[ParsedImport] = []
    for match in _IMPORT.finditer(content):
        items.append(
            ParsedImport(
                module=match.group(1),
                raw=match.group(0).strip(),
                line_number=_line_number(content, match.start()),
            ),
        )
    for match in _DYNAMIC_IMPORT.finditer(content):
        items.append(
            ParsedImport(
                module=match.group(1),
                raw=match.group(0).strip(),
                line_number=_line_number(content, match.start()),
            ),
        )
    return tuple(items)


def _extract_exports(content: str) -> tuple[ParsedExport, ...]:
    """Extract export declarations."""
    items: list[ParsedExport] = []
    for match in _EXPORT_FROM.finditer(content):
        items.append(
            ParsedExport(
                name=match.group(1),
                raw=match.group(0).strip(),
                line_number=_line_number(content, match.start()),
            ),
        )
    for match in _EXPORT_DECL.finditer(content):
        items.append(
            ParsedExport(
                name=match.group(1),
                raw=match.group(0).strip(),
                line_number=_line_number(content, match.start()),
            ),
        )
    return tuple(items)


def _extract_strings(content: str) -> tuple[ParsedStringLiteral, ...]:
    """Extract string literals from JavaScript content."""
    items: list[ParsedStringLiteral] = []
    for match in _STRING_LITERAL.finditer(content):
        value = match.group(2)
        if not value or len(value) < 2:
            continue
        items.append(
            ParsedStringLiteral(
                value=value[:512],
                line_number=_line_number(content, match.start()),
            ),
        )
        if len(items) >= _MAX_STRINGS:
            break
    return tuple(items)


def _extract_identifiers(content: str) -> tuple[str, ...]:
    """Extract dotted identifier expressions."""
    seen: set[str] = set()
    items: list[str] = []
    for match in _IDENTIFIER.finditer(content):
        value = match.group(0)
        if value in seen:
            continue
        seen.add(value)
        items.append(value)
        if len(items) >= _MAX_IDENTIFIERS:
            break
    return tuple(items)


def _line_number(content: str, index: int) -> int:
    """Return 1-based line number for a character index."""
    return content.count("\n", 0, index) + 1
