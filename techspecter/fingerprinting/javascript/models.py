"""JavaScript intelligence models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ParseStrategy(StrEnum):
    """Parsing strategy selected for a JavaScript resource."""

    FULL = "full"
    INCREMENTAL = "incremental"
    REGEX_FALLBACK = "regex_fallback"


@dataclass(frozen=True, slots=True)
class JavaScriptResource:
    """Normalized JavaScript resource ready for intelligence analysis."""

    url: str
    filename: str
    content: str
    source_map_url: str | None = None
    content_length: int = 0
    is_minified: bool = False
    parse_strategy: ParseStrategy = ParseStrategy.FULL


@dataclass(frozen=True, slots=True)
class ParsedImport:
    """Structured import observation."""

    module: str
    raw: str
    line_number: int | None = None


@dataclass(frozen=True, slots=True)
class ParsedExport:
    """Structured export observation."""

    name: str | None
    raw: str
    line_number: int | None = None


@dataclass(frozen=True, slots=True)
class ParsedStringLiteral:
    """Extracted string literal."""

    value: str
    line_number: int | None = None


@dataclass(frozen=True, slots=True)
class ParsedScript:
    """Structured parse output for a JavaScript resource."""

    resource: JavaScriptResource
    imports: tuple[ParsedImport, ...] = field(default_factory=tuple)
    exports: tuple[ParsedExport, ...] = field(default_factory=tuple)
    string_literals: tuple[ParsedStringLiteral, ...] = field(default_factory=tuple)
    identifiers: tuple[str, ...] = field(default_factory=tuple)
    parse_errors: tuple[str, ...] = field(default_factory=tuple)
    parse_strategy: ParseStrategy = ParseStrategy.FULL


@dataclass(frozen=True, slots=True)
class ExtractionFinding:
    """Intermediate finding before conversion to Evidence."""

    category: str
    evidence_type: str
    matched_value: str
    matched_pattern: str | None = None
    line_number: int | None = None
    reason: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class JavaScriptAnalysisResult:
    """Combined analysis output for one JavaScript resource."""

    resource: JavaScriptResource
    findings: tuple[ExtractionFinding, ...] = field(default_factory=tuple)
    elapsed_ms: float = 0.0
    errors: tuple[str, ...] = field(default_factory=tuple)
