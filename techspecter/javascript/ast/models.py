"""AST models for JavaScript preprocessing."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.fingerprinting.javascript.models import ParsedScript
from techspecter.javascript.models import AstSnapshot


@dataclass(frozen=True, slots=True)
class PreparedAst:
    """Prepared AST/token parse output for downstream analyzers."""

    snapshot: AstSnapshot
    parsed: ParsedScript

    @classmethod
    def from_parsed(cls, parsed: ParsedScript, *, parser_id: str) -> PreparedAst:
        """Build prepared AST from parsed script."""
        snapshot = AstSnapshot(
            parser_id=parser_id,
            parse_strategy=parsed.parse_strategy.value,
            import_count=len(parsed.imports),
            export_count=len(parsed.exports),
            identifier_count=len(parsed.identifiers),
            string_literal_count=len(parsed.string_literals),
            parse_errors=list(parsed.parse_errors),
        )
        return cls(snapshot=snapshot, parsed=parsed)
