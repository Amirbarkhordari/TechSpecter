"""AST preparation infrastructure for future analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from techspecter.fingerprinting.javascript.models import JavaScriptResource, ParsedScript
from techspecter.fingerprinting.javascript.parser.base import JavaScriptParser
from techspecter.fingerprinting.javascript.parser.token_parser import TokenJavaScriptParser
from techspecter.javascript.ast.models import PreparedAst
from techspecter.javascript.cache.resource_cache import JavaScriptResourceCache


class AstParser(ABC):
    """Abstract AST/token parser with swappable implementations."""

    @property
    @abstractmethod
    def parser_id(self) -> str:
        """Unique parser identifier."""

    @abstractmethod
    def parse(self, resource: JavaScriptResource) -> PreparedAst:
        """Parse resource into a prepared AST snapshot."""


@dataclass(slots=True)
class TokenAstParser(AstParser):
    """Token-based AST preparation using the existing token parser."""

    _backend: JavaScriptParser | None = None

    @property
    def parser_id(self) -> str:
        """Return parser identifier."""
        return "token"

    @property
    def backend(self) -> JavaScriptParser:
        """Return underlying parser backend."""
        if self._backend is None:
            self._backend = TokenJavaScriptParser()
        return self._backend

    def parse(self, resource: JavaScriptResource) -> PreparedAst:
        """Parse resource and return AST snapshot."""
        parsed: ParsedScript = self.backend.parse(resource)
        return PreparedAst.from_parsed(parsed, parser_id=self.parser_id)


class AstPreparationStage:
    """Prepare and cache AST snapshots for indexed resources."""

    def __init__(
        self,
        *,
        parser: AstParser | None = None,
        cache: JavaScriptResourceCache | None = None,
    ) -> None:
        """Initialize AST preparation stage."""
        self._parser = parser or TokenAstParser()
        self._cache = cache

    def prepare(
        self,
        *,
        url: str,
        filename: str,
        content: str,
        is_minified: bool,
    ) -> PreparedAst:
        """Prepare AST snapshot with caching."""
        cache_key = JavaScriptResourceCache.content_key(url=url, content=content)
        if self._cache is not None:
            cached = self._cache.ast_cache.get(cache_key)
            if cached is not None:
                return cached

        resource = JavaScriptResource(
            url=url,
            filename=filename,
            content=content,
            is_minified=is_minified,
            content_length=len(content),
        )
        prepared = self._parser.parse(resource)
        if self._cache is not None:
            self._cache.ast_cache.set(cache_key, prepared)
        return prepared
