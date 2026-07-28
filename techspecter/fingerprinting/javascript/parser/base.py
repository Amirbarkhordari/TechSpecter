"""JavaScript parser interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod

from techspecter.fingerprinting.javascript.models import JavaScriptResource, ParsedScript


class JavaScriptParser(ABC):
    """Abstract JavaScript parser with swappable backends."""

    @abstractmethod
    def parse(self, resource: JavaScriptResource) -> ParsedScript:
        """Parse a JavaScript resource into structured observations."""
