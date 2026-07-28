"""JavaScript parser exports."""

from techspecter.fingerprinting.javascript.parser.base import JavaScriptParser
from techspecter.fingerprinting.javascript.parser.token_parser import TokenJavaScriptParser

__all__ = ["JavaScriptParser", "TokenJavaScriptParser"]
