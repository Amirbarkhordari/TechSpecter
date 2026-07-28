"""Optional external provider backends."""

from techspecter.providers.backends.retirejs import CliRetireJsBackend, RetireJsBackend
from techspecter.providers.backends.wappalyzer import CliWappalyzerBackend, WappalyzerBackend
from techspecter.providers.backends.wappalyzer_compat import (
    WappalyzerAdapter,
    WappalyzerCompatibilityLayer,
)

__all__ = [
    "CliRetireJsBackend",
    "CliWappalyzerBackend",
    "RetireJsBackend",
    "WappalyzerAdapter",
    "WappalyzerBackend",
    "WappalyzerCompatibilityLayer",
]
