"""Optional external provider backends."""

from techspecter.providers.backends.retirejs import CliRetireJsBackend, RetireJsBackend
from techspecter.providers.backends.wappalyzer import CliWappalyzerBackend, WappalyzerBackend

__all__ = [
    "CliRetireJsBackend",
    "CliWappalyzerBackend",
    "RetireJsBackend",
    "WappalyzerBackend",
]
