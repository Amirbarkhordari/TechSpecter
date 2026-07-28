"""Centralized version information for TechSpecter."""

__version__ = "1.0.0rc1"
__version_tuple__ = (1, 0, 0, "rc", 1)


def version_display() -> str:
    """Return a human-readable semver string for CLI and reports."""
    if "rc" in __version__:
        return __version__.replace("rc", "-rc", 1)
    if "a" in __version__ and __version__.count("a") == 1 and __version__.index("a") > 0:
        return __version__.replace("a", "-alpha", 1)
    if "b" in __version__ and __version__.count("b") == 1 and __version__.index("b") > 0:
        return __version__.replace("b", "-beta", 1)
    return __version__
