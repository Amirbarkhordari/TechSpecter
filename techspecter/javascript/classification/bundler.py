"""Bundler detection for JavaScript resources."""

from __future__ import annotations

import re

from techspecter.javascript.models import BundlerType

_BUNDLER_PATTERNS: tuple[tuple[BundlerType, re.Pattern[str]], ...] = (
    (BundlerType.WEBPACK, re.compile(r"__webpack_require__|webpackChunk|webpackJsonp")),
    (BundlerType.TURBOPACK, re.compile(r"turbopack|__turbopack__")),
    (BundlerType.VITE, re.compile(r"__vite__|import\.meta\.env")),
    (BundlerType.ROLLUP, re.compile(r"rollupVersion|\bRollup\b")),
    (BundlerType.PARCEL, re.compile(r"parcelRequire|\bParcel\b")),
    (BundlerType.RSPACK, re.compile(r"__rspack_require__")),
    (BundlerType.ESBUILD, re.compile(r"esbuild|__ESBUILD__")),
)


def detect_bundler(*, content: str, filename: str) -> BundlerType:
    """Detect the bundler/build tool used for a JavaScript resource."""
    combined = f"{filename}\n{content[:8192]}"
    for bundler, pattern in _BUNDLER_PATTERNS:
        if pattern.search(combined):
            return bundler
    return BundlerType.UNKNOWN
