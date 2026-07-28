"""Technology ID normalization utilities for benchmark comparison."""

from __future__ import annotations

import re

_TECH_ALIASES: dict[str, str] = {
    "nextjs": "nextjs",
    "next": "nextjs",
    "reactjs": "react",
    "vuejs": "vue",
    "nuxtjs": "nuxt",
    "angularjs": "angular",
    "angular": "angular",
    "tailwindcss": "tailwindcss",
    "tailwind": "tailwindcss",
    "materialui": "mui",
    "material-ui": "mui",
    "muitoolkit": "mui",
    "styledcomponents": "styledcomponents",
    "styled-components": "styledcomponents",
    "aspnet": "aspnet",
    "aspnetcore": "aspnet",
    "aspnet-core": "aspnet",
    "springboot": "spring",
    "spring-boot": "spring",
    "wordpress": "wordpress",
    "nodejs": "node",
    "node-js": "node",
    "webpack": "webpack",
    "vite": "vite",
    "cloudflare": "cloudflare",
    "google-analytics": "googleanalytics",
    "googleanalytics": "googleanalytics",
    "ga4": "googleanalytics",
}

_SLUG_CLEAN = re.compile(r"[^a-z0-9]+")


def normalize_technology_id(value: str) -> str:
    """Normalize a technology name or slug for cross-engine comparison."""
    lowered = value.strip().lower()
    cleaned = _SLUG_CLEAN.sub("", lowered)
    return _TECH_ALIASES.get(cleaned, cleaned)


def normalize_category(value: str) -> str:
    """Normalize category labels for comparison."""
    cleaned = _SLUG_CLEAN.sub("-", value.strip().lower()).strip("-")
    return cleaned or "unknown"


def categories_match(left: str, right: str) -> bool:
    """Return whether two category labels refer to the same group."""
    left_norm = normalize_category(left)
    right_norm = normalize_category(right)
    if left_norm == right_norm:
        return True
    return left_norm in right_norm or right_norm in left_norm
