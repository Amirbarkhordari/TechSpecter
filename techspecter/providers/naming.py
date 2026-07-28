"""Technology naming normalization across providers."""

from __future__ import annotations

import re

from techspecter.benchmark.utils import normalize_technology_id as _normalize_technology_id

_NAME_ALIASES: dict[str, str] = {
    "reactjs": "React",
    "react.js": "React",
    "angularjs": "Angular",
    "angular.js": "Angular",
    "vuejs": "Vue",
    "vue.js": "Vue",
    "nextjs": "Next.js",
    "next.js": "Next.js",
    "nuxtjs": "Nuxt.js",
    "nuxt.js": "Nuxt.js",
    "nodejs": "Node.js",
    "node.js": "Node.js",
    "jquery": "jQuery",
    "tailwindcss": "Tailwind CSS",
    "materialui": "Material UI",
    "material-ui": "Material UI",
    "styledcomponents": "Styled Components",
    "styled-components": "Styled Components",
    "aspnetcore": "ASP.NET Core",
    "aspnet-core": "ASP.NET Core",
    "springboot": "Spring Boot",
    "spring-boot": "Spring Boot",
    "googleanalytics": "Google Analytics",
    "google-analytics": "Google Analytics",
}

_SLUG_CLEAN = re.compile(r"[^a-z0-9.]+")


def normalize_technology_name(value: str) -> str:
    """Normalize a technology display name (e.g. ReactJS -> React)."""
    stripped = value.strip()
    if not stripped:
        return stripped
    key = _SLUG_CLEAN.sub("", stripped.lower())
    return _NAME_ALIASES.get(key, stripped)


def normalize_technology_identity(name: str, *, fallback_id: str | None = None) -> tuple[str, str]:
    """Return canonical (technology_id, display_name) for a raw technology label."""
    display_name = normalize_technology_name(name)
    tech_id = _normalize_technology_id(fallback_id or display_name)
    return tech_id, display_name
