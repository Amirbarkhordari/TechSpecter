"""Structured knowledge mappings for evidence-driven candidate generation.

Maps strong structured evidence keys (packages, runtime families, headers,
bundle markers) to known technology identities. This is knowledge for
discovery — not a final-output whitelist and not generic keyword scanning.
"""

from __future__ import annotations

# npm / package path → (technology_id, display_name, category)
PACKAGE_TECHNOLOGY_MAP: dict[str, tuple[str, str, str]] = {
    "react": ("react", "React", "framework"),
    "react-dom": ("react", "React", "framework"),
    "react/jsx-runtime": ("react", "React", "framework"),
    "next": ("nextjs", "Next.js", "meta-framework"),
    "next/dist": ("nextjs", "Next.js", "meta-framework"),
    "vue": ("vue", "Vue", "framework"),
    "@vue/runtime-dom": ("vue", "Vue", "framework"),
    "@angular/core": ("angular", "Angular", "framework"),
    "@angular/platform-browser": ("angular", "Angular", "framework"),
    "angular": ("angularjs", "AngularJS", "framework"),
    "svelte": ("svelte", "Svelte", "framework"),
    "solid-js": ("solidjs", "SolidJS", "framework"),
    "preact": ("preact", "Preact", "framework"),
    "jquery": ("jquery", "jQuery", "library"),
    "lodash": ("lodash", "Lodash", "library"),
    "axios": ("axios", "Axios", "library"),
    "webpack": ("webpack", "webpack", "build-tool"),
    "vite": ("vite", "Vite", "build-tool"),
    "rollup": ("rollup", "Rollup", "build-tool"),
    "parcel": ("parcel", "Parcel", "build-tool"),
    "esbuild": ("esbuild", "esbuild", "build-tool"),
    "turbopack": ("turbopack", "Turbopack", "build-tool"),
    "@vercel/turbopack": ("turbopack", "Turbopack", "build-tool"),
    "bootstrap": ("bootstrap", "Bootstrap", "css-framework"),
    "tailwindcss": ("tailwindcss", "Tailwind CSS", "css-framework"),
    "@mui/material": ("material-ui", "Material UI", "ui-library"),
    "@chakra-ui/react": ("chakra-ui", "Chakra UI", "ui-library"),
    "antd": ("ant-design", "Ant Design", "ui-library"),
    "leaflet": ("leaflet", "Leaflet", "maps"),
    "mapbox-gl": ("mapbox-gl", "Mapbox GL", "maps"),
    "nuxt": ("nuxt", "Nuxt", "meta-framework"),
    "gatsby": ("gatsby", "Gatsby", "meta-framework"),
    "remix": ("remix", "Remix", "meta-framework"),
    "astro": ("astro", "Astro", "meta-framework"),
    "rxjs": ("rxjs", "RxJS", "library"),
    "zone.js": ("zonejs", "Zone.js", "library"),
    "moment": ("moment", "Moment.js", "library"),
    "dayjs": ("dayjs", "Day.js", "library"),
    "d3": ("d3", "D3.js", "visualization"),
    "three": ("threejs", "Three.js", "visualization"),
    "chart.js": ("chartjs", "Chart.js", "visualization"),
    "highcharts": ("highcharts", "HighCharts", "visualization"),
    "backbone": ("backbone", "Backbone.js", "framework"),
    "ember": ("ember", "Ember.js", "framework"),
    "lit": ("lit", "Lit", "library"),
    "alpinejs": ("alpine", "Alpine.js", "framework"),
    "@hotwired/stimulus": ("stimulus", "Stimulus", "framework"),
}

# runtime_family metadata / strong runtime markers → technology
RUNTIME_TECHNOLOGY_MAP: dict[str, tuple[str, str, str]] = {
    "react": ("react", "React", "framework"),
    "vue": ("vue", "Vue", "framework"),
    "angular": ("angular", "Angular", "framework"),
    "solid": ("solidjs", "SolidJS", "framework"),
    "svelte": ("svelte", "Svelte", "framework"),
    "astro": ("astro", "Astro", "meta-framework"),
    "next": ("nextjs", "Next.js", "meta-framework"),
    "nuxt": ("nuxt", "Nuxt", "meta-framework"),
}

# Exact matched_value (case-sensitive where unique) for strong bundle markers
BUNDLE_MARKER_MAP: dict[str, tuple[str, str, str]] = {
    "__webpack_require__": ("webpack", "webpack", "build-tool"),
    "__webpack_modules__": ("webpack", "webpack", "build-tool"),
    "webpackChunk": ("webpack", "webpack", "build-tool"),
    "__turbopack_load__": ("turbopack", "Turbopack", "build-tool"),
    "turbopack-runtime": ("turbopack", "Turbopack", "build-tool"),
    "TURBOPACK": ("turbopack", "Turbopack", "build-tool"),
    "import.meta.hot": ("vite", "Vite", "build-tool"),
    "__vite__": ("vite", "Vite", "build-tool"),
    "/@vite/client": ("vite", "Vite", "build-tool"),
}

# HTTP header name (lower) + value substring (lower) → technology
HTTP_HEADER_MAP: tuple[tuple[str, str, str, str, str], ...] = (
    ("server", "nginx", "nginx", "Nginx", "web-servers"),
    ("server", "apache", "apache", "Apache", "web-servers"),
    ("x-powered-by", "express", "express", "Express", "web-frameworks"),
    ("x-powered-by", "php", "php", "PHP", "languages"),
    ("x-powered-by", "asp.net", "aspnet", "ASP.NET", "web-frameworks"),
    ("x-nextjs-cache", "", "nextjs", "Next.js", "meta-framework"),
    ("x-vercel-id", "", "vercel", "Vercel", "hosting"),
)

# Bundle/package markers that are too generic to generate candidates alone
GENERIC_MARKER_BLOCKLIST: frozenset[str] = frozenset(
    {
        "chunk",
        "bundle",
        "ng",
        "react",
        "vue",
        "angular",
        "bootstrap",
        "webpack",
        "require",
        "import",
        "export",
    },
)


def normalize_package_key(value: str) -> str:
    """Normalize a package path or specifier to a lookup key."""
    cleaned = value.strip().strip("\"'").lower()
    if "node_modules/" in cleaned:
        cleaned = cleaned.split("node_modules/", 1)[1]
    cleaned = cleaned.lstrip("./")
    # Keep scoped packages as @scope/name when present
    parts = cleaned.split("/")
    if cleaned.startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else cleaned


def lookup_package(value: str) -> tuple[str, str, str] | None:
    """Resolve a package identifier to technology knowledge when known."""
    key = normalize_package_key(value)
    if key in PACKAGE_TECHNOLOGY_MAP:
        return PACKAGE_TECHNOLOGY_MAP[key]
    # Try scoped full path then unscoped first segment already handled
    if key.startswith("@") and key.count("/") >= 1:
        return PACKAGE_TECHNOLOGY_MAP.get(key)
    # nested path like next/dist/client
    for package_key, mapping in PACKAGE_TECHNOLOGY_MAP.items():
        if key == package_key or key.startswith(f"{package_key}/"):
            return mapping
    return None


def lookup_runtime_family(family: str) -> tuple[str, str, str] | None:
    """Resolve a runtime_family metadata value to technology knowledge."""
    return RUNTIME_TECHNOLOGY_MAP.get(family.strip().lower())


def lookup_bundle_marker(value: str) -> tuple[str, str, str] | None:
    """Resolve a strong bundle marker to technology knowledge."""
    if value in BUNDLE_MARKER_MAP:
        return BUNDLE_MARKER_MAP[value]
    lowered = value.lower()
    for marker, mapping in BUNDLE_MARKER_MAP.items():
        if marker.lower() == lowered:
            return mapping
    return None


def lookup_http_header(header: str, value: str) -> tuple[str, str, str] | None:
    """Resolve a technology-specific HTTP header observation."""
    header_key = header.strip().lower()
    value_key = value.strip().lower()
    for hdr, needle, tech_id, name, category in HTTP_HEADER_MAP:
        if hdr != header_key:
            continue
        if needle and needle not in value_key:
            continue
        if not needle and not value_key:
            continue
        return tech_id, name, category
    return None
