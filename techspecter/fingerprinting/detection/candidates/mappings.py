"""Structured knowledge mappings for evidence-driven candidate generation.

Maps strong structured evidence keys (packages, runtime families, headers,
bundle markers) to known technology identities. This is knowledge for
discovery — not a final-output whitelist and not generic keyword scanning.
"""

from __future__ import annotations

import re

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
    "webpackJsonp": ("webpack", "webpack", "build-tool"),
    "__turbopack_load__": ("turbopack", "Turbopack", "build-tool"),
    "turbopack-runtime": ("turbopack", "Turbopack", "build-tool"),
    "TURBOPACK": ("turbopack", "Turbopack", "build-tool"),
    "__turbopack__": ("turbopack", "Turbopack", "build-tool"),
    "import.meta.hot": ("vite", "Vite", "build-tool"),
    "import.meta.env": ("vite", "Vite", "build-tool"),
    "__vite__": ("vite", "Vite", "build-tool"),
    "/@vite/client": ("vite", "Vite", "build-tool"),
    "rollupVersion": ("rollup", "Rollup", "build-tool"),
    "parcelRequire": ("parcel", "Parcel", "build-tool"),
    "__rspack_require__": ("rspack", "Rspack", "build-tool"),
}

# Bundler metadata key → technology
BUNDLER_TECHNOLOGY_MAP: dict[str, tuple[str, str, str]] = {
    "webpack": ("webpack", "webpack", "build-tool"),
    "vite": ("vite", "Vite", "build-tool"),
    "rollup": ("rollup", "Rollup", "build-tool"),
    "parcel": ("parcel", "Parcel", "build-tool"),
    "rspack": ("rspack", "Rspack", "build-tool"),
    "turbopack": ("turbopack", "Turbopack", "build-tool"),
    "esbuild": ("esbuild", "esbuild", "build-tool"),
}

# CSS structured marker key → technology
CSS_TECHNOLOGY_MAP: dict[str, tuple[str, str, str]] = {
    "bootstrap": ("bootstrap", "Bootstrap", "css-framework"),
    "tailwindcss": ("tailwindcss", "Tailwind CSS", "css-framework"),
    "tailwind": ("tailwindcss", "Tailwind CSS", "css-framework"),
    "cloudflare": ("cloudflare", "Cloudflare", "cdn"),
}

# HTML framework hint / generator key → technology
HTML_TECHNOLOGY_MAP: dict[str, tuple[str, str, str]] = {
    "next.js": ("nextjs", "Next.js", "meta-framework"),
    "nextjs": ("nextjs", "Next.js", "meta-framework"),
    "next": ("nextjs", "Next.js", "meta-framework"),
    "nuxt": ("nuxt", "Nuxt", "meta-framework"),
    "react": ("react", "React", "framework"),
    "vue": ("vue", "Vue", "framework"),
    "angular": ("angular", "Angular", "framework"),
    "wordpress": ("wordpress", "WordPress", "cms"),
    "drupal": ("drupal", "Drupal", "cms"),
    "gatsby": ("gatsby", "Gatsby", "meta-framework"),
    "cloudflare": ("cloudflare", "Cloudflare", "cdn"),
}

# HTTP header name (lower) + value substring (lower) → technology
HTTP_HEADER_MAP: tuple[tuple[str, str, str, str, str], ...] = (
    ("server", "nginx", "nginx", "Nginx", "web-servers"),
    ("server", "apache", "apache", "Apache", "web-servers"),
    ("server", "cloudflare", "cloudflare", "Cloudflare", "cdn"),
    ("x-powered-by", "express", "express", "Express", "web-frameworks"),
    ("x-powered-by", "php", "php", "PHP", "languages"),
    ("x-powered-by", "asp.net", "aspnet", "ASP.NET", "web-frameworks"),
    ("x-powered-by", "next.js", "nextjs", "Next.js", "meta-framework"),
    ("x-powered-by", "nextjs", "nextjs", "Next.js", "meta-framework"),
    ("x-nextjs-cache", "", "nextjs", "Next.js", "meta-framework"),
    ("x-vercel-id", "", "vercel", "Vercel", "hosting"),
)

# Headers that may establish an identity from their product token alone.
HTTP_IDENTITY_HEADERS: frozenset[str] = frozenset(
    {
        "server",
        "x-powered-by",
        "x-generator",
        "x-framework",
        "x-nextjs-cache",
        "x-vercel-id",
    },
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
        "runtime",
        "app",
        "main",
        "component",
        "render",
        "common",
        "helper",
        "utils",
        "core",
    },
)

# Path / framework-internal segments that must never become package identities.
INVALID_PACKAGE_NAMES: frozenset[str] = frozenset(
    {
        "chunks",
        "static",
        "media",
        "font",
        "image",
        "images",
        "assets",
        "public",
        "pages",
        "page",
        "_next",
        "_nuxt",
        "next",
        "webpack",
        "node_modules",
        "favicon",
        "robots",
        "sitemap",
        "manifest",
        "browserconfig",
        "humans",
        "ads",
    },
)

# Ambiguous short names that must not auto-confirm without strong multi-signal evidence.
CONSERVATIVE_PACKAGE_NAMES: frozenset[str] = frozenset(
    {
        "core",
        "utils",
        "util",
        "app",
        "runtime",
        "common",
        "helper",
        "helpers",
        "config",
        "index",
        "main",
        "test",
        "tests",
        "lib",
        "src",
        "dist",
        "shared",
        "types",
        "internal",
        "component",
        "components",
        "render",
        "chunk",
        "bundle",
        "text",
        "code",
        "root",
        "style",
        "styles",
        "css",
        "js",
        "ts",
        "tsx",
        "jsx",
        "data",
        "error",
        "errors",
        "route",
        "routes",
        "server",
        "client",
        "browser",
        "node",
        "vendor",
        "polyfill",
        "compiled",
        "build",
        "module",
        "modules",
        "package",
        "packages",
        "ci",
        "dev",
        "prod",
        "production",
        "development",
    },
)

# npm package names must match this shape (optional scope + package root).
_VALID_NPM_PACKAGE = re.compile(
    r"^(?:@[a-z0-9][\w.~-]*/)?[a-z0-9][\w.~-]*$",
    re.IGNORECASE,
)

# Tailwind / utility-class style tokens are not package identities.
_CSS_UTILITY_PREFIX = re.compile(
    r"^(?:"
    r"bg|text|border|ring|from|to|via|flex|grid|gap|grow|shrink|basis|"
    r"p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|"
    r"w|h|min|max|size|rounded|shadow|opacity|z|"
    r"top|left|right|bottom|inset|col|row|items|justify|self|place|"
    r"font|leading|tracking|align|whitespace|overflow|object|"
    r"transition|duration|ease|animate|cursor|pointer|select|"
    r"space|divide|outline|blur|content|aspect|columns|break|box|"
    r"float|clear|isolation|overscroll|visible|invisible|sr|"
    r"underline|line|decoration|list|table|border|divide|outline|"
    r"accent|caret|fill|stroke|scroll|snap|touch|will|backface|"
    r"transform|translate|rotate|skew|scale|origin|filter|"
    r"backdrop|mix|contrast|brightness|grayscale|invert|saturate|sepia"
    r")-",
    re.IGNORECASE,
)

CONSERVATIVE_RUNTIME_NAMES: frozenset[str] = frozenset(CONSERVATIVE_PACKAGE_NAMES)

GENERIC_CSS_SELECTORS: frozenset[str] = frozenset(
    {
        "btn",
        "button",
        "container",
        "row",
        "col",
        "flex",
        "grid",
        "card",
        "nav",
        "navbar",
        "header",
        "footer",
        "main",
        "wrapper",
        "content",
        "item",
        "list",
        "text",
        "title",
        "active",
        "hidden",
        "show",
        "hide",
    },
)

GENERIC_HTML_ELEMENTS: frozenset[str] = frozenset(
    {
        "div",
        "span",
        "section",
        "button",
        "a",
        "p",
        "ul",
        "li",
        "img",
        "form",
        "input",
        "table",
        "html",
        "body",
        "head",
        "script",
        "link",
        "meta",
    },
)

GENERIC_HTTP_VALUES: frozenset[str] = frozenset(
    {
        "",
        "*",
        "unknown",
        "server",
        "ok",
        "true",
        "false",
        "null",
        "none",
        "http",
        "https",
    },
)


def is_relative_module(value: str) -> bool:
    """Return True when a specifier is an application-local relative path."""
    cleaned = value.strip().strip("\"'")
    if cleaned.startswith("./") or cleaned.startswith("../"):
        return True
    # Absolute path-like imports (/utils), excluding CSS comments and URL schemes.
    if cleaned.startswith("/*") or cleaned.startswith("//"):
        return False
    if cleaned.startswith("/") and "://" not in cleaned and " " not in cleaned:
        return True
    return False


def is_url_like_module(value: str) -> bool:
    """Return True when a specifier looks like a URL rather than a package."""
    cleaned = value.strip().lower()
    return cleaned.startswith(("http://", "https://", "data:", "blob:", "file:"))


def is_valid_package_identity(value: str) -> bool:
    """Return True when a value is a plausible npm/package identity.

    Rejects prose, CSS utilities, path segments, URLs, and other non-package
    strings that can appear in bundles but must never become technologies.
    """
    cleaned = value.strip().strip("\"'")
    if not cleaned or len(cleaned) > 214:
        return False
    if any(ch.isspace() for ch in cleaned):
        return False
    if is_relative_module(cleaned) or is_url_like_module(cleaned):
        return False
    if "\\" in cleaned or "?" in cleaned or "#" in cleaned:
        return False
    if "${" in cleaned or "`" in cleaned:
        return False
    lowered = cleaned.lower().replace("\\", "/")
    if lowered.startswith(("www.", "npmjs.com", "github.com", "unpkg.com", "cdn.")):
        return False
    # Version-only tokens
    if re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?", cleaned, flags=re.IGNORECASE):
        return False
    key = normalize_package_key(cleaned)
    if not key:
        return False
    basename = lowered.rsplit("/", 1)[-1]
    if "node_modules/" not in lowered and basename.endswith(
        (".js", ".css", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".map"),
    ):
        return False
    root = key.split("/")[-1] if key.startswith("@") else key
    if len(root) < 2:
        return False
    if root in INVALID_PACKAGE_NAMES or key in INVALID_PACKAGE_NAMES:
        return False
    if _CSS_UTILITY_PREFIX.match(root) or _CSS_UTILITY_PREFIX.match(key):
        return False
    if root in GENERIC_CSS_SELECTORS:
        return False
    if not _VALID_NPM_PACKAGE.match(key):
        return False
    if root in {"_next", "_nuxt", "_app", "_document", "_error"} or root.startswith("_next"):
        return False
    return True


def normalize_package_key(value: str) -> str:
    """Normalize a package path or specifier to a package-root lookup key."""
    cleaned = value.strip().strip("\"'")
    if is_relative_module(cleaned) or is_url_like_module(cleaned):
        return ""
    if any(ch.isspace() for ch in cleaned):
        return ""
    lowered = cleaned.lower()
    if "node_modules/" in lowered:
        lowered = lowered.split("node_modules/", 1)[1]
    lowered = lowered.lstrip("./")
    parts = lowered.split("/")
    if lowered.startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else lowered


def package_technology_id(normalized_key: str) -> str:
    """Build a stable evidence-native technology id for an unknown package."""
    return f"package:{normalized_key}"


def is_conservative_package_name(normalized_key: str) -> bool:
    """Return True for ambiguous package roots that should not auto-confirm."""
    if not normalized_key:
        return True
    root = normalized_key.split("/")[-1] if normalized_key.startswith("@") else normalized_key
    return root in CONSERVATIVE_PACKAGE_NAMES or normalized_key in CONSERVATIVE_PACKAGE_NAMES


def is_structured_package_evidence(item: object) -> bool:
    """Return True when evidence establishes a real package/module identity."""
    from techspecter.fingerprinting.evidence.models import Evidence, EvidenceType

    if not isinstance(item, Evidence):
        return False
    if item.evidence_type not in {
        EvidenceType.PACKAGE_REFERENCE,
        EvidenceType.IMPORT_EXPORT,
        EvidenceType.SOURCE_MAP_METADATA,
    }:
        return False
    value = item.matched_value or ""
    if not is_valid_package_identity(value):
        return False
    # IMPORT_EXPORT must be an import, not an export name
    if item.evidence_type == EvidenceType.IMPORT_EXPORT:
        return item.metadata.get("kind") in {None, "import", "dynamic_import"}
    if item.evidence_type == EvidenceType.SOURCE_MAP_METADATA:
        return "node_modules/" in value.replace("\\", "/").lower()
    return True


def lookup_package(value: str) -> tuple[str, str, str] | None:
    """Resolve a package identifier to technology knowledge when known."""
    return lookup_package_raw(value)


def lookup_package_raw(value: str) -> tuple[str, str, str] | None:
    """Resolve a package identifier against the knowledge map only."""
    if is_relative_module(value) or is_url_like_module(value):
        return None
    key = normalize_package_key(value)
    if not key:
        return None
    if key in PACKAGE_TECHNOLOGY_MAP:
        return PACKAGE_TECHNOLOGY_MAP[key]
    if key.startswith("@") and key.count("/") >= 1:
        mapped = PACKAGE_TECHNOLOGY_MAP.get(key)
        if mapped is not None:
            return mapped
    for package_key, mapping in PACKAGE_TECHNOLOGY_MAP.items():
        if key == package_key or key.startswith(f"{package_key}/"):
            return mapping
    return None


def resolve_package_identity(
    value: str,
) -> tuple[str, str, str, bool] | None:
    """Resolve package evidence to catalog or evidence-native identity.

    Returns:
        (technology_id, display_name, category, knowledge_matched) or None.
    """
    if is_relative_module(value) or is_url_like_module(value):
        return None
    key = normalize_package_key(value)
    if not key:
        return None
    known = lookup_package_raw(value)
    if known is not None:
        tech_id, name, category = known
        return tech_id, name, category, True
    if not is_valid_package_identity(value):
        return None
    return package_technology_id(key), key, "unknown", False


def lookup_runtime_family(family: str) -> tuple[str, str, str] | None:
    """Resolve a runtime_family metadata value to technology knowledge."""
    return RUNTIME_TECHNOLOGY_MAP.get(family.strip().lower())


def normalize_identity_key(value: str) -> str:
    """Normalize a free-form identity token to a stable lowercase key."""
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return ""
    lowered = cleaned.lower().replace("_", "-")
    while "--" in lowered:
        lowered = lowered.replace("--", "-")
    return lowered.strip("-")


def is_conservative_runtime_name(normalized_key: str) -> bool:
    """Return True for ambiguous runtime names that must not open-discover."""
    return not normalized_key or normalized_key in CONSERVATIVE_RUNTIME_NAMES


def is_structured_runtime_marker(value: str) -> bool:
    """Return True when a runtime marker looks uniquely structured."""
    cleaned = value.strip()
    if len(cleaned) < 4:
        return False
    if cleaned.startswith("__") and cleaned.endswith("__") and len(cleaned) >= 6:
        return True
    if "." in cleaned and any(token.isupper() or token[:1].isupper() for token in cleaned.split(".")):
        return True
    return False


def resolve_runtime_identity(
    family: str,
    *,
    matched_value: str | None = None,
) -> tuple[str, str, str, bool] | None:
    """Resolve runtime evidence to catalog or evidence-native identity."""
    key = normalize_identity_key(family)
    if not key:
        return None
    known = lookup_runtime_family(key)
    if known is not None:
        tech_id, name, category = known
        return tech_id, name, category, True
    if is_conservative_runtime_name(key):
        return None
    # Open runtime identities require a structured marker, not a bare word.
    if matched_value and not is_structured_runtime_marker(matched_value):
        if not key.startswith(("__", "@")) and "-" not in key and len(key) < 8:
            return None
    return f"runtime:{key}", key, "unknown", False


def lookup_bundle_marker(value: str) -> tuple[str, str, str] | None:
    """Resolve a strong bundle marker to technology knowledge."""
    if value in BUNDLE_MARKER_MAP:
        return BUNDLE_MARKER_MAP[value]
    lowered = value.lower()
    for marker, mapping in BUNDLE_MARKER_MAP.items():
        if marker.lower() == lowered:
            return mapping
    return None


def lookup_bundler(bundler: str) -> tuple[str, str, str] | None:
    """Resolve bundler metadata to technology knowledge."""
    return BUNDLER_TECHNOLOGY_MAP.get(bundler.strip().lower())


def resolve_bundle_identity(
    *,
    marker: str | None = None,
    bundler: str | None = None,
) -> tuple[str, str, str, bool] | None:
    """Resolve bundler evidence to catalog or evidence-native identity."""
    if bundler:
        known = lookup_bundler(bundler)
        if known is not None:
            tech_id, name, category = known
            return tech_id, name, category, True
        key = normalize_identity_key(bundler)
        if key and key not in GENERIC_MARKER_BLOCKLIST and not is_conservative_package_name(key):
            return f"bundle:{key}", key, "build-tool", False
    if marker:
        if marker.lower() in GENERIC_MARKER_BLOCKLIST:
            return None
        # Filenames and chunk ids are not technology identities.
        if "." in marker and marker.lower().endswith((".js", ".css", ".map")):
            return None
        known = lookup_bundle_marker(marker)
        if known is not None:
            tech_id, name, category = known
            return tech_id, name, category, True
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


def _http_product_token(value: str) -> str:
    """Extract the leading product token from a Server / X-Powered-By value."""
    cleaned = value.strip()
    if not cleaned:
        return ""
    # Take first product before spaces/commas; strip version suffix.
    token = cleaned.split(",")[0].strip().split()[0]
    token = token.split("/")[0].strip()
    return normalize_identity_key(token)


def resolve_http_identity(
    header: str,
    value: str,
) -> tuple[str, str, str, bool] | None:
    """Resolve HTTP header evidence to catalog or evidence-native identity."""
    header_key = header.strip().lower()
    if header_key not in HTTP_IDENTITY_HEADERS:
        return None
    known = lookup_http_header(header, value)
    if known is not None:
        tech_id, name, category = known
        return tech_id, name, category, True
    # Presence-only framework headers without a value product stay map-driven.
    if header_key in {"x-nextjs-cache", "x-vercel-id"}:
        return None
    product = _http_product_token(value)
    if not product or product in GENERIC_HTTP_VALUES:
        return None
    if is_conservative_package_name(product) or product in GENERIC_MARKER_BLOCKLIST:
        return None
    if len(product) < 3:
        return None
    display = value.strip().split(",")[0].strip().split("/")[0].strip() or product
    return f"http:{product}", display, "unknown", False


def lookup_css_marker(key: str) -> tuple[str, str, str] | None:
    """Resolve a CSS technology marker key to catalog knowledge."""
    return CSS_TECHNOLOGY_MAP.get(key.strip().lower())


def is_generic_css_selector(value: str) -> bool:
    """Return True for generic CSS class/selector names."""
    cleaned = value.strip().lstrip(".#").lower()
    if not cleaned:
        return True
    root = cleaned.split(":")[0].split("(")[0]
    return root in GENERIC_CSS_SELECTORS


def resolve_css_identity(
    key: str,
    *,
    matched_value: str | None = None,
) -> tuple[str, str, str, bool] | None:
    """Resolve CSS evidence to catalog or evidence-native identity."""
    normalized = normalize_identity_key(key)
    if not normalized:
        return None
    if is_generic_css_selector(normalized) or is_generic_css_selector(matched_value or ""):
        return None
    known = lookup_css_marker(normalized)
    if known is not None:
        tech_id, name, category = known
        return tech_id, name, category, True
    if is_conservative_package_name(normalized):
        return None
    return f"css:{normalized}", normalized, "css-framework", False


def lookup_html_marker(key: str) -> tuple[str, str, str] | None:
    """Resolve an HTML framework/generator marker to catalog knowledge."""
    return HTML_TECHNOLOGY_MAP.get(key.strip().lower())


def is_generic_html_element(value: str) -> bool:
    """Return True for generic HTML element names."""
    return value.strip().lower() in GENERIC_HTML_ELEMENTS


def resolve_html_identity(
    key: str,
    *,
    matched_value: str | None = None,
) -> tuple[str, str, str, bool] | None:
    """Resolve HTML evidence to catalog or evidence-native identity."""
    raw = key.strip()
    if raw.lower().startswith("generator:"):
        raw = raw.split(":", 1)[1].strip()
    # Generator values often include versions: "WordPress 6.4.2"
    token = raw.split()[0] if raw else ""
    normalized = normalize_identity_key(token)
    if not normalized:
        return None
    if is_generic_html_element(normalized) or is_generic_html_element(matched_value or ""):
        return None
    known = lookup_html_marker(normalized)
    if known is None and " " not in raw:
        known = lookup_html_marker(raw.lower())
    # WordPress-style generator tokens
    if known is None:
        for hint_key, mapping in HTML_TECHNOLOGY_MAP.items():
            if hint_key in normalized or normalized.startswith(hint_key):
                known = mapping
                break
    if known is not None:
        tech_id, name, category = known
        return tech_id, name, category, True
    if is_conservative_package_name(normalized) or normalized in GENERIC_MARKER_BLOCKLIST:
        return None
    if len(normalized) < 3:
        return None
    return f"html:{normalized}", raw.split()[0], "unknown", False
