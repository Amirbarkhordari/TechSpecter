"""Phase 2 technology detection accuracy regression tests."""

from __future__ import annotations

from techspecter.fingerprinting.match_attribution import is_valid_detection_candidate
from techspecter.fingerprinting.match_quality import MatchQualityGate
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target


def _run(content: str, filename: str, *, url: str | None = None) -> DiscoveryResult:
    """Run fingerprint pipeline against a single analyzed asset."""
    resolved_url = url or f"https://example.com/{filename}"
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url=resolved_url,
                filename=filename,
                content=content,
                download_success=True,
                status_code=200,
                content_type="application/javascript",
                content_length=len(content),
                download_duration_ms=1.0,
            ),
        ],
        inline_scripts=[],
    )
    return FingerprintPipeline().run(discovery)


def _confirmed_ids(result) -> set[str]:
    return {item.technology.id for item in result.matches}


def _first_match(result, tech_id: str):
    return next(item for item in result.matches if item.technology.id == tech_id)


def test_react_runtime_detection() -> None:
    """React runtime markers in bundles must produce confirmed detections."""
    result = _run(
        'reconcilerVersion:"19.0.0"; React.createElement("div");',
        "framework.js",
    )
    assert "react" in _confirmed_ids(result)
    react = _first_match(result, "react")
    assert react.version == "19.0.0"
    assert react.source_file == "framework.js"
    assert react.evidence


def test_nextjs_runtime_detection() -> None:
    """Next.js runtime markers must produce confirmed detections."""
    result = _run(
        'window.next={version:"16.2.10",appDir:true};',
        "0-s5ec5safvjx.js",
    )
    assert "nextjs" in _confirmed_ids(result)
    nextjs = _first_match(result, "nextjs")
    assert nextjs.version == "16.2.10"
    assert nextjs.source_file == "0-s5ec5safvjx.js"


def test_vue_detection() -> None:
    """Vue runtime markers must produce confirmed detections with version."""
    result = _run(
        'Vue.version="3.4.21"; Vue.createApp({ render() { return null; } });',
        "app.js",
    )
    assert "vue" in _confirmed_ids(result)
    vue = _first_match(result, "vue")
    assert vue.version == "3.4.21"
    assert vue.source_file == "app.js"


def test_angular_detection() -> None:
    """Angular Ivy/runtime markers must produce confirmed detections."""
    result = _run(
        'import "@angular/core"; ɵɵdefineComponent({}); platformBrowserDynamic();',
        "main.js",
    )
    assert "angular" in _confirmed_ids(result)
    angular = _first_match(result, "angular")
    assert angular.source_file == "main.js"
    assert angular.evidence


def test_bootstrap_validation() -> None:
    """Bootstrap requires framework indicators, not generic text mentions."""
    weak = _run("var label = 'Bootstrap documentation';", "app.js")
    assert "bootstrap" not in _confirmed_ids(weak)

    strong = _run(
        '<link rel="stylesheet" href="/assets/bootstrap.min.css">'
        '<button data-bs-toggle="modal">Open</button>',
        "index.html",
        url="https://example.com/index.html",
    )
    assert "bootstrap" in _confirmed_ids(strong)


def test_tailwind_validation() -> None:
    """Tailwind requires build/CSS indicators, not arbitrary class names."""
    weak = _run("const classes = 'flex items-center';", "app.js")
    assert "tailwindcss" not in _confirmed_ids(weak)

    strong = _run(
        "@tailwind base;\n@tailwind components;\n@tailwind utilities;\n"
        "const __tailwindcss_version__ = '3.4.1';",
        "styles.css",
        url="https://example.com/styles.css",
    )
    assert "tailwindcss" in _confirmed_ids(strong)


def test_material_ui_validation() -> None:
    """Material UI requires package/runtime indicators."""
    weak = _run("const theme = 'material ui inspired';", "app.js")
    assert "material-ui" not in _confirmed_ids(weak)

    strong = _run(
        'import { Button } from "@mui/material"; MuiThemeProvider({ children: null });',
        "components.js",
    )
    assert "material-ui" in _confirmed_ids(strong)


def test_webpack_validation() -> None:
    """Webpack requires runtime signatures, not chunk filenames alone."""
    weak = _run("console.log('hello');", "928-f8fcd93b9c496fa5.js")
    assert "webpack" not in _confirmed_ids(weak)

    strong = _run(
        "function r(e){return __webpack_require__(e)}; __webpack_modules__={};",
        "webpack-91bd.js",
    )
    assert "webpack" in _confirmed_ids(strong)


def test_vite_validation() -> None:
    """Vite requires dev/build runtime markers."""
    weak = _run("console.log('bundle');", "main.js")
    assert "vite" not in _confirmed_ids(weak)

    strong = _run(
        "import.meta.hot.accept(); const __vite__ = { injectQuery: () => {} };",
        "main.js",
    )
    assert "vite" in _confirmed_ids(strong)


def test_turbopack_validation() -> None:
    """Turbopack requires bundler-specific runtime markers."""
    weak = _run("console.log('bundle');", "main.js")
    assert "turbopack" not in _confirmed_ids(weak)

    strong = _run(
        "self.__turbopack_load__ = () => {}; // TURBOPACK runtime",
        "turbopack-runtime.js",
    )
    assert "turbopack" in _confirmed_ids(strong)


def test_generic_keyword_rejection() -> None:
    """Generic keywords alone must not create confirmed framework detections."""
    result = _run(
        "var foo = { ng: true, Bootstrap: 'text', L: { map: () => {} } };",
        "chunk.js",
    )
    confirmed = _confirmed_ids(result)
    assert "angular" not in confirmed
    assert "bootstrap" not in confirmed
    assert "leaflet" not in confirmed


def test_version_attribution() -> None:
    """Version evidence must attach to the confirmed technology result."""
    result = _run(
        'React.version="19.0.0"; reconcilerVersion:"19.0.0"; React.createElement("div");',
        "main.js",
    )
    react = _first_match(result, "react")
    assert react.version == "19.0.0"
    assert react.version != "Unknown"
    assert any(
        item.matched_value == "19.0.0" or item.evidence_type == "version_marker"
        for item in react.evidence
    )


def test_source_attribution() -> None:
    """Every confirmed technology must retain source and evidence attribution."""
    gate = MatchQualityGate()
    result = _run(
        'window.next={version:"16.2.10"}; reconcilerVersion:"19.0.0";',
        "0-s5ec5safvjx.js",
    )
    for match in result.matches:
        assert is_valid_detection_candidate(match)
        assert gate.is_confirmed(match)
        assert match.source_file == "0-s5ec5safvjx.js"
        assert match.primary_matcher
        assert match.matched_value or match.evidence
        assert match.confidence >= 50.0
