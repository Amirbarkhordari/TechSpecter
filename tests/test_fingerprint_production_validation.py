"""Phase 3 production validation and stability tests."""

from __future__ import annotations

from techspecter.fingerprinting.detection.merger import TechnologyMerger
from techspecter.fingerprinting.loader import SignatureLoader
from techspecter.fingerprinting.match_attribution import is_valid_detection_candidate
from techspecter.fingerprinting.match_quality import MatchQualityGate, is_weak_pattern
from techspecter.fingerprinting.models import PatternEvidence, Technology, TechnologyMatch
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target


def _run(content: str, filename: str, *, url: str | None = None):
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


# --- Application type validation ---


def test_nextjs_application_profile() -> None:
    """Next.js bundles should report Next.js and React."""
    result = _run(
        'window.next={version:"16.2.10"}; reconcilerVersion:"19.0.0"; React.createElement("div");',
        "0-s5ec5safvjx.js",
    )
    confirmed = _confirmed_ids(result)
    assert "nextjs" in confirmed
    assert "react" in confirmed


def test_react_application_profile() -> None:
    """React SPA bundles should report React."""
    result = _run(
        'React.version="19.0.0"; ReactDOM.createRoot(document.getElementById("root"));',
        "main.js",
    )
    assert "react" in _confirmed_ids(result)
    assert "nextjs" not in _confirmed_ids(result)


def test_vue_application_profile() -> None:
    """Vue bundles should report Vue with version when available."""
    result = _run(
        'Vue.version="3.4.21"; Vue.createApp({ render() { return null; } });',
        "app.js",
    )
    assert "vue" in _confirmed_ids(result)
    vue = next(item for item in result.matches if item.technology.id == "vue")
    assert vue.version == "3.4.21"


def test_angular_application_profile() -> None:
    """Angular bundles should report Angular from Ivy/runtime markers."""
    result = _run(
        'import "@angular/core"; ɵɵdefineComponent({}); platformBrowserDynamic();',
        "main.js",
    )
    assert "angular" in _confirmed_ids(result)


def test_wordpress_application_profile() -> None:
    """WordPress HTML/assets should report WordPress CMS indicators."""
    result = _run(
        '<link href="/wp-content/themes/twentytwenty/style.css" rel="stylesheet">'
        '<script src="/wp-includes/js/wp-emoji-release.min.js"></script>',
        "index.html",
        url="https://example.com/index.html",
    )
    assert "wordpress" in _confirmed_ids(result)


def test_static_website_no_framework_false_positives() -> None:
    """Plain static sites must not report major frameworks."""
    result = _run(
        "function hello(){document.getElementById('x').textContent='Hello';}",
        "app.js",
    )
    confirmed = _confirmed_ids(result)
    assert not confirmed.intersection({"react", "nextjs", "vue", "angular", "bootstrap"})


# --- Quality gates ---


def test_no_detection_without_evidence() -> None:
    """Technologies without matcher evidence must not confirm."""
    gate = MatchQualityGate()
    match = TechnologyMatch(
        technology=Technology(id="react", name="React", category="framework"),
        confidence=95.0,
        filename="app.js",
        source_file="app.js",
        evidence=[],
        matched_patterns=[],
    )
    assert gate.is_confirmed(match) is False
    assert "no matcher-produced evidence" in gate.rejection_reason(match)


def test_no_detection_without_source() -> None:
    """Technologies without source attribution must not confirm."""
    gate = MatchQualityGate()
    match = TechnologyMatch(
        technology=Technology(id="react", name="React", category="framework"),
        confidence=95.0,
        evidence=[
            PatternEvidence(
                matcher="string",
                pattern="React.createElement",
                weight=45.0,
            ),
        ],
        matched_patterns=["string:React.createElement"],
    )
    assert is_valid_detection_candidate(match) is False
    assert gate.is_confirmed(match) is False


def test_generic_keyword_rejection_stability() -> None:
    """Generic keywords must not create confirmed detections."""
    result = _run(
        "var foo = { ng: true, Bootstrap: 'text', L: { map: () => {} } };",
        "chunk.js",
    )
    confirmed = _confirmed_ids(result)
    assert "angular" not in confirmed
    assert "bootstrap" not in confirmed
    assert "leaflet" not in confirmed


def test_version_attribution_stability() -> None:
    """Version evidence must attach to confirmed technology results."""
    result = _run(
        'React.version="19.0.0"; reconcilerVersion:"19.0.0"; React.createElement("div");',
        "main.js",
    )
    react = next(item for item in result.matches if item.technology.id == "react")
    assert react.version == "19.0.0"
    assert react.source_file == "main.js"


def test_evidence_merging_stability() -> None:
    """Multiple evidence items for one technology must merge."""
    tech = Technology(id="react", name="React", category="framework")
    runtime = TechnologyMatch(
        technology=tech,
        version="Unknown",
        confidence=72.0,
        filename="runtime.js",
        source_file="runtime.js",
        evidence=[
            PatternEvidence(
                matcher="string",
                pattern="React.createElement",
                weight=40.0,
                source_file="runtime.js",
                matched_value="React.createElement",
            ),
        ],
        matched_patterns=["string:React.createElement"],
    )
    version = TechnologyMatch(
        technology=tech,
        version="19.0.0",
        confidence=80.0,
        filename="bundle.js",
        source_file="bundle.js",
        version_confidence=95.0,
        evidence=[
            PatternEvidence(
                matcher="version",
                pattern="reconcilerVersion",
                weight=45.0,
                source_file="bundle.js",
                matched_value="19.0.0",
                evidence_type="version_marker",
            ),
        ],
        matched_patterns=["version:reconcilerVersion"],
    )
    merged = TechnologyMerger().merge_matches([runtime, version])
    assert len(merged) == 1
    assert merged[0].version == "19.0.0"
    assert len(merged[0].evidence) == 2


def test_duplicate_technology_merging_stability() -> None:
    """Duplicate technology IDs across assets must merge to one result."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/a.js",
                filename="a.js",
                content='React.createElement("a");',
                download_success=True,
                status_code=200,
                content_type="application/javascript",
                content_length=32,
                download_duration_ms=1.0,
            ),
            DownloadResult(
                url="https://example.com/b.js",
                filename="b.js",
                content='ReactDOM.createRoot(document.getElementById("root"));',
                download_success=True,
                status_code=200,
                content_type="application/javascript",
                content_length=48,
                download_duration_ms=1.0,
            ),
        ],
        inline_scripts=[],
    )
    merged_result = FingerprintPipeline().run(discovery)
    react_matches = [item for item in merged_result.matches if item.technology.id == "react"]
    assert len(react_matches) == 1


# --- Framework/build tool detection stability ---


def test_bootstrap_detection_stability() -> None:
    result = _run(
        '<button data-bs-toggle="modal" class="btn">Open</button>'
        '<link href="/assets/bootstrap.min.css" rel="stylesheet">',
        "index.html",
        url="https://example.com/index.html",
    )
    assert "bootstrap" in _confirmed_ids(result)


def test_tailwind_detection_stability() -> None:
    result = _run(
        "@tailwind base;\n@tailwind utilities;\nconst __tailwindcss_version__='3.4.1';",
        "styles.css",
        url="https://example.com/styles.css",
    )
    assert "tailwindcss" in _confirmed_ids(result)


def test_material_ui_detection_stability() -> None:
    result = _run(
        'import { Button } from "@mui/material"; MuiThemeProvider({ children: null });',
        "components.js",
    )
    assert "material-ui" in _confirmed_ids(result)


def test_webpack_detection_stability() -> None:
    result = _run(
        "function r(e){return __webpack_require__(e)} __webpack_modules__={};",
        "webpack-91bd.js",
    )
    assert "webpack" in _confirmed_ids(result)


def test_vite_detection_stability() -> None:
    result = _run(
        "import.meta.hot.accept(); const __vite__ = { injectQuery: () => {} };",
        "main.js",
    )
    assert "vite" in _confirmed_ids(result)


def test_turbopack_detection_stability() -> None:
    result = _run(
        "self.__turbopack_load__ = () => {}; // TURBOPACK runtime",
        "turbopack-runtime.js",
    )
    assert "turbopack" in _confirmed_ids(result)


def test_fingerprint_signatures_include_strong_markers() -> None:
    """Every fingerprint must include at least one non-weak detection marker."""
    weak_only: list[str] = []
    for fingerprint in SignatureLoader().load_all(reload=True):
        has_strong = any(
            not is_weak_pattern(pattern.matcher, pattern.pattern)
            for pattern in fingerprint.patterns
        )
        if not has_strong:
            weak_only.append(fingerprint.id)
    assert not weak_only, f"Fingerprints with only weak patterns: {weak_only}"


def test_weak_patterns_never_confirm_alone() -> None:
    """Weak indicators alone must never pass the quality gate."""
    gate = MatchQualityGate()
    for matcher, pattern in (
        ("global", "ng"),
        ("global", "L"),
        ("string", "Bootstrap"),
        ("filename", "chunk"),
    ):
        assert is_weak_pattern(matcher, pattern)
        match = TechnologyMatch(
            technology=Technology(id="test", name="Test", category="framework"),
            confidence=90.0,
            filename="chunk.js",
            source_file="chunk.js",
            evidence=[
                PatternEvidence(
                    matcher=matcher,
                    pattern=pattern,
                    weight=40.0,
                    source_file="chunk.js",
                ),
            ],
            matched_patterns=[f"{matcher}:{pattern}"],
        )
        assert gate.is_confirmed(match) is False
