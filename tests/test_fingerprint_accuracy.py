"""False positive and false negative regression tests."""

from __future__ import annotations

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.engine import FingerprintEngine
from techspecter.fingerprints.loader import SignatureLoader


def test_plain_javascript_produces_no_detections() -> None:
    """Verify generic JavaScript does not trigger technology matches."""
    engine = FingerprintEngine(SignatureLoader().load_all(reload=True))
    context = MatchContext(
        content="function hello() { console.log('hello world'); }",
        filename="app.js",
        url="https://example.com/app.js",
    )
    assert engine.detect(context) == []


def test_react_bundle_detects_multiple_libraries() -> None:
    """Verify a realistic bundle can expose multiple technologies."""
    engine = FingerprintEngine(SignatureLoader().load_all(reload=True))
    context = MatchContext(
        content=(
            'React.version="18.2.0"; React.createElement("div"); '
            "__webpack_require__(1); axios.create({}); "
            'jQuery.fn.jquery="3.7.1";'
        ),
        filename="main.chunk.js",
        url="https://example.com/static/main.chunk.js",
    )
    matches = engine.detect(context)
    ids = {item.technology.id for item in matches}
    assert "react" in ids
    assert "webpack" in ids
    assert "axios" in ids
    assert "jquery" in ids


def test_highcharts_not_confused_with_chartjs() -> None:
    """Verify Highcharts content is not misidentified as Chart.js only."""
    engine = FingerprintEngine(SignatureLoader().load_all(reload=True))
    context = MatchContext(
        content="Highcharts.chart('container', { series: [] });",
        filename="highcharts.js",
        url="https://example.com/highcharts.js",
    )
    matches = engine.detect(context)
    ids = {item.technology.id for item in matches}
    assert "highcharts" in ids
    assert "chartjs" not in ids
