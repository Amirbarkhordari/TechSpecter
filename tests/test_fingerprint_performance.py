"""Performance tests for fingerprint detection."""

from __future__ import annotations

import time

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.engine import FingerprintEngine
from techspecter.fingerprints.loader import SignatureLoader


def test_detection_completes_within_reasonable_time() -> None:
    """Verify full-database detection against a large script stays fast."""
    engine = FingerprintEngine(SignatureLoader().load_all(reload=True))
    content = (
        'React.version="18.2.0"; React.createElement("div"); '
        "__webpack_require__(1); axios.create({}); Vue.createApp({}); " * 50
    )
    context = MatchContext(
        content=content,
        filename="vendor.bundle.js",
        url="https://example.com/vendor.bundle.js",
    )
    started = time.perf_counter()
    for _ in range(5):
        engine.detect(context)
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert elapsed_ms < 5000
