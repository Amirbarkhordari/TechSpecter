"""Shared report test fixtures."""

from __future__ import annotations

from techspecter.fingerprinting.models import (
    DetectionResult,
    PatternEvidence,
    Technology,
    TechnologyMatch,
)


def sample_detection_result() -> DetectionResult:
    """Return a representative detection result for reporting tests."""
    return DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(
                    id="react",
                    name="React",
                    category="framework",
                    website="https://react.dev",
                    description="React UI library",
                ),
                version="18.2.0",
                confidence=92.5,
                matched_patterns=["string:React.createElement", "global:React"],
                filename="react.js",
                source_url="https://example.com/react.js",
                evidence=[
                    PatternEvidence(
                        matcher="string",
                        pattern="React.createElement",
                        weight=40.0,
                        detail="react.js",
                    )
                ],
            ),
            TechnologyMatch(
                technology=Technology(
                    id="webpack",
                    name="webpack",
                    category="build-tool",
                ),
                version="Unknown",
                confidence=78.0,
                matched_patterns=["string:__webpack_require__"],
                filename="main.chunk.js",
                source_url="https://example.com/main.chunk.js",
            ),
        ],
        scripts_analyzed=2,
        elapsed_ms=125.0,
    )
