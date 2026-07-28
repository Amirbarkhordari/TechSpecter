"""Pipeline timing utilities."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Self


@dataclass(slots=True)
class StageTiming:
    """Elapsed time for a pipeline stage."""

    name: str
    elapsed_ms: float = 0.0


@dataclass
class PipelineTiming:
    """Collect pipeline stage timings."""

    stages: list[StageTiming] = field(default_factory=list)
    analyzer_timings: dict[str, float] = field(default_factory=dict)

    class _Stage:
        """Context manager for a timed stage."""

        def __init__(self, timing: PipelineTiming, name: str) -> None:
            self._timing = timing
            self._name = name
            self._started = 0.0

        def __enter__(self) -> Self:
            self._started = time.perf_counter()
            return self

        def __exit__(self, *_args: object) -> None:
            elapsed_ms = (time.perf_counter() - self._started) * 1000
            self._timing.stages.append(StageTiming(name=self._name, elapsed_ms=elapsed_ms))

    def stage(self, name: str) -> _Stage:
        """Return a context manager that records stage elapsed time."""
        return PipelineTiming._Stage(self, name)

    def record_analyzer(self, analyzer_id: str, elapsed_ms: float) -> None:
        """Record per-analyzer elapsed time."""
        self.analyzer_timings[analyzer_id] = elapsed_ms

    def total_ms(self) -> float:
        """Return summed stage elapsed time."""
        return round(sum(stage.elapsed_ms for stage in self.stages), 3)

    def as_metadata(self) -> dict[str, object]:
        """Return timing summary suitable for analysis metadata."""
        return {
            "stages": {stage.name: round(stage.elapsed_ms, 3) for stage in self.stages},
            "analyzer_timings": {
                analyzer_id: round(elapsed_ms, 3)
                for analyzer_id, elapsed_ms in sorted(self.analyzer_timings.items())
            },
            "total_stage_ms": self.total_ms(),
        }
