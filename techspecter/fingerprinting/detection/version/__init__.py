"""Version candidate collection and resolution."""

from techspecter.fingerprinting.detection.version.candidates import (
    VersionCandidate,
    VersionCandidateCollector,
)
from techspecter.fingerprinting.detection.version.priorities import (
    VERSION_SOURCE_PRIORITIES,
    priority_for_source,
)

__all__ = [
    "VERSION_SOURCE_PRIORITIES",
    "VersionCandidate",
    "VersionCandidateCollector",
    "priority_for_source",
]
