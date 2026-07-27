"""Base exporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from techspecter.reporting.models import Report, ReportFormat


class BaseExporter(ABC):
    """Abstract base class for report exporters."""

    format: ReportFormat

    @abstractmethod
    def export(self, report: Report) -> str:
        """Export a report to the target format.

        Args:
            report: Structured scan report.

        Returns:
            Serialized report content.
        """
