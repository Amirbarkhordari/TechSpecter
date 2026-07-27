"""CSV report exporter."""

from __future__ import annotations

import csv
import io

from techspecter.reporting.exporters.base import BaseExporter
from techspecter.reporting.models import Report


class CsvExporter(BaseExporter):
    """Export reports as CSV with one technology per row."""

    format = "csv"

    def export(self, report: Report) -> str:
        """Serialize technologies to CSV."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            ["Technology", "Category", "Version", "Confidence", "Evidence", "Source File"]
        )
        for technology in report.technologies:
            evidence = "; ".join(
                f"{item.matcher_type}:{item.matched_pattern}" for item in technology.evidence
            )
            writer.writerow(
                [
                    technology.name,
                    technology.category,
                    technology.version,
                    f"{technology.confidence:.2f}",
                    evidence,
                    technology.source_file or "",
                ]
            )
        return buffer.getvalue()
