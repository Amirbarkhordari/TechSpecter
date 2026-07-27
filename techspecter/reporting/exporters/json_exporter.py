"""JSON report exporter."""

from __future__ import annotations

import json

from techspecter.reporting.exporters.base import BaseExporter
from techspecter.reporting.models import Report


class JsonExporter(BaseExporter):
    """Export reports as structured JSON."""

    format = "json"

    def export(self, report: Report) -> str:
        """Serialize the report to indented JSON."""
        payload = report.model_dump(mode="json")
        return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
