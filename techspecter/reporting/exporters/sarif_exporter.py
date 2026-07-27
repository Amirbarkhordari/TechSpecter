"""SARIF report exporter."""

from __future__ import annotations

import json

from techspecter.reporting.exporters.base import BaseExporter
from techspecter.reporting.models import Report


class SarifExporter(BaseExporter):
    """Export reports as SARIF for CI/CD integration."""

    format = "sarif"

    def export(self, report: Report) -> str:
        """Serialize technology detections as SARIF 2.1.0 results."""
        rules = []
        results = []
        for technology in report.technologies:
            rule_id = technology.id
            rule: dict[str, object] = {
                "id": rule_id,
                "name": technology.name,
                "shortDescription": {"text": f"{technology.name} technology detection"},
                "fullDescription": {
                    "text": technology.description or f"Detected {technology.name}"
                },
            }
            if technology.website:
                rule["helpUri"] = technology.website
            rules.append(rule)
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "note",
                    "message": {
                        "text": (
                            f"Detected {technology.name} "
                            f"{technology.version} (confidence {technology.confidence:.1f}%)"
                        )
                    },
                    "properties": {
                        "category": technology.category,
                        "version": technology.version,
                        "confidence": technology.confidence,
                        "sourceFile": technology.source_file,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": technology.source_file or report.target.url,
                                }
                            }
                        }
                    ],
                }
            )

        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": report.metadata.tool_name,
                            "version": report.metadata.tool_version,
                            "informationUri": "https://github.com/Amirbarkhordari/TechSpecter",
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": report.metadata.scan_timestamp.isoformat(),
                        }
                    ],
                    "results": results,
                }
            ],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
