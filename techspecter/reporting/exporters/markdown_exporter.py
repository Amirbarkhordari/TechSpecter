"""Markdown report exporter."""

from __future__ import annotations

from techspecter.reporting.exporters.base import BaseExporter
from techspecter.reporting.models import Report


class MarkdownExporter(BaseExporter):
    """Export reports as Markdown documents."""

    format = "markdown"

    def export(self, report: Report) -> str:
        """Render a professional Markdown report."""
        lines: list[str] = [
            "# TechSpecter Scan Report",
            "",
            "## Project Information",
            "",
            f"- **Target:** {report.target.url}",
            f"- **Tool:** {report.metadata.tool_name} {report.metadata.tool_version}",
            f"- **Scan Timestamp:** {report.metadata.scan_timestamp.isoformat()}",
            f"- **Scan Duration:** {report.metadata.scan_duration_ms:.0f} ms",
            "",
            "## Summary",
            "",
            report.summary.headline,
            "",
            "## Statistics",
            "",
            f"- **Technologies Detected:** {report.statistics.total_technologies}",
            f"- **Categories:** {report.statistics.category_count}",
            f"- **Scripts Analyzed:** {report.statistics.scripts_analyzed}",
            f"- **Average Confidence:** {report.statistics.average_confidence:.1f}%",
            f"- **Highest Confidence:** {report.statistics.highest_confidence:.1f}%",
            f"- **Known Versions:** {report.statistics.known_versions}",
            f"- **Unknown Versions:** {report.statistics.unknown_versions}",
            "",
            "## Detected Technologies",
            "",
        ]

        if not report.technologies:
            lines.append("_No technologies detected._")
        else:
            lines.extend(
                [
                    "| Technology | Category | Version | Confidence | Source |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for technology in report.technologies:
                lines.append(
                    f"| {technology.name} | {technology.category} | "
                    f"{technology.version} | {technology.confidence:.1f}% | "
                    f"{technology.source_file or '-'} |"
                )

        lines.extend(["", "## Evidence", ""])
        if not report.technologies:
            lines.append("_No evidence available._")
        else:
            for technology in report.technologies:
                lines.append(f"### {technology.name}")
                if not technology.evidence:
                    lines.append("- No structured evidence recorded.")
                else:
                    for item in technology.evidence:
                        lines.append(
                            f"- `{item.matcher_type}` `{item.matched_pattern}` "
                            f"(file: {item.matched_file or 'unknown'}, "
                            f"confidence: {item.confidence:.1f}%)"
                        )
                lines.append("")

        lines.extend(
            [
                "## Scan Metadata",
                "",
                f"- **Tool Name:** {report.metadata.tool_name}",
                f"- **Tool Version:** {report.metadata.tool_version}",
                f"- **Target URL:** {report.metadata.target_url}",
                f"- **Technologies Detected:** {report.metadata.technologies_detected}",
                f"- **Categories Detected:** {report.metadata.categories_detected}",
                "",
            ]
        )
        return "\n".join(lines)
