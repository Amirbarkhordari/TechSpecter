"""HTML report exporter."""

from __future__ import annotations

import html
from pathlib import Path

from techspecter.exceptions import TemplateError
from techspecter.reporting.exporters.base import BaseExporter
from techspecter.reporting.models import Report

_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "templates" / "report.html"


class HtmlExporter(BaseExporter):
    """Export reports as standalone HTML documents."""

    format = "html"

    def __init__(self, template_path: Path | str | None = None) -> None:
        """Initialize the HTML exporter.

        Args:
            template_path: Optional custom HTML template path.
        """
        self._template_path = Path(template_path) if template_path else _TEMPLATE_PATH

    def export(self, report: Report) -> str:
        """Render the report using the HTML template."""
        template = self._load_template()
        rows = self._render_technology_rows(report)
        category_cards = self._render_category_cards(report)
        evidence_sections = self._render_evidence_sections(report)

        replacements = {
            "{{TARGET_URL}}": html.escape(report.target.url),
            "{{TOOL_NAME}}": html.escape(report.metadata.tool_name),
            "{{TOOL_VERSION}}": html.escape(report.metadata.tool_version),
            "{{SCAN_TIMESTAMP}}": html.escape(report.metadata.scan_timestamp.isoformat()),
            "{{SCAN_DURATION}}": f"{report.metadata.scan_duration_ms:.0f}",
            "{{SUMMARY_HEADLINE}}": html.escape(report.summary.headline),
            "{{TECHNOLOGY_COUNT}}": str(report.statistics.total_technologies),
            "{{CATEGORY_COUNT}}": str(report.statistics.category_count),
            "{{SCRIPTS_ANALYZED}}": str(report.statistics.scripts_analyzed),
            "{{AVERAGE_CONFIDENCE}}": f"{report.statistics.average_confidence:.1f}",
            "{{HIGHEST_CONFIDENCE}}": f"{report.statistics.highest_confidence:.1f}",
            "{{KNOWN_VERSIONS}}": str(report.statistics.known_versions),
            "{{UNKNOWN_VERSIONS}}": str(report.statistics.unknown_versions),
            "{{TECHNOLOGY_ROWS}}": rows,
            "{{CATEGORY_CARDS}}": category_cards,
            "{{EVIDENCE_SECTIONS}}": evidence_sections,
        }
        rendered = template
        for key, value in replacements.items():
            rendered = rendered.replace(key, value)
        return rendered

    def _load_template(self) -> str:
        """Load the HTML template from disk."""
        try:
            return self._template_path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"Unable to load HTML template: {self._template_path}"
            raise TemplateError(msg) from exc

    def _render_technology_rows(self, report: Report) -> str:
        """Render HTML table rows for detected technologies."""
        if not report.technologies:
            return '<tr><td colspan="5">No technologies detected.</td></tr>'

        rows: list[str] = []
        for technology in report.technologies:
            confidence_class = _confidence_class(technology.confidence)
            rows.append(
                "<tr>"
                f"<td>{html.escape(technology.name)}</td>"
                f"<td>{html.escape(technology.category)}</td>"
                f"<td>{html.escape(technology.version)}</td>"
                f'<td><span class="confidence {confidence_class}">'
                f"{technology.confidence:.1f}%</span></td>"
                f"<td>{html.escape(technology.source_file or '-')}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def _render_category_cards(self, report: Report) -> str:
        """Render summary cards for each category."""
        if not report.statistics.category_counts:
            return '<div class="card">No categories detected.</div>'

        cards: list[str] = []
        for category, count in report.statistics.category_counts.items():
            cards.append(
                '<div class="card">'
                f"<h3>{html.escape(category)}</h3>"
                f'<p class="metric">{count}</p>'
                "</div>"
            )
        return "\n".join(cards)

    def _render_evidence_sections(self, report: Report) -> str:
        """Render evidence sections for each technology."""
        if not report.technologies:
            return "<p>No evidence available.</p>"

        sections: list[str] = []
        for technology in report.technologies:
            items = technology.evidence or []
            if not items:
                evidence_html = "<li>No structured evidence recorded.</li>"
            else:
                evidence_html = "".join(
                    "<li>"
                    f"<code>{html.escape(item.matcher_type or 'unknown')}</code> "
                    f"<code>{html.escape(item.matched_pattern or '')}</code> "
                    f"(file: {html.escape(item.matched_file or 'unknown')}, "
                    f"confidence: {item.confidence:.1f}%)"
                    "</li>"
                    for item in items
                )
            sections.append(
                '<section class="evidence-block">'
                f"<h3>{html.escape(technology.name)}</h3>"
                f"<ul>{evidence_html}</ul>"
                "</section>"
            )
        return "\n".join(sections)


def _confidence_class(confidence: float) -> str:
    """Return a CSS class name for a confidence score."""
    if confidence >= 80:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"
