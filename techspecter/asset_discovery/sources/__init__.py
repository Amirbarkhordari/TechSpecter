"""Asset discovery source extractors."""

from techspecter.asset_discovery.sources.css import extract_css_references
from techspecter.asset_discovery.sources.html import extract_html_references
from techspecter.asset_discovery.sources.javascript import extract_javascript_references
from techspecter.asset_discovery.sources.manifest import extract_manifest_references

__all__ = [
    "extract_css_references",
    "extract_html_references",
    "extract_javascript_references",
    "extract_manifest_references",
]
