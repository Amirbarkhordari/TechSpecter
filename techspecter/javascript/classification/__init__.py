"""JavaScript classification."""

from techspecter.javascript.classification.bundler import detect_bundler
from techspecter.javascript.classification.classifier import classify_resource, extract_chunk_name

__all__ = ["classify_resource", "detect_bundler", "extract_chunk_name"]
