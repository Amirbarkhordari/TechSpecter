"""Centralized JavaScript resource index."""

from __future__ import annotations

from pydantic import Field

from techspecter.javascript.models import IndexedJavaScriptResource, JavaScriptPipelineStatistics
from techspecter.models.base import TechSpecterModel


class JavaScriptIndex(TechSpecterModel):
    """Central index of discovered and processed JavaScript resources."""

    resources: dict[str, IndexedJavaScriptResource] = Field(default_factory=dict)
    url_to_id: dict[str, str] = Field(default_factory=dict)
    hash_to_id: dict[str, str] = Field(default_factory=dict)

    def add(self, resource: IndexedJavaScriptResource) -> None:
        """Index a resource exactly once by URL; link duplicates by content hash."""
        url_key = str(resource.url)
        if url_key in self.url_to_id:
            return
        self.resources[resource.resource_id] = resource
        self.url_to_id[url_key] = resource.resource_id
        content_hash = resource.metadata.content_hash
        if content_hash and content_hash not in self.hash_to_id:
            self.hash_to_id[content_hash] = resource.resource_id

    def get_by_url(self, url: str) -> IndexedJavaScriptResource | None:
        """Return indexed resource for a URL."""
        resource_id = self.url_to_id.get(url)
        if resource_id is None:
            return None
        return self.resources.get(resource_id)

    def get_by_hash(self, content_hash: str) -> IndexedJavaScriptResource | None:
        """Return first indexed resource with matching content hash."""
        resource_id = self.hash_to_id.get(content_hash)
        if resource_id is None:
            return None
        return self.resources.get(resource_id)

    def all_resources(self) -> list[IndexedJavaScriptResource]:
        """Return all indexed resources in stable order."""
        return sorted(self.resources.values(), key=lambda item: (item.inline, str(item.url)))

    @property
    def count(self) -> int:
        """Return total indexed resources."""
        return len(self.resources)


class JavaScriptPipelineResult(TechSpecterModel):
    """Complete output of the JavaScript preprocessing pipeline."""

    index: JavaScriptIndex
    statistics: JavaScriptPipelineStatistics
    started_at: str | None = None
    completed_at: str | None = None
